/* SPDX-License-Identifier: GPL-2.0 */
/*
* Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
* Copyright (c) 2022 Tejun Heo <tj@kernel.org>
* Copyright (c) 2022 David Vernet <dvernet@meta.com>
*/
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <time.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_simple.bpf.skel.h"

const char help_fmt[] =
"A simple sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
if (level == LIBBPF_DEBUG && !verbose)
return 0;
return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
exit_req = 1;
}

static __u64 get_current_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static void poll_cpus(struct scx_simple *skel)
{
	int nr_cpus = skel->bss->num_cpus;
	assert(nr_cpus > 0);
	__u32 idx;
	__u64 percpu_values[nr_cpus];
	long long difference;
	int prev_kick_idx = 0;
	__u64 current_time;
	int ret;
	
	int map_fd = bpf_map__fd(skel->maps.prev_kick_time);
	if (map_fd < 0) {
		printf("Invalid map fd: %d\n", map_fd);
		return;
	}
	
	ret = bpf_map_lookup_elem(map_fd, &prev_kick_idx, percpu_values);
	current_time = get_current_time_ns();  //Hopefully this mimics scx_bpf_now()
	if (ret < 0) {
		printf("Map lookup failed, ret: %d\n", ret);
		return;
	}
	
	for (idx = 0; idx < nr_cpus; idx++) {
		difference = skel->bss->time - percpu_values[idx];

		if(difference <= 500000000) { // .5 seconds 
		printf("CPU %d is running or kicked - Current time: %llu, Last idle time: %llu, Time since last idle: %lld ns\n", 
		       idx, current_time, percpu_values[idx], difference);
		}
		else  { 
			printf("CPU %d is running or allowed to idle (Time since last idle: %lld ns = %.3f seconds)\n", 
			       idx, difference, difference / 1000000000.0);
		}
	}
}

static void read_stats(struct scx_simple *skel, __u64 *stats)
{
int nr_cpus = libbpf_num_possible_cpus();
assert(nr_cpus > 0);
__u64 cnts[2][nr_cpus];
__u32 idx;

memset(stats, 0, sizeof(stats[0]) * 2);

for (idx = 0; idx < 2; idx++) {
int ret, cpu;

ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
&idx, cnts[idx]);
if (ret < 0)
continue;
for (cpu = 0; cpu < nr_cpus; cpu++)
stats[idx] += cnts[idx][cpu];
}
}

int main(int argc, char **argv)
{
struct scx_simple *skel;
struct bpf_link *link;
__u32 opt;
__u64 ecode;

libbpf_set_print(libbpf_print_fn);
signal(SIGINT, sigint_handler);
signal(SIGTERM, sigint_handler);
restart:
skel = SCX_OPS_OPEN(simple_ops, scx_simple);

while ((opt = getopt(argc, argv, "fvh")) != -1) {
switch (opt) {
case 'f':
skel->rodata->fifo_sched = true;
break;
case 'v':
verbose = true;
break;
default:
fprintf(stderr, help_fmt, basename(argv[0]));
return opt != 'h';
}
}

SCX_OPS_LOAD(skel, simple_ops, scx_simple, uei);
link = SCX_OPS_ATTACH(skel, simple_ops, scx_simple);

while (!exit_req && !UEI_EXITED(skel, uei)) {
		poll_cpus(skel);
		__u64 stats[2];
		fflush(stdout);
sleep(1);
}

bpf_link__destroy(link);
ecode = UEI_REPORT(skel, uei);
scx_simple__destroy(skel);

if (UEI_ECODE_RESTART(ecode))
goto restart;
return 0;
}