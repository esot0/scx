# scx_spark

This is a single user-defined scheduler used within [sched_ext](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about sched_ext](https://github.com/sched-ext/scx/tree/main).


## GPU Support

The scheduler includes built-in GPU support that automatically detects and prioritizes GPU-using tasks:

### Usage

Enable GPU support with the `--enable-gpu-support` flag:

```bash
sudo scx_spark --enable-gpu-support
```

### Aggressive GPU Mode

For maximum GPU-CPU coordination, you can enable aggressive mode where **only GPU tasks can use big/performance cores**:

```bash
sudo scx_spark --enable-gpu-support --aggressive-gpu-tasks
```

In aggressive mode:
- GPU tasks get exclusive access to fast cores (big cores in big.LITTLE systems)
- Non-GPU tasks are restricted to little cores or other non-primary domain CPUs
- This ensures maximum performance for GPU workloads by preventing CPU contention on fast cores

## Example Usage

### Basic GPU-optimized scheduling
```bash
sudo scx_spark --enable-gpu-support --primary-domain performance
```

### Aggressive GPU mode for maximum performance
```bash
sudo scx_spark --enable-gpu-support --aggressive-gpu-tasks --primary-domain performance
```

### High-performance AI workload
```bash
sudo scx_spark \
  --enable-gpu-support \
  --aggressive-gpu-tasks \
  --primary-domain performance \
  --dsq-mode cpu \
  --slice-us 10000 \
  --stats 0.5
```

### Power-efficient GPU scheduling
```bash
sudo scx_spark \
  --enable-gpu-support \
  --primary-domain auto \
  --cpufreq \
  --throttle-us 1000
```
## Command Line Options

### GPU Support
- `--enable-gpu-support`: Enable GPU task detection and prioritization
- `--aggressive-gpu-tasks`: Only GPU tasks can use big/performance cores (requires --enable-gpu-support)

