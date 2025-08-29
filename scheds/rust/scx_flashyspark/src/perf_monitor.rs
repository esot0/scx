// SPDX-License-Identifier: GPL-2.0
//
// Performance monitoring module for workload classification

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use libc::{c_int, c_long, c_ulong, pid_t, syscall, SYS_perf_event_open};
use log::{debug, info, warn};

use crate::bpf_intf::*;

// perf_event_attr structure
#[repr(C)]
#[derive(Debug, Clone)]
struct perf_event_attr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
    config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    __reserved_2: u16,
    aux_sample_size: u32,
    __reserved_3: u32,
}

// Perf event types
const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_TYPE_HW_CACHE: u32 = 3;
const PERF_TYPE_RAW: u32 = 4;

// Hardware event configs
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;

// Cache event configs
const PERF_COUNT_HW_CACHE_LL: u64 = 2;  // Last level cache
const PERF_COUNT_HW_CACHE_DTLB: u64 = 3;  // Data TLB
const PERF_COUNT_HW_CACHE_OP_READ: u64 = 0;
const PERF_COUNT_HW_CACHE_RESULT_ACCESS: u64 = 0;
const PERF_COUNT_HW_CACHE_RESULT_MISS: u64 = 1;

// Flags
const PERF_FLAG_FD_CLOEXEC: c_ulong = 0x00000008;

// Read format
const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;

// Helper to create cache config
fn cache_config(cache_id: u64, op_id: u64, result_id: u64) -> u64 {
    (cache_id) | (op_id << 8) | (result_id << 16)
}

// Per-task performance monitoring state
struct TaskPerfMonitor {
    pid: pid_t,
    fds: Vec<OwnedFd>,
    start_time: std::time::Instant,
}

// Performance counter values
#[repr(C)]
struct ReadFormat {
    value: u64,
    time_enabled: u64,
    time_running: u64,
}

impl TaskPerfMonitor {
    fn new(pid: pid_t) -> Result<Self> {
        let mut fds = Vec::new();

        // Helper to create and open a perf event
        let open_event = |type_: u32, config: u64| -> Result<OwnedFd> {
            let mut attr = perf_event_attr {
                type_,
                size: std::mem::size_of::<perf_event_attr>() as u32,
                config,
                sample_period: 0,
                sample_type: 0,
                read_format: PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
                flags: 0,
                wakeup_events: 0,
                bp_type: 0,
                config1: 0,
                config2: 0,
                branch_sample_type: 0,
                sample_regs_user: 0,
                sample_stack_user: 0,
                clockid: 0,
                sample_regs_intr: 0,
                aux_watermark: 0,
                sample_max_stack: 0,
                __reserved_2: 0,
                aux_sample_size: 0,
                __reserved_3: 0,
            };

            attr.flags |= 1 << 0;  // disabled
            attr.flags |= 1 << 1;  // inherit
            attr.flags |= 1 << 3;  // exclude_kernel
            attr.flags |= 1 << 4;  // exclude_hv

            let fd = unsafe {
                syscall(
                    SYS_perf_event_open,
                    &attr as *const _ as c_long,
                    pid as c_long,
                    -1 as c_long,  // any CPU
                    -1 as c_long,  // no group
                    PERF_FLAG_FD_CLOEXEC as c_long,
                )
            };

            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            Ok(unsafe { OwnedFd::from_raw_fd(fd as c_int) })
        };

        // Open performance counters
        // 1. CPU cycles
        fds.push(open_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES)
            .context("Failed to open CPU cycles counter")?);

        // 2. Instructions retired
        fds.push(open_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS)
            .context("Failed to open instructions counter")?);

        // 3. LLC references
        fds.push(open_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES)
            .context("Failed to open cache references counter")?);

        // 4. LLC misses
        fds.push(open_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES)
            .context("Failed to open cache misses counter")?);

        // 5. Branch misses
        fds.push(open_event(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES)
            .context("Failed to open branch misses counter")?);

        // 6. TLB accesses
        fds.push(open_event(
            PERF_TYPE_HW_CACHE,
            cache_config(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_ACCESS))
            .context("Failed to open TLB access counter")?);

        // 7. TLB misses
        fds.push(open_event(
            PERF_TYPE_HW_CACHE,
            cache_config(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ, PERF_COUNT_HW_CACHE_RESULT_MISS))
            .context("Failed to open TLB miss counter")?);

        // Enable all counters
        for fd in &fds {
            unsafe {
                libc::ioctl(fd.as_raw_fd(), 0x2400); // PERF_EVENT_IOC_ENABLE
            }
        }

        Ok(Self {
            pid,
            fds,
            start_time: std::time::Instant::now(),
        })
    }

    fn read_counters(&self) -> Result<perf_event_data> {
        let mut data = perf_event_data {
            llc_misses: 0,
            llc_references: 0,
            tlb_misses: 0,
            tlb_references: 0,
            memory_bandwidth: 0,
            local_memory_accesses: 0,
            remote_memory_accesses: 0,
            instructions_retired: 0,
            cycles: 0,
            branch_misses: 0,
            last_perf_sample: 0,
            perf_sample_count: 0,
            _padding: 0,
        };

        // Read each counter
        for (i, fd) in self.fds.iter().enumerate() {
            let mut read_format = ReadFormat {
                value: 0,
                time_enabled: 0,
                time_running: 0,
            };

            let ret = unsafe {
                libc::read(
                    fd.as_raw_fd(),
                    &mut read_format as *mut _ as *mut libc::c_void,
                    std::mem::size_of::<ReadFormat>(),
                )
            };

            if ret < 0 {
                warn!("Failed to read counter {}: {}", i, std::io::Error::last_os_error());
                continue;
            }

            // Scale the value if the counter wasn't running all the time
            let value = if read_format.time_running > 0 && read_format.time_enabled > read_format.time_running {
                (read_format.value as f64 * read_format.time_enabled as f64 / read_format.time_running as f64) as u64
            } else {
                read_format.value
            };

            match i {
                0 => data.cycles = value,
                1 => data.instructions_retired = value,
                2 => data.llc_references = value,
                3 => data.llc_misses = value,
                4 => data.branch_misses = value,
                5 => data.tlb_references = value,
                6 => data.tlb_misses = value,
                _ => {}
            }
        }

        data.last_perf_sample = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        Ok(data)
    }
}

// Commands for the monitoring thread
pub enum MonitorCommand {
    Request { pid: u32, state: u8 },
    UpdateData { pid: u32, data: perf_event_data },
    RemoveData { pid: u32 },
    Shutdown,
}

// Global performance monitoring state
pub struct PerfMonitor {
    tx: Sender<MonitorCommand>,
    rx: Arc<Mutex<Receiver<MonitorCommand>>>,
    update_tx: Sender<MonitorCommand>,
    update_rx: Receiver<MonitorCommand>,
}

impl PerfMonitor {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        let (update_tx, update_rx) = channel();
        Self {
            tx,
            rx: Arc::new(Mutex::new(rx)),
            update_tx,
            update_rx,
        }
    }

    pub fn send_request(&self, pid: u32, state: u8) -> Result<()> {
        self.tx.send(MonitorCommand::Request { pid, state })?;
        Ok(())
    }

    pub fn try_recv_update(&mut self) -> Result<MonitorCommand> {
        Ok(self.update_rx.try_recv()?)
    }

    pub fn start_monitoring_thread(
        &self,
        shutdown: Arc<AtomicBool>,
    ) -> Result<thread::JoinHandle<()>> {
        let rx = self.rx.clone();
        let update_tx = self.update_tx.clone();

        let handle = thread::spawn(move || {
            info!("Performance monitoring thread started");
            let mut monitors: HashMap<pid_t, TaskPerfMonitor> = HashMap::new();

            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }

                // Check for commands
                if let Ok(rx) = rx.lock() {
                    if let Ok(cmd) = rx.recv_timeout(Duration::from_millis(100)) {
                        match cmd {
                            MonitorCommand::Request { pid, state } => {
                                debug!("Perf request for PID {} state {}", pid, state);

                                match state {
                                    1 => { // PERF_MON_PENDING
                                        // Start monitoring
                                        match TaskPerfMonitor::new(pid as pid_t) {
                                            Ok(monitor) => {
                                                info!("Started perf monitoring for PID {}", pid);
                                                monitors.insert(pid as pid_t, monitor);
                                            }
                                            Err(e) => {
                                                warn!("Failed to start perf monitoring for PID {}: {}", pid, e);
                                            }
                                        }
                                    }
                                    0 => { // PERF_MON_DISABLED
                                        // Stop monitoring
                                        if monitors.remove(&(pid as pid_t)).is_some() {
                                            info!("Stopped perf monitoring for PID {}", pid);
                                        }
                                    }
                                    _ => {
                                        warn!("Unknown perf monitoring state: {}", state);
                                    }
                                }
                            }
                            MonitorCommand::Shutdown => {
                                info!("Perf monitor received shutdown command");
                                break;
                            }
                            _ => {} // UpdateData and RemoveData are sent from scheduler
                        }
                    }
                }

                // Update performance data for all monitored tasks
                let mut to_remove = Vec::new();

                for (pid, monitor) in monitors.iter_mut() {
                    match monitor.read_counters() {
                        Ok(mut data) => {
                            // Increment sample count
                            data.perf_sample_count = monitor.start_time.elapsed().as_secs() as u32;

                            // Send update command back to scheduler
                            let pid_u32 = *pid as u32;
                            if let Err(e) = update_tx.send(MonitorCommand::UpdateData { pid: pid_u32, data }) {
                                warn!("Failed to send perf data update: {}", e);
                            } else {
                                debug!("Read perf data for PID {}: cycles={}, instructions={}, llc_misses={}",
                                    pid, data.cycles, data.instructions_retired, data.llc_misses);
                            }
                        }
                        Err(e) => {
                            // Task might have exited
                            debug!("Failed to read perf counters for PID {}: {}", pid, e);
                            to_remove.push(*pid);
                        }
                    }
                }

                // Remove monitors for dead tasks
                for pid in to_remove {
                    monitors.remove(&pid);
                    // Send remove command
                    let pid_u32 = pid as u32;
                    let _ = update_tx.send(MonitorCommand::RemoveData { pid: pid_u32 });
                }
            }

            info!("Performance monitoring thread exiting");
        });

        Ok(handle)
    }

    pub fn stop(&self) -> Result<()> {
        self.tx.send(MonitorCommand::Shutdown)?;
        Ok(())
    }
}