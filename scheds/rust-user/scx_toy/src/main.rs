mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

use std::thread;

use std::ffi::CStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::collections::BTreeSet;

use anyhow::Context;
use anyhow::Result;
use libbpf_rs::skel::OpenSkel as _;
use libbpf_rs::skel::Skel as _;
use libbpf_rs::skel::SkelBuilder as _;
use log::debug;
use log::info;
use log::warn;

#[derive(Debug, PartialEq, Eq, PartialOrd)]
#[repr(C)]
struct Task {
    pid: i32,
    data: u64,
}

impl Ord for Task {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.data
            .cmp(&other.data)
            .then_with(|| self.pid.cmp(&other.pid))
    }
}

struct TaskPool {
    tasks: BTreeSet<Task>,
}

impl TaskPool {
    fn new() -> Self {
        TaskPool {
            tasks: BTreeSet::new(),
        }
    }

    fn push(&mut self, pid: i32, data: u64) {
        let task = Task { pid, data };
        self.tasks.insert(task);
    }

    fn pop(&mut self) -> Option<Task> {
        self.tasks.pop_first()
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    task_pool: TaskPool,
    struct_ops: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    fn init() -> Result<Self> {
        // Open the BPF prog first for verification.
        let skel_builder = BpfSkelBuilder::default();
        let mut skel = skel_builder.open().context("Failed to open BPF program")?;
        skel.bss_mut().usersched_pid = std::process::id();

        // Scheduler task pool to sort task by data.
        let task_pool = TaskPool::new();

        // Attach BPF scheduler.
        let mut skel = skel.load().context("Failed to load BPF program")?;
        skel.attach().context("Failed to attach BPF program")?;
        let struct_ops = Some(
            skel.maps_mut()
                .toy()
                .attach_struct_ops()
                .context("Failed to attach toy struct ops")?,
        );
        info!("Toy Scheduler Attached");

        // Return scheduler object.
        Ok(Self {
            skel,
            task_pool,
            struct_ops,
        })
    }

    fn read_bpf_exit_kind(&mut self) -> i32 {
        unsafe { std::ptr::read_volatile(&self.skel.bss().exit_kind as *const _) }
    }

    fn report_bpf_exit_kind(&mut self) -> Result<()> {
        match self.read_bpf_exit_kind() {
            0 => Ok(()),
            etype => {
                let cstr = unsafe { CStr::from_ptr(self.skel.bss().exit_msg.as_ptr() as *const _) };
                let msg = cstr
                    .to_str()
                    .context("Failed to convert exit msg to string")
                    .unwrap();
                info!("BPF exit_kind={} msg={}", etype, msg);
                Ok(())
            }
        }
    }

    fn schedule(&mut self) {
        let maps = self.skel.maps();
        let enqueued = maps.enqueued();
        let dispatched = maps.dispatched();

        // Drain enqueued list and store tasks into the task pool (sorted by data)
        loop {
            match enqueued.lookup_and_delete(&[]) {
                Ok(Some(val)) => {
                    let task = unsafe { &*(val.as_slice().as_ptr() as *const bpf_intf::task_ctx) };
                    self.task_pool.push(task.pid, task.data);
                }
                Ok(None) => break,
                Err(err) => {
                    warn!("Error: {}", err);
                    break;
                }
            }
        }

        // Dispatch drained tasks in order
        debug!("=== BEGIN dispatch ===");
        loop {
            match self.task_pool.pop() {
                Some(task) => {
                    let task_struct: &[u8] = unsafe {
                        std::slice::from_raw_parts(
                            &task as *const Task as *const u8,
                            std::mem::size_of::<Task>(),
                        )
                    };
                    match dispatched.update(&[], &task_struct, libbpf_rs::MapFlags::ANY) {
                        Ok(_) => {}
                        Err(_) => {
                            /*
                             * Re-add the task to the dispatched list in case of failure and stop
                             * dispatching.
                             */
                            self.task_pool.push(task.pid, task.data);
                            break;
                        }
                    }
                    debug!("task={:?}", task);
                }
                None => break,
            }
        }
        debug!("=== END dispatch ===");

        // Yield to avoid using too much CPU from the scheduler itself.
        thread::yield_now();
    }

    // Print internal scheduler statistics.
    fn print_stats(&mut self) {
        let nr_enqueues = self.skel.bss().nr_enqueues as u64;
        let nr_user_dispatches = self.skel.bss().nr_user_dispatches as u64;
        let nr_kernel_dispatches = self.skel.bss().nr_kernel_dispatches as u64;

        info!(
            "nr_enqueues={} nr_user_dispatched={} nr_kernel_dispatches={}",
            nr_enqueues, nr_user_dispatches, nr_kernel_dispatches
        );
        log::logger().flush();
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<()> {
        let mut prev_ts = SystemTime::now();

        while !shutdown.load(Ordering::Relaxed) && self.read_bpf_exit_kind() == 0 {
            let curr_ts = SystemTime::now();
            let elapsed = curr_ts
                .duration_since(prev_ts)
                .unwrap_or_else(|_| Duration::from_secs(0));

            self.schedule();

            // Print scheduler statistics every second
            if elapsed > Duration::from_secs(1) {
                self.print_stats();
                prev_ts = curr_ts;
            }
        }

        self.report_bpf_exit_kind()
    }
}

impl<'a> Drop for Scheduler<'a> {
    fn drop(&mut self) {
        if let Some(struct_ops) = self.struct_ops.take() {
            drop(struct_ops);
        }
        info!("Unregister toy scheduler");
    }
}

fn main() -> Result<()> {
    let loglevel = simplelog::LevelFilter::Info;

    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    let mut sched = Scheduler::init()?;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    sched.run(shutdown)
}
