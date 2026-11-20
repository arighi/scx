// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.

//! Native callback entries for the shared reevdf implementation.

#![no_std]
#![no_main]

use scx_reevdf_kernel::{Reevdf, TaskContext};
use scx_rustsched::prelude::{
    Cgroup, CgroupArgs, Cid, DeqFlags, DumpCtx, EnqFlags, Error, InitTaskArgs, Task, WakeFlags,
};

/// Forward native callbacks to the shared implementation. The library
/// owns idle tracking, so these entries disable runtime idle tracking.
#[scx_rustsched::scheduler(
    name = "reevdf",
    flags = TID_TO_TASK | ENQ_LAST | ENQ_EXITING | ENQ_MIGRATION_DISABLED | ALLOW_QUEUED_WAKEUP,
    task_slot = TaskContext,
    idle_tracking = false
)]
impl Host {
    #[inline(always)]
    fn init() -> Result<(), Error> {
        Reevdf::init()
    }

    #[inline(always)]
    fn init_task(task: &Task, args: &InitTaskArgs) {
        Reevdf::init_task(task, args)
    }

    #[inline(always)]
    fn exit_task(task: &Task) {
        Reevdf::exit_task(task)
    }

    #[inline(always)]
    fn enable(task: &Task) {
        Reevdf::enable(task)
    }

    #[inline(always)]
    fn select_cid(task: &Task, previous: Cid, flags: WakeFlags) -> Cid {
        Reevdf::select_cid(task, previous, flags)
    }

    #[inline(always)]
    fn enqueue(task: &Task, flags: EnqFlags) {
        Reevdf::enqueue(task, flags)
    }

    #[inline(always)]
    fn dequeue(task: &Task, flags: DeqFlags) {
        Reevdf::dequeue(task, flags)
    }

    #[inline(always)]
    fn dispatch(cid: Cid, prev: Option<&Task>) {
        Reevdf::dispatch(cid, prev)
    }

    #[inline(always)]
    fn tick(task: &Task) {
        Reevdf::tick(task)
    }

    #[inline(always)]
    fn running(task: &Task) {
        Reevdf::running(task)
    }

    #[inline(always)]
    fn stopping(task: &Task, runnable: bool) {
        Reevdf::stopping(task, runnable)
    }

    #[inline(always)]
    fn quiescent(task: &Task, flags: DeqFlags) {
        Reevdf::quiescent(task, flags)
    }

    #[inline(always)]
    fn yield_task(from: &Task, to: Option<&Task>) -> bool {
        Reevdf::yield_task(from, to)
    }

    #[inline(always)]
    fn core_sched_before(a: &Task, b: &Task) -> bool {
        Reevdf::core_sched_before(a, b)
    }

    #[inline(always)]
    fn set_cmask(task: &Task) {
        Reevdf::set_cmask(task)
    }

    #[inline(always)]
    fn update_idle(cid: Cid, idle: bool) {
        Reevdf::update_idle(cid, idle)
    }

    #[inline(always)]
    fn dump_task(dump: &DumpCtx, task: &Task) {
        Reevdf::dump_task(dump, task)
    }

    #[inline(always)]
    fn cgroup_init(cgroup: &Cgroup, args: &CgroupArgs) -> Result<(), Error> {
        Reevdf::cgroup_init(cgroup, args)
    }

    #[inline(always)]
    fn cgroup_exit(cgroup: &Cgroup) {
        Reevdf::cgroup_exit(cgroup)
    }

    #[inline(always)]
    fn cgroup_move(task: &Task, _from: &Cgroup, to: &Cgroup) {
        Reevdf::cgroup_move(task, _from, to)
    }

    #[inline(always)]
    fn cgroup_set_weight(cgroup: &Cgroup, weight: u32) {
        Reevdf::cgroup_set_weight(cgroup, weight)
    }

    #[inline(always)]
    fn cgroup_set_idle(cgroup: &Cgroup, idle: bool) {
        Reevdf::cgroup_set_idle(cgroup, idle)
    }

    #[inline(always)]
    fn cgroup_set_bandwidth(cgroup: &Cgroup, period_us: u64, quota_us: u64, burst_us: u64) {
        Reevdf::cgroup_set_bandwidth(cgroup, period_us, quota_us, burst_us)
    }
}
