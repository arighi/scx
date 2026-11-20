// SPDX-License-Identifier: GPL-2.0-only

//! Callback-provider API. Queued state stays private to the host; policies
//! choose numeric coordinates and the host maintains their accounting.

use scx_rustsched::prelude::{Cid, EnqFlags, Task};

pub mod math {
    pub use crate::accounting::{NICE_0_WEIGHT, place, time_before};
}

/// A task temporarily removed from its pack's average. The reference is
/// projected for rejoining at weight, and peers excludes this task.
#[derive(Clone, Copy)]
pub struct VruntimePosition {
    pub current: u64,
    pub reference: u64,
    pub weight: u64,
    pub peers: u64,
}

/// A placed task before deadline preparation and EDQ insertion. This
/// handle cannot outlive its enqueue callback or expose mutable arena data.
pub struct QueuedTask<'a> {
    task: &'a Task,
    state: &'a crate::taskctx::Context,
    cid: Cid,
    flags: EnqFlags,
    now: u64,
}

impl QueuedTask<'_> {
    #[inline(always)]
    pub fn is_initial(&self) -> bool {
        self.state.initial().get()
    }

    #[inline(always)]
    pub fn is_reenqueue(&self) -> bool {
        crate::reenq_reason(self.task, self.flags).is_some()
    }

    /// Select a new coordinate while preserving pack membership, cgroup
    /// load and the unfinished request's relative deadline. Refuse to
    /// adjust the CID's published running task. Return whether it changed.
    #[inline(always)]
    pub fn adjust_vruntime(&mut self, choose: impl FnOnce(VruntimePosition) -> u64) -> bool {
        crate::pack::rebase(self.state, self.cid, self.now, choose)
    }
}

impl crate::Reevdf {
    /// Specialize ordinary enqueue with a policy applied after placement.
    /// This is a static call, inlined into the provider's BPF object.
    #[inline(always)]
    pub fn enqueue_with(task: &Task, flags: EnqFlags, policy: impl FnOnce(&mut QueuedTask<'_>)) {
        crate::enqueue_with(task, flags, |task, state, cid, flags, now| {
            policy(&mut QueuedTask {
                task,
                state,
                cid,
                flags,
                now,
            });
        });
    }
}
