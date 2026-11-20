// SPDX-License-Identifier: GPL-2.0-only
//! Wakeup-credit policy, built independently of the host's callback entries.

#![no_std]
#![no_main]

use scx_reevdf_kernel::{Reevdf, api::math};
use scx_rustsched::{
    prelude::{EnqFlags, Task},
    var::Var,
};

mod policy;

/// Service credit at the member's effective weight. Repeated wakeups can
/// receive fresh credit; this is a latency bias, not a repayment scheme.
const CREDIT_NS: u64 = 1_000_000;

scx_rustsched::shared! {
    pub static BORROWED in ".data.plugin_borrow": Var<u64> = Var::new(0);
}

#[scx_rustsched::plugin(manifest = "src/imports.plugin")]
impl BorrowingPlugin {
    #[inline(always)]
    fn enqueue(task: &Task, flags: EnqFlags) {
        Reevdf::enqueue_with(task, flags, |placed| {
            if flags.contains(EnqFlags::WAKEUP)
                && !flags.blocked()
                && !placed.is_initial()
                && !placed.is_reenqueue()
                && placed.adjust_vruntime(|position| {
                    policy::borrow_vtime(
                        position.current,
                        position.reference,
                        CREDIT_NS,
                        position.weight,
                        position.peers,
                    )
                })
            {
                BORROWED.add(1);
            }
        });
    }
}
