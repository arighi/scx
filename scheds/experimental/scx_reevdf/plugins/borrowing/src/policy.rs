// SPDX-License-Identifier: GPL-2.0-only

use crate::math::{NICE_0_WEIGHT, place, time_before};

/// A wakeup credit in ns of service, scaled at the member's actual weight.
/// Keep an existing larger lag. Comparisons use signed differences so the
/// virtual-time coordinate may wrap through zero.
#[inline(always)]
pub fn borrow_vtime(vtime: u64, reference: u64, credit_ns: u64, weight: u64, others: u64) -> u64 {
    if credit_ns == 0 || weight == 0 || others == 0 {
        return vtime;
    }
    let credit = credit_ns.saturating_mul(NICE_0_WEIGHT) / weight;
    // Inflate the offset to account for the average moving as we rejoin.
    let target = place(reference, others, credit as i64, weight);
    if time_before(target, vtime) {
        target
    } else {
        vtime
    }
}
