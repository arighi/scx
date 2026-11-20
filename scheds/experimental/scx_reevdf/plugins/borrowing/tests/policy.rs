// SPDX-License-Identifier: GPL-2.0-only

mod task {
    pub const NICE_0_WEIGHT: u64 = 1024;
}
#[path = "../../../bpf/src/accounting.rs"]
#[allow(dead_code)]
mod math;
#[path = "../src/policy.rs"]
mod policy;
use math::{NICE_0_WEIGHT, Request, charge, join_delta, leave_delta};
use policy::borrow_vtime;

#[test]
fn borrowing_keeps_weighted_reference_and_deadline_consistent() {
    // A competitor at 800 and a wakee at 1200 have an average of 1000.
    // Remove the wakee, grant 100 ns of nice-0 credit, then rejoin it.
    let reference = 1000_u64.wrapping_add(leave_delta(1000, 2048, 1200, 1024));
    assert_eq!(reference, 800);
    let target = borrow_vtime(1200, reference, 100, 1024, 1024);
    let joined = reference.wrapping_add(join_delta(reference, 1024, target, 1024));
    assert_eq!(joined.wrapping_sub(target), 100);
    let mut request = Request {
        deadline: 1500,
        slice: 300,
        weight: 1024,
    };
    request.rebase(1200, target);
    assert_eq!(request.deadline.wrapping_sub(target), 300);
    // Normal charging resumes from the new coordinate, without hiding
    // service behind the old joined stamp.
    let (step, _) = charge(1024, 200, 2048, 0);
    assert_eq!(joined.wrapping_add(step), target.wrapping_add(200));
}

#[test]
fn borrowing_scales_credit_and_preserves_existing_lag_across_wrap() {
    let reference = 50_u64;
    for weight in [512, 1024, 2048] {
        let target = borrow_vtime(100, reference, 100, weight, 1024);
        let joined = reference.wrapping_add(join_delta(reference, 1024, target, weight));
        assert_eq!(joined.wrapping_sub(target), 100 * NICE_0_WEIGHT / weight);
        let earlier = target.wrapping_sub(100);
        assert_eq!(borrow_vtime(earlier, reference, 100, weight, 1024), earlier);
    }
    assert_eq!(borrow_vtime(100, 50, 0, 1024, 1024), 100);
    assert_eq!(borrow_vtime(100, 50, 100, 0, 1024), 100);
    assert_eq!(borrow_vtime(100, 50, 100, 1024, 0), 100);
}
