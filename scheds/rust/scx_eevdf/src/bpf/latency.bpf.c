/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Virtual-time borrowing for latency-sensitive wakees. Placement floors a
 * wakee's carried lag at a fixed virtual-time credit, and optional packing
 * sends admitted work to a higher asymmetric-packing tier when no CPU is
 * idle.
 */
#include "latency.bpf.h"
#include "task.bpf.h"

static u64 credit_pack_cursor;

/*
 * Return whether @tctx may borrow on @cid. The sleep window is always met by
 * a wakeup; it also defines the current tasks that packing leaves alone.
 */
static __always_inline bool task_credit_admitted(s32 cid,
						 const task_ctx_t *tctx, u64 now)
{
	return latency_credit &&
	       now - tctx->last_sleep_at < latency_credit_sleep_ns;
}

/*
 * Return the offset from the destination reference used to place @p: the lag
 * carried out of its old pack, with a minimum of the configured virtual-time
 * credit.
 *
 * The credit is a fixed placement scale rather than a computed minimum needed
 * to cross the current deadline frontier. It is scaled by the task's deadline
 * weight.
 */
static s64 task_place_offset(const struct task_struct *p, task_ctx_t *tctx)
{
	s64 credit;

	if (!latency_credit)
		return tctx->se.vlag;

	credit = (s64)scale_by_dl_weight(p, tctx, latency_credit_ns);

	return MAX(tctx->se.vlag, credit);
}

/*
 * Return the cid an admitted wakee is queued on when the idle scan found
 * nothing: @target, unless a cid of a higher asymmetric-packing priority
 * is running a task that never sleeps.
 *
 * SD_ASYM_PACKING fills the preferred CPUs first, and fair.c's asymmetric
 * active balance pulls a running task up to a preferred CPU only when that
 * CPU is idle. With a hog on every CPU nothing is ever idle, and a task
 * stays wherever its wakeups keep finding it. The WebGL aquarium's render
 * thread sat on an E-core at 2.2 GHz for as long as the hogs ran, at 19
 * fps, while the same thread pinned to a P-core beside its hog made 37 to
 * 46. The credit already lets the wakee win the CPU from a hog wherever it
 * lands, so let it land where the CPU is fastest: the hog there loses its
 * turn, and the balancer finds it a lower-priority CPU in due course. A
 * cid whose current task slept recently is left alone, it is running work
 * of the same kind, and a cursor spreads successive wakees over the tier.
 * A task pinned to one CPU, or one whose target is already in the top
 * tier, is not moved.
 */
static s32 credit_pack_cid(const struct task_struct *p, task_ctx_t *tctx,
			   s32 target, u64 now)
{
	u32 tier, t, i, start;
	bool restricted;

	if (!latency_credit || no_latency_credit_pack || !asym_packing ||
	    nr_place_tiers < 2 || !cid_valid(target) || is_pcpu_task(p))
		return target;
	tier = cid_topo(target)->place_tier;
	if (!tier || !task_credit_admitted(target, tctx, now))
		return target;

	restricted = is_restricted(p);
	start = __sync_fetch_and_add(&credit_pack_cursor, 1);
	bpf_arena_for(t, 0, tier) {
		bpf_arena_for(i, 0, nr_cids) {
			s32 cid = (start + i) % nr_cids;

			if (cid_topo(cid)->place_tier != t)
				continue;
			if (READ_ONCE(cid_ctx(cid)->curr_sleeper))
				continue;
			if (restricted && !cid_allowed(p, cid))
				continue;
			return cid;
		}
	}

	return target;
}
