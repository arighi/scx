/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Virtual-time borrowing for latency-sensitive wakees. Placement floors a
 * wakee's carried lag at a fixed virtual-time credit, a per-pack budget
 * bounds what credited work may take in aggregate, and optional packing
 * sends admitted work to a higher asymmetric-packing tier when no CPU is
 * idle.
 */
#include "latency.bpf.h"
#include "task.bpf.h"

/* @latency_credit_budget at which a pack lends without limit. */
#define CREDIT_UNBOUNDED	1024

static u64 credit_pack_cursor;

/*
 * The most service a pack lends before it has to earn more, and, negated, the
 * deepest debt one round of lending may leave it in. The ceiling bounds what
 * an idle pack saves up, so the first storm to arrive cannot spend a quiet
 * minute in one round; a credited task's whole burst should fit inside it.
 * The floor bounds how long a pack that lent to a storm stays out of the
 * credit afterwards: without it that is decided by whatever the tasks already
 * admitted go on to consume, which is nothing the budget can name.
 */
static __always_inline s64 credit_burst(void)
{
	return (s64)(slice_ns * 4);
}

/*
 * Move @pk's allowance by @delta, saturating at either end of the burst.
 * Wakeups refill a pack from other CPUs while the cid charges it, so the
 * exchange is retried rather than letting a lost race carry the allowance
 * past a bound it is the whole point of.
 */
static void credit_add(pack_t *pk, s64 delta)
{
	s64 burst = credit_burst();
	s64 old, new;

	while (can_loop) {
		old = READ_ONCE(pk->credit_tokens);
		new = old + delta;
		if (new > burst)
			new = burst;
		else if (new < -burst)
			new = -burst;
		if (new == old || cmpxchg(&pk->credit_tokens, old, new) == old)
			return;
	}
}

/*
 * Grow @pk's allowance by its share of the time the cid has had since the
 * last refill, measured in the cid's task clock: the same clock credited
 * service is charged in, and one that already excludes the interrupt and
 * steal time the CPU never had to give away.
 *
 * That clock does not stand still for idle, so a pack earns while its cid is
 * idle as well as while it runs, and the budget is a share of the CPU rather
 * than of the service the pack happened to deliver. This is deliberate: an
 * idle CPU is where a wakee is cheapest to favour, and a rule that only paid
 * a busy pack would withhold the credit exactly where it costs nothing.
 * @credit_burst() is what keeps a long idle from being spendable at once.
 *
 * Refills are spaced by a quarter slice. The wakeup path is where this runs,
 * and under the storms this exists to bound that is every wakeup on the cid;
 * without the spacing they would serialize on one cacheline to add a few
 * nanoseconds each. A refill that loses the exchange simply lets the winner's
 * interval cover it.
 */
static void credit_refill(pack_t *pk, u64 tnow)
{
	u64 last = READ_ONCE(pk->credit_refill_at);
	s64 delta, gain, tokens, burst, room;
	u64 span;

	/*
	 * Signed: @tnow is an rq clock less an offset another CPU publishes,
	 * see cid_clock_task_at(), so it can step backwards by the interrupt
	 * time that offset grew by between two reads. Unsigned, such a step
	 * reads as an interval of almost 2^64 and buys a full burst.
	 */
	delta = (s64)(tnow - last);
	if (delta < (s64)(slice_ns >> 2))
		return;
	if (cmpxchg(&pk->credit_refill_at, last, tnow) != last)
		return;

	if (!latency_credit_budget)
		return;
	burst = credit_burst();
	tokens = READ_ONCE(pk->credit_tokens);
	room = burst - tokens;
	if (room <= 0)
		return;

	/*
	 * Nothing beyond @room can be earned in one refill, so bound the
	 * interval that buys it before it is scaled. That is also what keeps
	 * the product in range on a pack's first refill, where @last is zero
	 * and the interval is the machine's whole uptime. Both sides are
	 * positive here and the arithmetic is unsigned: BPF has no signed
	 * divide.
	 */
	span = (u64)room * CREDIT_UNBOUNDED / latency_credit_budget;
	if ((u64)delta >= span)
		gain = room;
	else
		gain = (s64)((u64)delta * latency_credit_budget /
			     CREDIT_UNBOUNDED);
	if (gain > 0)
		credit_add(pk, gain);
}

/*
 * Whether @pk has anything left to lend, without refilling it. Packing reads
 * this for every cid it considers, and the placement path refills the cid it
 * lands on, so the value a scan sees is at most a quarter slice stale.
 *
 * A pack that has never refilled holds no tokens yet and is treated as able
 * to lend: it is the first wakee's placement that fills it, and packing has
 * to be able to send that wakee there. Without this a cid that never took a
 * credited wakeup could never be picked to take one.
 */
static __always_inline bool credit_available(pack_t *pk)
{
	if (latency_credit_budget >= CREDIT_UNBOUNDED)
		return true;
	if (!latency_credit_budget)
		return false;

	return !READ_ONCE(pk->credit_refill_at) ||
	       READ_ONCE(pk->credit_tokens) > 0;
}

/*
 * Hand what @cid's pack has counted since the last tick to the totals user
 * space reads. The counters live in the pack, on a line the placement path
 * already owns, so a wakeup pays nothing for them; one exchange per tick is
 * what turns them into a number. Nothing is counted on a cid without a wakee
 * being queued there for it, so a pack with something to fold is a pack whose
 * cid is about to tick.
 */
static void credit_stats_fold(s32 cid)
{
	pack_t *pk;
	u64 v;

	if (latency_credit_budget >= CREDIT_UNBOUNDED || !cid_valid(cid))
		return;
	pk = cid_pack(cid);

	v = __sync_lock_test_and_set(&pk->credit_grants, 0);
	if (v)
		__sync_fetch_and_add(&nr_credit_grants, v);
	v = __sync_lock_test_and_set(&pk->credit_denied, 0);
	if (v)
		__sync_fetch_and_add(&nr_credit_denied, v);
}

/*
 * Charge @delta of service to the budget of @pk, the pack @tctx is credited
 * on. A loan is only ever repaid to the pack that granted it: every arrival
 * in another pack clears the flag, see place_task() and eevdf_running(), so
 * a task that still carries it has not moved since it was placed.
 *
 * What a loan costs the tasks it displaces is the service the credited task
 * takes while it sits ahead of them, not the displacement it was granted:
 * placement is absolute, vruntime = vref - credit on every wakeup and never
 * cumulative, so a thread waking three thousand times a second is granted
 * sixty seconds of virtual time per second and costs a hog only the bursts
 * it actually runs. Charging grants would price that thread out of the
 * credit it was built for, which is what bounding the loan per task already
 * did once, see the aquarium numbers behind the flat credit.
 *
 * So charge consumption. What the budget then says is that uncredited work
 * keeps at least 1 - @latency_credit_budget of the pack, whatever the number
 * of credited sleepers, which is the one thing no per-task rule can promise.
 */
static void credit_charge(pack_t *pk, task_ctx_t *tctx, u64 delta)
{
	if (latency_credit_budget >= CREDIT_UNBOUNDED)
		return;
	if (delta)
		credit_add(pk, -(s64)delta);

	/*
	 * The loan is spent once the task has caught the reference. From here
	 * it is ahead of nobody and what it runs is its own turn, so stop
	 * charging it for a position it no longer holds.
	 */
	if (!time_before(tctx->se.vruntime, pack_vref(pk)))
		tctx->credited = false;
}

/*
 * Whether @cid has queued enough tasks to stop granting the credit, see
 * task_place_offset().
 */
static __always_inline bool credit_crowded(s32 cid)
{
	return latency_credit_max_queued && cid_valid(cid) &&
	       cid_queue_nr(cid) >= latency_credit_max_queued;
}

/*
 * Return whether @p is a task that sleeps, as opposed to one that computes:
 * whether it has run for less than @latency_credit_burst_ns since it last
 * blocked. Credit packing leaves a cid whose current task is a sleeper alone,
 * see credit_pack_cid().
 *
 * A wall-clock window cannot tell the two apart. A stress-ng worker blocks
 * once while it starts and computes from then on, and a window of seconds
 * calls it a sleeper for as long, so the first seconds of every new hog are
 * spent on a cid packing will not touch. Service can: the hog is judged
 * after a burst no pipeline stage takes. It is also blind to waiting. A task
 * that has not run is not turning into a hog however long it sat queued, and
 * neither is a task that has not slept yet, whose @sleep_exec is zero and
 * which is judged on all it has run.
 */
static __always_inline bool task_sleeper(const struct task_struct *p,
					 const task_ctx_t *tctx, u64 now)
{
	/*
	 * A proxy-execution donor is waiting for a mutex, and the service
	 * charged to it is what the mutex owner runs on its behalf. Judged on
	 * that service it would turn into a hog after one long critical
	 * section, and taking its CPU away would stall the owner it waits on.
	 */
	if (task_is_blocked(p))
		return true;
	if (latency_credit_burst_ns)
		return p->se.sum_exec_runtime - tctx->sleep_exec <
		       latency_credit_burst_ns;
	return now - tctx->last_sleep_at < latency_credit_sleep_ns;
}

static void smt_guard_release(s32 sib);
static void smt_guard_tick(s32 cid, u64 now);

/*
 * Record whether @cid runs a task that is not a sleeper, and keep
 * @nr_hog_cids in step. Only the cid's own CPU calls this, from
 * ops.running(), ops.tick() and ops.update_idle(), so the flag needs no
 * atomic and the shared count is written only when the flag changes.
 */
static void cid_set_hog(s32 cid, bool hog)
{
	struct cid_ctx __arena *cctx;

	if (!latency_credit || !cid_valid(cid))
		return;
	cctx = cid_ctx(cid);
	if (READ_ONCE(cctx->curr_hog) == hog)
		return;
	WRITE_ONCE(cctx->curr_hog, hog);
	if (hog)
		__sync_fetch_and_add(&nr_hog_cids, 1);
	else
		__sync_fetch_and_sub(&nr_hog_cids, 1);
}

/*
 * A running task stops being a sleeper without switching out when it
 * computes past its burst, see task_sleeper(), and ops.running() is the only
 * other place @curr_sleeper is set. Take it back at the tick.
 *
 * Under the SMT guard the same task may be keeping its sibling held, or be
 * one the sibling's sleeper should not share the core with: release the
 * sibling, and hand this cid to the hold by preempting the task.
 */
static void credit_tick(s32 cid, struct task_struct *p, u64 now)
{
	struct cid_ctx __arena *cctx;
	task_ctx_t *tctx;
	s32 sib;

	if (!latency_credit || !cid_valid(cid))
		return;
	smt_guard_tick(cid, now);
	cctx = cid_ctx(cid);
	if (!READ_ONCE(cctx->curr_sleeper) && !READ_ONCE(cctx->sg_sleeper))
		return;
	tctx = try_lookup_task_ctx(p);
	if (!tctx || task_sleeper(p, tctx, now))
		return;
	WRITE_ONCE(cctx->curr_sleeper, 0);
	cid_set_hog(cid, true);
	sib = smt_guard_sibling(cid);
	if (sib < 0 || !READ_ONCE(cctx->sg_sleeper))
		return;
	WRITE_ONCE(cctx->sg_sleeper, 0);
	smt_guard_release(sib);
	if (READ_ONCE(cid_ctx(sib)->sg_sleeper) && !is_pcpu_task(p))
		scx_bpf_kick_cid(cid, SCX_KICK_PREEMPT);
}

/*
 * Return whether @tctx may borrow on @cid. The sleep window is always met by
 * a wakeup.
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
 *
 * A pack out of budget places the wakee at the lag it earned, which is
 * ordinary EEVDF: the mechanism turns itself off under exactly the load that
 * exhausts it, rather than letting every wakee conclude on its own that it
 * has earned another loan.
 */
static s64 task_place_offset(s32 cid, pack_t *pk, const struct task_struct *p,
			     task_ctx_t *tctx, u64 now, u64 tnow)
{
	bool bounded = latency_credit_budget < CREDIT_UNBOUNDED;
	s64 credit;

	if (!latency_credit)
		return tctx->se.vlag;

	/*
	 * A credited join pulls the pack's reference down, and the next one
	 * pulls it down again. A task queued behind the reference, one that
	 * overran its request and is waiting to become eligible, is kept
	 * waiting for as long as the joins keep coming: under a sleep storm
	 * that is until the watchdog fires. A crowded pack therefore places
	 * the wakee at the lag it earned. Ordinary EEVDF conserves the
	 * reference, and every waiter becomes eligible in its turn.
	 *
	 * The limit is a queue length rather than a budget because what the
	 * credit is for, a pipeline thread beside a hog, queues one or two
	 * tasks, and what it must not do happens on a queue of hundreds.
	 */
	if (credit_crowded(cid))
		return tctx->se.vlag;

	if (bounded) {
		credit_refill(pk, tnow);
		if (READ_ONCE(pk->credit_tokens) <= 0) {
			__sync_fetch_and_add(&pk->credit_denied, 1);
			return tctx->se.vlag;
		}
	}

	credit = (s64)scale_by_dl_weight(p, tctx, latency_credit_ns);

	/*
	 * A task whose own lag already carries it further than the credit is
	 * not borrowing anything: it is being placed where EEVDF would place
	 * it. Leave it uncredited so the budget is charged for loans only.
	 */
	if (credit <= tctx->se.vlag)
		return tctx->se.vlag;

	tctx->credited = true;
	if (bounded)
		__sync_fetch_and_add(&pk->credit_grants, 1);

	return credit;
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
 *
 * A cid out of credit budget is left alone too, and so is a crowded one. The
 * move is worth making only because the credit wins the CPU on arrival;
 * without it the wakee is merely queued behind a hog it did not choose, which
 * is worse than the target the wakeup picked for itself. A crowded cid would
 * also collect every admitted wakee of a storm: its current task being the
 * one that does not sleep is what makes it a destination, and nothing else
 * the scan looks at changes as the queue grows.
 */
static s32 credit_pack_cid(const struct task_struct *p, task_ctx_t *tctx,
			   s32 target, u64 now)
{
	u32 tier, t, i, start;
	bool restricted;

	if (!latency_credit || no_latency_credit_pack || !asym_packing ||
	    nr_place_tiers < 2 || !cid_valid(target) || is_pcpu_task(p))
		return target;
	/*
	 * Every destination runs a task that does not sleep. With none running
	 * anywhere there is nothing to find, and the scans below would cost a
	 * wakeup-heavy load a walk of every cid on each wakeup, on the waker's
	 * CPU.
	 */
	if (!READ_ONCE(nr_hog_cids))
		return target;
	tier = cid_topo(target)->place_tier;
	if (!task_credit_admitted(target, tctx, now))
		return target;

	/*
	 * Under the SMT guard a target whose core already runs a sleeper, on
	 * the target itself or on its sibling, is no better than any other
	 * core that is not an E-core: the wakee would share it with another
	 * stage of the same pipeline. Wake-affine puts a wakee on its waker's
	 * cid, so without this the stages of one pipeline pile onto the top
	 * tier while the cores below it run hogs. At the clock a loaded
	 * package runs every core at, a core of the next tier to itself is
	 * worth more than half a core of the top one.
	 */
	if (smt_guard) {
		s32 tsib = smt_guard_sibling(target);

		if (READ_ONCE(cid_ctx(target)->sg_sleeper) ||
		    (tsib >= 0 && READ_ONCE(cid_ctx(tsib)->sg_sleeper)))
			tier = nr_place_tiers - 1;
	}
	if (!tier)
		return target;

	restricted = is_restricted(p);
	start = __sync_fetch_and_add(&credit_pack_cursor, 1);

	/*
	 * With the guard, look for a whole core first: a cid whose sibling is
	 * not running a sleeper either, so the guard gives the wakee the core.
	 */
	if (smt_guard) {
		bpf_arena_for(t, 0, tier) {
			bpf_arena_for(i, 0, nr_cids) {
				s32 cid = (start + i) % nr_cids;
				s32 sib;

				if (cid_topo(cid)->place_tier != t)
					continue;
				if (READ_ONCE(cid_ctx(cid)->curr_sleeper))
					continue;
				sib = smt_guard_sibling(cid);
				if (sib >= 0 &&
				    READ_ONCE(cid_ctx(sib)->sg_sleeper))
					continue;
				if (!credit_available(cid_pack(cid)))
					continue;
				if (credit_crowded(cid))
					continue;
				if (restricted && !cid_allowed(p, cid))
					continue;
				return cid;
			}
		}
	}
	bpf_arena_for(t, 0, tier) {
		bpf_arena_for(i, 0, nr_cids) {
			s32 cid = (start + i) % nr_cids;

			if (cid_topo(cid)->place_tier != t)
				continue;
			if (READ_ONCE(cid_ctx(cid)->curr_sleeper))
				continue;
			if (!credit_available(cid_pack(cid)))
				continue;
			if (credit_crowded(cid))
				continue;
			if (restricted && !cid_allowed(p, cid))
				continue;
			return cid;
		}
	}

	return target;
}

/*
 * SMT guard.
 *
 * A thread of a pipeline stage that wins its CPU from a hog still shares the
 * core with whatever runs on the sibling, and a hog there takes about half the
 * core's throughput. The WebGL aquarium's stages need the throughput of about
 * two whole cores between them: beside a hog on every CPU they ran at 22 to 24
 * fps with the latency credit, and at 55 with two cores kept free by hand.
 *
 * So while a cid runs a sleeper, see task_sleeper(), its SMT sibling is kept
 * from running a task that is not one: the sibling's current hog is preempted,
 * and its dispatch declines to pick one, going idle instead. Two sleepers
 * share a core as they would anyway, and a hog is held off for at most
 * @smt_guard_max_ns at a time, so one that can only run there is not starved.
 */

/* Return the other thread of @cid's core, or -1 if there is none to guard. */
static __always_inline s32 smt_guard_sibling(s32 cid)
{
	struct cid_topo __arena *topo;

	if (!smt_guard || !smt_enabled || !cid_valid(cid))
		return -1;
	topo = cid_topo(cid);
	if (topo->ranges.core_nr != 2)
		return -1;
	return cid == topo->ranges.core_base ? cid + 1 : topo->ranges.core_base;
}

/* End @sib's hold, and have it pick again. */
static void smt_guard_release(s32 sib)
{
	struct cid_ctx __arena *sctx = cid_ctx(sib);

	if (READ_ONCE(sctx->sg_held)) {
		WRITE_ONCE(sctx->sg_held, 0);
		scx_bpf_kick_cid(sib, SCX_KICK_IDLE);
	}
}

/*
 * Record what @cid now runs and act on it: a sleeper takes the core from a
 * hog on the sibling, anything else releases a sibling held for this cid.
 */
static void smt_guard_running(s32 cid, const struct task_struct *p,
			      const task_ctx_t *tctx, u64 now)
{
	struct cid_ctx __arena *cctx;
	bool sleeper;
	s32 sib;

	sib = smt_guard_sibling(cid);
	if (sib < 0)
		return;
	cctx = cid_ctx(cid);

	/*
	 * Running anything ends this cid's own hold, whether or not the task
	 * came through ops.dispatch(). A task inserted into the local DSQ at
	 * wakeup does not, and a hold left set would keep the cid out of the
	 * idle mask the next time it went idle, with nothing left to release
	 * it: wakeups would queue on it without ever kicking it.
	 */
	if (READ_ONCE(cctx->sg_held))
		WRITE_ONCE(cctx->sg_held, 0);
	if (READ_ONCE(cctx->sg_pinned) != is_pcpu_task(p))
		WRITE_ONCE(cctx->sg_pinned, is_pcpu_task(p));
	sleeper = task_sleeper(p, tctx, now);
	if (READ_ONCE(cctx->sg_sleeper) != sleeper)
		WRITE_ONCE(cctx->sg_sleeper, sleeper);
	if (!sleeper) {
		if (cctx->sg_hold_since)
			cctx->sg_hold_since = 0;
		smt_guard_release(sib);
		return;
	}
	/*
	 * Kick a sibling that runs a hog, not one that merely is not running
	 * a sleeper: between two tasks, or on its way out of idle, its flag
	 * reads the same, and a kick there only costs it a reschedule. So
	 * does a kick to a hog that can run nowhere else, which is not held,
	 * see smt_guard_hold().
	 */
	if (READ_ONCE(nr_hog_cids) && READ_ONCE(cid_ctx(sib)->curr_hog) &&
	    !READ_ONCE(cid_ctx(sib)->sg_pinned) &&
	    !READ_ONCE(cid_ctx(sib)->sg_held))
		scx_bpf_kick_cid(sib, SCX_KICK_PREEMPT);
}

/* @cid went idle: it runs no sleeper, so its sibling is free. */
static void smt_guard_idle(s32 cid)
{
	s32 sib = smt_guard_sibling(cid);

	if (sib < 0)
		return;
	if (READ_ONCE(cid_ctx(cid)->sg_sleeper))
		WRITE_ONCE(cid_ctx(cid)->sg_sleeper, 0);
	smt_guard_release(sib);
}

/*
 * Release the sibling once its hold has lasted @smt_guard_max_ns. A held cid
 * is idle and has no tick of its own; this cid, running the sleeper, does.
 */
static void smt_guard_tick(s32 cid, u64 now)
{
	s32 sib = smt_guard_sibling(cid);
	struct cid_ctx __arena *sctx;
	u64 since;

	if (sib < 0)
		return;
	sctx = cid_ctx(sib);
	since = READ_ONCE(sctx->sg_hold_since);
	if (READ_ONCE(sctx->sg_held) &&
	    (!since || now - since > smt_guard_max_ns))
		smt_guard_release(sib);
}

/*
 * Return whether ops.dispatch() on @cid should pick nothing and let the cid go
 * idle, because its sibling runs a sleeper and what it would run here is not
 * one.
 *
 * Only @prev and the head of the queue are looked at: a sleeper queued deeper
 * waits for the head, as it would behind the hog. A crowded cid is never held,
 * see credit_crowded(). The guard is for a core with a pipeline stage and a
 * hog on it; a queue of hundreds needs the capacity, and holding such cids
 * during a sleep storm left half the machine's cores idle.
 *
 * A task that can run on this cid only is never held. The cap bounds one
 * hold, not how often holds come: with a sibling that runs a sleeper almost
 * all the time, the cid runs one slice per hold, and a migratable hog is
 * pulled elsewhere by the balancer, but a pinned task has nowhere to go. A
 * nice 19 task pinned beside such a sibling ran 2 ms in 20 s, and one
 * starved past the watchdog.
 *
 * A held cid stays out of the idle mask, see eevdf_update_idle(), or the next
 * wakeup would take it and put a second pipeline stage on the core. It is
 * released by the sibling, see smt_guard_running(), smt_guard_idle() and
 * smt_guard_tick().
 */
static bool smt_guard_hold(s32 cid, struct task_struct *prev, bool has_prev,
			   u64 now)
{
	struct cid_ctx __arena *cctx;
	struct task_struct *head;
	task_ctx_t *tctx;
	s32 sib;
	u64 tid;

	sib = smt_guard_sibling(cid);
	if (sib < 0)
		return false;
	cctx = cid_ctx(cid);
	/*
	 * With no hog running anywhere, a hog at the head here is let run:
	 * it is then counted, and the next pick holds against it. Until then
	 * a load of sleepers pays one read per pick, not a queue peek.
	 */
	if (!READ_ONCE(nr_hog_cids) || !READ_ONCE(cid_ctx(sib)->sg_sleeper) ||
	    credit_crowded(cid))
		goto no_hold;
	if (cctx->sg_hold_since && now - cctx->sg_hold_since > smt_guard_max_ns)
		goto no_hold;
	if (has_prev) {
		tctx = try_lookup_task_ctx(prev);
		if (is_pcpu_task(prev) ||
		    (tctx && task_sleeper(prev, tctx, now)))
			goto no_hold;
	}
	tid = cid_edq_peek_tid_owned(cid);
	if (tid) {
		head = scx_bpf_tid_to_task(tid);
		tctx = head ? try_lookup_task_ctx(head) : NULL;
		if ((head && is_pcpu_task(head)) ||
		    (tctx && task_sleeper(head, tctx, now)))
			goto no_hold;
	}
	if (!cctx->sg_hold_since)
		cctx->sg_hold_since = now;
	WRITE_ONCE(cctx->sg_held, 1);
	return true;
no_hold:
	if (READ_ONCE(cctx->sg_held))
		WRITE_ONCE(cctx->sg_held, 0);
	return false;
}
