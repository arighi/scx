/* Copyright (c) Andrea Righi <andrea.righi@canonical.com> */
/*
 * scx_rustland: simple user-space scheduler written in Rust
 *
 * The main goal of this scheduler is be an "easy to read" template that can be
 * used to quickly test more complex scheduling policies. For this reason this
 * scheduler is mostly focused on simplicity and code readability.
 *
 * The scheduler is made of a BPF component (dispatcher) that implements the
 * low level sched-ext functionalities and a user-space counterpart
 * (scheduler), written in Rust, that implements the actual scheduling policy.
 *
 * The BPF dispatcher collects total cputime and weight from the tasks that
 * need to run, then it sends all details to the user-space scheduler that
 * decides the best order of execution of the tasks (based on the collected
 * metrics).
 *
 * The user-space scheduler then returns to the BPF component the list of tasks
 * to be dispatched in the proper order.
 *
 * Messages between the BPF component and the user-space scheduler are passed
 * using two BPF_MAP_TYPE_QUEUE maps: @queued for the messages sent by the BPF
 * dispatcher to the user-space scheduler and @dispatched for the messages sent
 * by the user-space scheduler to the BPF dispatcher.
 *
 * The BPF dispatcher is completely agnostic of the particular scheduling
 * policy implemented in user-space. For this reason developers that are
 * willing to use this scheduler to experiment scheduling policies should be
 * able to simply modify the Rust component, without having to deal with any
 * internal kernel / BPF details.
 *
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 */
#include <scx/common.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

/*
 * Maximum amount of CPUs supported by this scheduler (this defines the size of
 * cpu_map that is used to store the idle state and CPU ownership).
 */
#define MAX_CPUS 1024

/* !0 for veristat, set during init */
const volatile s32 num_possible_cpus = 8;

/*
 * Exit info (passed to the user-space counterpart).
 */
int exit_kind = SCX_EXIT_NONE;
char exit_msg[SCX_EXIT_MSG_LEN];

/*
 * Scheduler attributes and statistics.
 */
u32 usersched_pid; /* User-space scheduler PID */
const volatile bool switch_partial; /* Switch all tasks or SCHED_EXT tasks */
const volatile u64 slice_ns = SCX_SLICE_DFL; /* Base time slice duration */

/*
 * Effective time slice: allow the scheduler to override the default time slice
 * (slice_ns) if this one is set.
 */
volatile u64 effective_slice_ns;

/*
 * Number of tasks that are queued for scheduling.
 *
 * This number is incremented by the BPF component when a task is queued to the
 * user-space scheduler and it must be decremented by the user-space scheduler
 * when a task is consumed.
 */
volatile u64 nr_queued;

/*
 * Number of tasks that are waiting for scheduling.
 *
 * This number must be updated by the user-space scheduler to keep track if
 * there is still some scheduling work to do.
 */
volatile u64 nr_scheduled;

/* Dispatch statistics */
volatile u64 nr_user_dispatches, nr_kernel_dispatches;

/* Failure statistics */
volatile u64 nr_failed_dispatches, nr_sched_congested;

 /* Report additional debugging information */
const volatile bool debug;

/* Allow to use bpf_printk() only when @debug is set */
#define dbg_msg(_fmt, ...) do {						\
	if (debug)							\
		bpf_printk(_fmt " nr_queued=%lu nr_scheduled=%llu",	\
		##__VA_ARGS__, nr_queued, nr_scheduled);		\
} while(0)

/*
 * Maximum amount of tasks queued between kernel and user-space at a certain
 * time.
 *
 * The @queued and @dispatched lists are used in a producer/consumer fashion
 * between the BPF part and the user-space part.
 */
#define MAX_ENQUEUED_TASKS 1024

/*
 * The map containing tasks that are queued to user space from the kernel.
 *
 * This map is drained by the user space scheduler.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct queued_task_ctx);
	__uint(max_entries, MAX_ENQUEUED_TASKS);
} queued SEC(".maps");

/*
 * The map containing pids that are dispatched from user space to the kernel.
 *
 * Drained by the kernel in .dispatch().
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__type(value, struct dispatched_task_ctx);
	__uint(max_entries, MAX_ENQUEUED_TASKS);
} dispatched SEC(".maps");

/*
 * Per-task local storage.
 *
 * This contain all the per-task information used internally by the BPF code.
 */
struct task_ctx {
	/*
	 * Set this flag to dispatch directly from .enqueueu() to the local DSQ
	 * of the cpu where the task is going to run (bypassing the scheduler).
	 *
	 * This can be used for example when the selected cpu is idle; in this
	 * case we can simply dispatch the task on the same target cpu and
	 * avoid unnecessary calls to the user-space scheduler.
	 */
	bool force_local;
};

/* Map that contains task-local storage. */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Heartbeat timer used to periodically trigger the check to run the user-space
 * scheduler.
 *
 * Without this timer we may starve the scheduler if the system is completely
 * idle and hit the watchdog that would auto-kill this scheduler.
 */
struct usersched_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct usersched_timer);
} usersched_timer SEC(".maps");

/*
 * Map of allocated CPUs.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} cpu_map SEC(".maps");

/*
 * Assign a task to a CPU (used in .running() and .stopping()).
 *
 * If pid == 0 the CPU will be considered idle.
 */
static void set_cpu_owner(u32 cpu, u32 pid)
{
	u32 *owner;

	owner = bpf_map_lookup_elem(&cpu_map, &cpu);
	if (!owner) {
		scx_bpf_error("Failed to look up cpu_map for cpu %u", cpu);
		return;
	}
	*owner = pid;
}

/*
 * Get the pid of the task that is currently running on @cpu.
 *
 * Return 0 if the CPU is idle.
 */
static u32 get_cpu_owner(u32 cpu)
{
	u32 *owner;

	owner = bpf_map_lookup_elem(&cpu_map, &cpu);
	if (!owner) {
		scx_bpf_error("Failed to look up cpu_map for cpu %u", cpu);
		return 0;
	}
	return *owner;
}

/*
 * Return true if the target task @p is the user-space scheduler.
 */
static inline bool is_usersched_task(const struct task_struct *p)
{
	return p->pid == usersched_pid;
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
}

/*
 * Flag used to wake-up the user-space scheduler.
 */
static volatile u32 usersched_needed;

/*
 * Set user-space scheduler wake-up flag (equivalent to an atomic release
 * operation).
 */
static void set_usersched_needed(void)
{
	__sync_fetch_and_or(&usersched_needed, 1);
}

/*
 * Check and clear user-space scheduler wake-up flag (equivalent to an atomic
 * acquire operation).
 */
static bool test_and_clear_usersched_needed(void)
{
	return __sync_fetch_and_and(&usersched_needed, 0) == 1;
}

/*
 * Return true if there's any pending activity to do for the scheduler, false
 * otherwise.
 *
 * NOTE: nr_queued is incremented by the BPF component, more exactly in
 * enqueue(), when a task is sent to the user-space scheduler, then the
 * scheduler drains the queued tasks (updating nr_queued) and adds them to its
 * internal data structures / state; at this point tasks become "scheduled" and
 * the user-space scheduler will take care of updating nr_scheduled
 * accordingly; lastly tasks will be dispatched and the user-space scheduler
 * will update nr_scheduled again.
 *
 * Checking both counters allows to determine if there is still some pending
 * work to do for the scheduler: new tasks have been queued since last check,
 * or there are still tasks "queued" or "scheduled" since the previous
 * user-space scheduler run. If the counters are both zero it is pointless to
 * wake-up the scheduler (even if a CPU becomes idle), because there is nothing
 * to do.
 *
 * Also keep in mind that we don't need any protection here since this code
 * doesn't run concurrently with the user-space scheduler (that is single
 * threaded), therefore this check is also safe from a concurrency perspective.
 */
static bool is_usersched_needed(void)
{
	return nr_queued || nr_scheduled;
}

/*
 * Dispatch a task on its local per-CPU FIFO.
 */
static void dispatch_local(struct task_struct *p, u64 enq_flags)
{
	dbg_msg("dispatch: pid=%d (%s) cpu=local", p->pid, p->comm);
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL, slice_ns, enq_flags | SCX_ENQ_LOCAL);
}

/*
 * Get a valid CPU to dispatch a task.
 *
 * First we check if the designated CPU is available, otherwise we check if the
 * previously used CPU is still available (trying to reduce migrations), if
 * both are busy return a random CPU available according to the bitmask, or
 * -ENOENT if none of the allowed CPUs are available.
 */
static s32 get_task_cpu(struct task_struct *p, s32 cpu)
{
	if (cpu < 0)
		return cpu;
	/*
	 * Check if the designated CPU can be used to dispatch the task.
	 */
	if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return cpu;

	/*
	 * The designated CPU is unavailable, check if the previously used CPU
	 * is available.
	 */
	cpu = scx_bpf_task_cpu(p);
	if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return cpu;

	/*
	 * Otherwise get a random CPU available according to the cpumask.
	 * Return -ENOENT if no CPU is available.
	 */
	cpu = bpf_cpumask_any_distribute(p->cpus_ptr);
	return cpu < num_possible_cpus ? cpu : -ENOENT;
}

/*
 * Dispatch a task on a target CPU.
 *
 * If it's not possible to dispatch on the selected CPU, try to re-use the
 * previously used one, if that one is also not usable dispatch to the global
 * DSQ.
 */
static void dispatch_task(struct task_struct *p, s32 cpu, u64 enq_flags)
{
	u64 slice = __sync_fetch_and_add(&effective_slice_ns, 0) ? : slice_ns;

	cpu = get_task_cpu(p, cpu);
	if (cpu < 0) {
		/*
		 * We couldn't find any available CPU that can be used
		 * immediately to dispatch the task.
		 *
		 * This is not necessarily a problem, using the global DSQ will
		 * give a small performance penalty to the task (because it
		 * needs to wait for the local DSQ to be drained). So for now
		 * simply report the event as a "dispatch failure" and keep
		 * going.
		 */
		dbg_msg("dispatch: pid=%d (%s) cpu=any", p->pid, p->comm);
		__sync_fetch_and_add(&nr_failed_dispatches, 1);
		scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, slice, enq_flags);
		return;
	}
	dbg_msg("dispatch: pid=%d (%s) cpu=%ld", p->pid, p->comm, cpu);
	scx_bpf_dispatch(p, SCX_DSQ_LOCAL_ON | cpu, slice,
			 enq_flags | SCX_ENQ_LOCAL);
}

/*
 * Select the target CPU where a task can be directly dispatched to from
 * .enqueue().
 *
 * The idea here is to try to find an idle CPU in the system, and preferably
 * maintain the task on the same CPU.
 *
 * If the CPU where the task was running is still idle, then the task can be
 * dispatched immediately on the same CPU from .enqueue(), without having to
 * call the scheduler.
 *
 * Decision made in this function is not final. The user-space scheduler may
 * decide to move the task to a different CPU later, if needed.
 */
s32 BPF_STRUCT_OPS(rustland_select_cpu, struct task_struct *p, s32 prev_cpu,
		   u64 wake_flags)
{
	struct task_ctx *tctx;

	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("Failed to look up task-local storage for %s", p->comm);
		return -ESRCH;
	}
	/*
	 * Always try to keep the tasks on the same CPU (unless the user-space
	 * scheduler decides otherwise).
	 *
	 * Check if the previously used CPU is idle, in this case we can
	 * dispatch directly from .enqueue(), bypassing the user-space
	 * scheduler.
	 */
	tctx->force_local = get_cpu_owner(prev_cpu) == 0;

	return prev_cpu;
}

/*
 * Return true if the selected CPU for the task is immediately available
 * (user-space scheduler not required), false otherwise (user-space scheduler
 * required).
 *
 * To determine if the CPU is available we rely on tctx->force_idle (set in
 * .select_cpu()), since this function may be called on a different CPU (so we
 * cannot check the current CPU directly).
 */
static bool is_task_cpu_available(struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;

	/*
	 * Always dispatch per-CPU kthreads on the same CPU, bypassing the
	 * user-space scheduler (in this way we can to prioritize critical
	 * kernel threads that may potentially slow down the entire system if
	 * they are blocked for too long).
	 */
	if (is_kthread(p) && p->nr_cpus_allowed == 1)
		return true;

	/*
	 * Do not bypass the user-space scheduler if there are pending
	 * activity, otherwise, we may risk disrupting the scheduler's
	 * decisions and negatively affecting the overall system performance.
	 */
	if (is_usersched_needed())
		return false;

	/*
	 * For regular tasks always rely on force_local to determine if we can
	 * bypass the scheduler.
	 */
	tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
	if (!tctx) {
		scx_bpf_error("Failed to lookup task ctx for %s", p->comm);
		return false;
	}
	return tctx->force_local;
}

/*
 * Fill @task with all the information that need to be sent to the user-space
 * scheduler.
 */
static void get_task_info(struct queued_task_ctx *task,
			  const struct task_struct *p, bool exiting)
{
	task->pid = p->pid;
	/*
	 * Use a negative CPU number to notify that the task is exiting, so
	 * that we can free up its resources in the user-space scheduler.
	 */
	if (exiting) {
		task->cpu = -1;
		return;
	}
	task->sum_exec_runtime = p->se.sum_exec_runtime;
	task->weight = p->scx.weight;
	task->cpu = scx_bpf_task_cpu(p);
}

/*
 * User-space scheduler is congested: log that and increment congested counter.
 */
static void sched_congested(struct task_struct *p)
{
	dbg_msg("congested: pid=%d (%s)", p->pid, p->comm);
	__sync_fetch_and_add(&nr_sched_congested, 1);
}

/*
 * Task @p becomes ready to run. We can dispatch the task directly here if the
 * user-space scheduler is not required, or enqueue it to be processed by the
 * scheduler.
 */
void BPF_STRUCT_OPS(rustland_enqueue, struct task_struct *p, u64 enq_flags)
{
        struct queued_task_ctx task;

	/*
	 * Scheduler is dispatched directly in .dispatch() when needed, so
	 * we can skip it here.
	 */
	if (is_usersched_task(p))
		return;

	/*
	 * Directly dispatch the task to the local DSQ if the selected task's
	 * CPU is available (no scheduling decision required).
	 */
	if (is_task_cpu_available(p, enq_flags)) {
		dispatch_local(p, enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		return;
	}

	/*
	 * Other tasks can be added to the @queued list and they will be
	 * processed by the user-space scheduler.
	 *
	 * If @queued list is full (user-space scheduler is congested) tasks
	 * will be dispatched directly from the kernel (re-using their
	 * previously used CPU in this case).
	 */
	get_task_info(&task, p, false);
	dbg_msg("enqueue: pid=%d (%s)", p->pid, p->comm);
	if (bpf_map_push_elem(&queued, &task, 0)) {
		sched_congested(p);
		dispatch_task(p, -1, enq_flags);
		__sync_fetch_and_add(&nr_kernel_dispatches, 1);
		return;
	}
	__sync_fetch_and_add(&nr_queued, 1);
}

/*
 * Dispatch the user-space scheduler.
 */
static void dispatch_user_scheduler(s32 cpu)
{
	struct task_struct *p;

	if (!test_and_clear_usersched_needed())
		return;

	p = bpf_task_from_pid(usersched_pid);
	if (!p) {
		scx_bpf_error("Failed to find usersched task %d", usersched_pid);
		return;
	}
	dispatch_task(p, cpu, SCX_ENQ_PREEMPT);
	__sync_fetch_and_add(&nr_kernel_dispatches, 1);
	bpf_task_release(p);
}

/*
 * Dispatch tasks that are ready to run.
 *
 * This function is called when a CPU's local DSQ is empty and ready to accept
 * new dispatched tasks.
 *
 * We may dispatch tasks also on other CPUs from here, if the scheduler decided
 * so (usually if other CPUs are idle we may want to send more tasks to their
 * local DSQ to optimize the scheduling pipeline).
 */
void BPF_STRUCT_OPS(rustland_dispatch, s32 cpu, struct task_struct *prev)
{
	/*
	 * Check if the user-space scheduler needs to run, and in that case try
	 * to dispatch it on the current CPU.
	 */
	dispatch_user_scheduler(cpu);

	/*
	 * Consume all tasks from the @dispatched list and immediately try to
	 * dispatch them on their target CPU selected by the user-space
	 * scheduler (at this point the proper ordering has been already
	 * determined by the scheduler).
	 */
	bpf_repeat(MAX_ENQUEUED_TASKS) {
		struct task_struct *p;
		struct dispatched_task_ctx task;

		/*
		 * Pop first task from the dispatched queue, stop if dispatch
		 * queue is empty.
		 */
		if (bpf_map_pop_elem(&dispatched, &task))
			break;

		/* Ignore entry if the task doesn't exist anymore */
		p = bpf_task_from_pid(task.pid);
		if (!p)
			continue;
		/*
		 * Check whether the scheduler assigned a different CPU to the
		 * task and migrate (if possible).
		 */
		dbg_msg("usersched: pid=%d cpu=%d payload=%llu",
			task.pid, task.cpu, task.payload);
		dispatch_task(p, task.cpu, 0);
		__sync_fetch_and_add(&nr_user_dispatches, 1);
		bpf_task_release(p);
	}
}

/*
 * Task @p starts on its selected CPU (update CPU ownership map).
 */
void BPF_STRUCT_OPS(rustland_running, struct task_struct *p)
{
	s32 cpu = scx_bpf_task_cpu(p);

	dbg_msg("start: pid=%d (%s) cpu=%ld", p->pid, p->comm, cpu);
	/*
	 * Mark the CPU as busy by setting the pid as owner (ignoring the
	 * user-space scheduler).
	 */
	if (!is_usersched_task(p))
		set_cpu_owner(cpu, p->pid);
}

/*
 * Task @p stops running on its associated CPU (update CPU ownership map).
 */
void BPF_STRUCT_OPS(rustland_stopping, struct task_struct *p, bool runnable)
{
	s32 cpu = scx_bpf_task_cpu(p);

	dbg_msg("stop: pid=%d (%s) cpu=%ld", p->pid, p->comm, cpu);
	/*
	 * Mark the CPU as idle by setting the owner to 0.
	 */
	if (!is_usersched_task(p))
		set_cpu_owner(scx_bpf_task_cpu(p), 0);
}

/*
 * A CPU is about to change its idle state.
 *
 * NOTE: implementing an update_idle() callback automatically disables the
 * built-in idle tracking. This is fine because we want to rely on the internal
 * CPU ownership map (get_cpu_owner() / set_cpu_owner()) to determine if a CPU
 * is available or not.
 *
 * This information can easily be shared with the user-space scheduler via
 * cpu_map.
 */
void BPF_STRUCT_OPS(rustland_update_idle, s32 cpu, bool idle)
{
	/*
	 * Don't do anything if we exit from and idle state, a CPU owner will
	 * be assigned in .running().
	 */
	if (!idle)
		return;
	/*
	 * A CPU is now available, notify the user-space scheduler that tasks
	 * can be dispatched.
	 */
	if (is_usersched_needed()) {
		/*
		 * Kick the CPU to make it immediately ready to accept
		 * dispatched tasks.
		 */
		scx_bpf_kick_cpu(cpu, 0);
		set_usersched_needed();
	}
}

/*
 * A new task @p is being created.
 *
 * Allocate and initialize all the internal structures for the task (this
 * function is allowed to block, so it can be used to preallocate memory).
 */
s32 BPF_STRUCT_OPS(rustland_prep_enable, struct task_struct *p,
		   struct scx_enable_args *args)
{
	/* Allocate task's local storage */
	if (bpf_task_storage_get(&task_ctx_stor, p, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE))
		return 0;
	else
		return -ENOMEM;
}

/*
 * Task @p is exiting.
 *
 * Notify the user-space scheduler that we can free up all the allocated
 * resources associated to this task.
 */
void BPF_STRUCT_OPS(rustland_disable, struct task_struct *p)
{
        struct queued_task_ctx task = {};

	dbg_msg("exit: pid=%d (%s)", p->pid, p->comm);
	get_task_info(&task, p, true);
	if (bpf_map_push_elem(&queued, &task, 0)) {
		/*
		 * We may have a memory leak in the scheduler at this point,
		 * because we failed to notify it about this exiting task and
		 * some resources may remain allocated.
		 *
		 * Do not worry too much about this condition for now, since
		 * it should be pretty rare (and it happens only when the
		 * scheduler is already congested, so it is probably a good
		 * thing to avoid introducing extra overhead to free up
		 * resources).
		 */
		sched_congested(p);
		return;
	}
	__sync_fetch_and_add(&nr_queued, 1);
}

/*
 * Heartbeat scheduler timer callback.
 *
 * If the system is completely idle the sched-ext watchdog may incorrectly
 * detect that as a stall and automatically disable the scheduler. So, use this
 * timer to periodically wake-up the scheduler and avoid long inactivity.
 *
 * This can also help to prevent real "stalling" conditions in the scheduler.
 */
static int usersched_timer_fn(void *map, int *key, struct bpf_timer *timer)
{
	int err = 0;

	/* Kick the scheduler */
	set_usersched_needed();

	/* Re-arm the timer */
	err = bpf_timer_start(timer, NSEC_PER_SEC, 0);
	if (err)
		scx_bpf_error("Failed to arm stats timer");

	return 0;
}

/*
 * Initialize the heartbeat scheduler timer.
 */
static int usersched_timer_init(void)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int err;

	timer = bpf_map_lookup_elem(&usersched_timer, &key);
	if (!timer) {
		scx_bpf_error("Failed to lookup scheduler timer");
		return -ESRCH;
	}
	bpf_timer_init(timer, &usersched_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, usersched_timer_fn);
	err = bpf_timer_start(timer, NSEC_PER_SEC, 0);
	if (err)
		scx_bpf_error("Failed to arm scheduler timer");

	return err;
}

/*
 * Initialize the scheduling class.
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(rustland_init)
{
	int err;

	err = usersched_timer_init();
	if (err)
		return err;
        if (!switch_partial)
		scx_bpf_switch_all();
	return 0;
}

/*
 * Unregister the scheduling class.
 */
void BPF_STRUCT_OPS(rustland_exit, struct scx_exit_info *ei)
{
	bpf_probe_read_kernel_str(exit_msg, sizeof(exit_msg), ei->msg);
	exit_kind = ei->kind;
}

/*
 * Scheduling class declaration.
 */
SEC(".struct_ops.link")
struct sched_ext_ops rustland = {
	.select_cpu		= (void *)rustland_select_cpu,
	.enqueue		= (void *)rustland_enqueue,
	.dispatch		= (void *)rustland_dispatch,
	.running		= (void *)rustland_running,
	.stopping		= (void *)rustland_stopping,
	.update_idle		= (void *)rustland_update_idle,
	.prep_enable		= (void *)rustland_prep_enable,
	.disable		= (void *)rustland_disable,
	.init			= (void *)rustland_init,
	.exit			= (void *)rustland_exit,
	.flags			= SCX_OPS_ENQ_LAST,
	.timeout_ms		= 5000,
	.name			= "rustland",
};
