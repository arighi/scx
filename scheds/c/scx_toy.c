/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <pthread.h>
#include <bpf/bpf.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <scx/common.h>
#include "scx_toy.bpf.skel.h"
#include "scx_toy.h"

const char help_fmt[] =
"A toy sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s\n"
"\n"
"  -h            Display this help and exit\n";

static volatile int exit_req;

pthread_t stats_printer;

/*
 * Descriptors used to communicate enqueue and dispatch event with the BPF
 * program.
 */
static int enqueued_fd, dispatched_fd;

static struct scx_toy *skel;

static void sigint_handler(int dummy)
{
	exit_req = 1;
}

/* Thread that periodically prints enqueue statistics */
static void *run_stats_printer(void *arg)
{
	while (!exit_req) {
		__u64 nr_failed_enqueues, nr_kernel_enqueues, nr_user_enqueues, total;

		nr_failed_enqueues = skel->bss->nr_failed_enqueues;
		nr_kernel_enqueues = skel->bss->nr_kernel_enqueues;
		nr_user_enqueues = skel->bss->nr_user_enqueues;
		total = nr_failed_enqueues + nr_kernel_enqueues + nr_user_enqueues;

		printf("\e[1;1H\e[2J");
		printf("o-----------------------o\n");
		printf("| BPF SCHED ENQUEUES    |\n");
		printf("|-----------------------|\n");
		printf("|  kern:     %10llu |\n", nr_kernel_enqueues);
		printf("|  user:     %10llu |\n", nr_user_enqueues);
		printf("|  failed:   %10llu |\n", nr_failed_enqueues);
		printf("|  -------------------- |\n");
		printf("|  total:    %10llu |\n", total);
		printf("o-----------------------o\n\n");
		sleep(1);
	}

	return NULL;
}

/* Send a dispatch event to the BPF program */
static int dispatch_task(s32 pid)
{
	int err;

	err = bpf_map_update_elem(dispatched_fd, NULL, &pid, 0);
	if (err) {
		fprintf(stderr, "Failed to dispatch task %d\n", pid);
		exit_req = 1;
	}

	return err;
}

/* Receive all the enqueue events from the BPF program */
static void drain_enqueued_map(void)
{
	struct scx_toy_enqueued_task task;

	while (!bpf_map_lookup_and_delete_elem(enqueued_fd, NULL, &task))
		dispatch_task(task.pid);
}

/*
 * Scheduler main loop: get enqueue events from the BPF program, process them
 * (no-op) and send dispatch events to the BPF program.
 */
static void sched_main_loop(void)
{
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		drain_enqueued_map();
		sched_yield();
	}
	drain_enqueued_map();
}

int main(int argc, char **argv)
{
	struct bpf_link *link;
	u32 opt;
	__u64 ecode;
	int err;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	/*
	 * It's not always safe to allocate in a user space scheduler, as an
	 * enqueued task could hold a lock that we require in order to be able
	 * to allocate.
	 */
	err = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (err) {
		fprintf(stderr, "Failed to prefault and lock address space: %s\n",
			strerror(err));
		return err;
	}

	skel = SCX_OPS_OPEN(toy_ops, scx_toy);

	skel->rodata->usersched_pid = getpid();
	assert(skel->rodata->usersched_pid > 0);

	SCX_OPS_LOAD(skel, toy_ops, scx_toy, uei);

	/* Initialize file descriptors to communicate with the BPF program */
	enqueued_fd = bpf_map__fd(skel->maps.enqueued);
	dispatched_fd = bpf_map__fd(skel->maps.dispatched);
	assert(enqueued_fd > 0);
	assert(dispatched_fd > 0);

	link = SCX_OPS_ATTACH(skel, toy_ops, scx_toy);

	/* Start the thread to periodically print enqueue statistics */
	err = pthread_create(&stats_printer, NULL, run_stats_printer, NULL);
	if (err) {
		fprintf(stderr, "Failed to spawn stats thread: %s\n", strerror(err));
		goto destroy_skel;
	}

	/* Call the scheduler main loop */
	sched_main_loop();

destroy_skel:
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_toy__destroy(skel);

	return ecode;
}
