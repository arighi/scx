/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_simple.bpf.skel.h"
#include "scx_simple.h"

const char help_fmt[] =
"A simple sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-p]\n"
"\n"
"  -p            Switch only tasks on SCHED_EXT policy intead of all\n"
"  -h            Display this help and exit\n";

static volatile int exit_req;

static void sigint_handler(int simple)
{
	exit_req = 1;
}

static void read_stats(struct scx_simple *skel, __u64 *stats, int nr_cpus)
{
	__u64 cnts[nr_cpus][nr_cpus] = {};
	__u32 cpu;

	for (cpu = 0; cpu < nr_cpus; cpu++) {
		int ret, i;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &cpu, cnts[cpu]);
		if (ret < 0)
			continue;

		for (i = 0; i < nr_cpus; i++)
			stats[cpu] += cnts[cpu][i];
	}
}

int main(int argc, char **argv)
{
	int nr_cpus = libbpf_num_possible_cpus();
	struct scx_simple *skel;
	struct bpf_link *link;
	__u32 opt;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_simple__open();
	SCX_BUG_ON(!skel, "Failed to open skel");

	while ((opt = getopt(argc, argv, "ph")) != -1) {
		switch (opt) {
		case 'p':
			skel->rodata->switch_partial = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_BUG_ON(scx_simple__load(skel), "Failed to load skel");

	link = bpf_map__attach_struct_ops(skel->maps.simple_ops);
	SCX_BUG_ON(!link, "Failed to attach struct_ops");

	while (!exit_req && !uei_exited(&skel->bss->uei)) {
		__u64 stats[nr_cpus] = {};
		int i;

		read_stats(skel, stats, nr_cpus);
		for (i = 0; i < nr_cpus; i++)
			printf("cpu%d=%llu\n", i, stats[i]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	uei_print(&skel->bss->uei);
	scx_simple__destroy(skel);
	return 0;
}
