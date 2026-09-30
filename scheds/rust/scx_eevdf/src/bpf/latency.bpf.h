/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 *
 * Virtual-time borrowing for latency-sensitive wakees: placement credit
 * and asymmetric-capacity packing.
 */
#pragma once

#include "eevdf.bpf.h"

static void credit_tick(s32 cid, struct task_struct *p, u64 now);
static void cid_set_hog(s32 cid, bool hog);
static __always_inline s32 smt_guard_sibling(s32 cid);
static void smt_guard_running(s32 cid, const struct task_struct *p,
			      const task_ctx_t *tctx, u64 now);
static void smt_guard_idle(s32 cid);
static bool smt_guard_hold(s32 cid, struct task_struct *prev, bool has_prev,
			   u64 now);
static s64 task_place_offset(s32 cid, pack_t *pk, const struct task_struct *p,
			     task_ctx_t *tctx, u64 now, u64 tnow);
static void credit_charge(pack_t *pk, task_ctx_t *tctx, u64 delta);
static void credit_stats_fold(s32 cid);
static s32 credit_pack_cid(const struct task_struct *p, task_ctx_t *tctx,
			   s32 target, u64 now);
