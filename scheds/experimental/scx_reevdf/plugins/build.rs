// SPDX-License-Identifier: GPL-2.0-only
//! Plugin build registration belongs outside the host policy.

use scx_rustsched_build::Spec;

pub fn build(_host: &Spec<'_>) {}
