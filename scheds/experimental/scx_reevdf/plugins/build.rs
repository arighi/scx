// SPDX-License-Identifier: GPL-2.0-only
//! Example registration belongs with the plugins, not the host policy.

use scx_rustsched_build::{Spec, build_plugin, export_plugin};

pub fn build(host: &Spec<'_>) {
    let spec = Spec {
        package: "scx_reevdf_borrowing",
        manifest: "plugins/borrowing/Cargo.toml",
        crate_name: "scx_reevdf_borrowing",
        catalog: host.catalog,
        kfuncs: host.kfuncs.clone(),
        ksyms: host.ksyms,
        variants: host.variants,
    };
    build_plugin(&spec, "bpf");
    export_plugin(&spec, "bpf", "scx_reevdf_borrowing");
}
