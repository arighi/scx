# scx_rustsched_build

Build script support for a Rust BPF sched_ext scheduler. The scheduler's
build.rs fills a `Spec`, the BPF crate's manifest and name, the kfunc
catalog, the ksyms it reads and the object variants, and calls `build()`,
or calls `build_default()` when it uses nothing beyond the runtime's.
That builds the crate for the BPF target with the toolchain that builds
the scheduler, or the rustup toolchain `BPF_RUST_TOOLCHAIN` names, adds
to each object's BTF what the Rust toolchain does not emit (the kfunc
prototypes, the ksyms and an `arg:trusted` tag on every task parameter of
a global function), and weakens the symbols a kernel may lack.

The BPF target has no prebuilt `core`, so it is built from `rust-src`,
and `bpf-linker` reads the compiler's LLVM bitcode, so it must be built
against the same LLVM. A distribution builds both against its own. The
build uses unstable features, build-std among them, which it enables
with `RUSTC_BOOTSTRAP=1`, so a stable compiler does. On a host without
the toolchain the objects are left empty and the scheduler refuses to
start, so that workspace builds do not need it.

`build_plugin(&spec, "feature")` builds the same variants with an additional
Cargo feature enabling its BPF entry point. The Spec can point to a standalone
plugin crate which links a host policy library. The host's entry points do
not need feature switches for individual plugins.
The output files are `plugin-feature-variant.bpf.o` in OUT_DIR, alongside
the host's `scheduler-variant.bpf.o` files. Both use the same BTF fixups,
kfunc catalog and toolchain. Track the plugin manifest with
`cargo:rerun-if-changed` in the host build script. A plugin still needs an
explicit host contract; see scx_rustsched_loader's README.

After building a plugin, `export_plugin(&spec, "feature", "name")` exports
`name.bpf.a` beside the executable. This standard `ar` archive contains
`legacy.bpf.o` and `sized.bpf.o`, chosen from the Spec's topology flags;
the loader selects the member matching the host before loading. Archive
headers use fixed timestamps and ownership for reproducible packaging.
The directory follows the active Cargo profile, target and target directory,
including custom profiles. Exports are tracked so a later build restores
deleted files, and obsolete separate `.bpf.o` exports are removed. Without
BPF tooling, empty placeholders stay in OUT_DIR and stale public artifacts
are removed. A partially built archive is never exported.
