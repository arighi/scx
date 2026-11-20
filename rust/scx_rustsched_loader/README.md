# scx_rustsched_loader

Loading and running a Rust BPF sched_ext scheduler from user space: the
configuration table's kernel entries resolved from the running kernel's BTF,
the struct_ops map the kernel can take, the map sizes set before the load,
the attach, the exit record, the arena statistics, the per-callback profiler
and the sampler of the per-CID queues, which reads them from the arena
through scx_rustsched's `edq.rs`. `tiers` reads the CPU capacities and the
kernel's asymmetric packing priorities and hands them to the BPF program per
CPU.

`main!` is a scheduler's whole `main()`: it parses the command line,
loads and attaches the scheduler, and runs it until Ctrl-C, the end of
`--duration`, or the kernel ejects it. Every scheduler gets `--verify`,
`--exit-dump-len`, `--timeout-ms` (the watchdog timeout, in place of the
scheduler's own), `--version` and libbpf's options from it. What a
scheduler adds is its options and what it implements of `Scheduler`.

## Options and tunables

`Opts` is a `clap::Args` structure, written as in any other scheduler,
and each of its fields sets the tunable of the same name. The BPF side
declares those from the same structure, with `scx_rustsched::opts!()`:

```rust
#[derive(clap::Args)]
struct Opts {
    /// Scheduling slice duration in microseconds.
    #[clap(short = 's', long, default_value = "5000")]
    slice_us: u64,
}

impl scx_rustsched_loader::Scheduler for Opts {}

scx_rustsched_loader::main!("description", Opts);
```

`--slice-us 1000` then sets `SLICE_NS`, to 1000000: an option in
microseconds or milliseconds, named `_us` or `_ms`, sets the tunable in
nanoseconds. The default the scheduler starts with is the one in `Opts`.

An option that is not the tunable's value as it stands has a name of its
own, and `Scheduler::settings()` sets the tunable from it, which the BPF
side declares with `scx_rustsched::params!`. A list of CPUs that the
scheduler takes as a mask, an array tunable, is one:

```rust
#[derive(clap::Args)]
struct Opts {
    /// CPUs to run tasks on first, as a list.
    #[clap(short = 'm', long, default_value = "")]
    primary_domain: String,
}

impl Scheduler for Opts {
    fn settings(&self, params: &mut Params) -> Result<()> {
        params.set("primary_cpus", &mask_of(&self.primary_domain)?)
    }
}
```

`Params::set()` takes values of the tunable's own type: one for an integer
or a bool, and for an array at most as many as it has elements, the rest
of which become zero. `settings()` sees only what the names leave over:
every other option is set before it runs.

An option that only the loader uses, such as one that says how to read
the CPU capacities, is marked `#[opts(no_bpf)]`, on a structure that also
derives `scx_rustsched_loader::Opts`. `opts!()` then declares no tunable for
it:

```rust
#[derive(clap::Args, scx_rustsched_loader::Opts)]
struct Opts {
    /// Treat every CPU as having the same capacity.
    #[opts(no_bpf)]
    #[clap(long)]
    uniform_capacity: bool,
}
```

`settings()` also chooses the ops flags the scheduler is loaded with,
starting from the ones `#[scheduler(flags = ...)]` declares. A flag the
kernel may lack is added there, from `compat`, which reads 0 for it on
such a kernel, and the BPF side asks `scx_rustsched::ops::enabled()` what it
got:

```rust
fn settings(&self, params: &mut Params) -> Result<()> {
    if !self.no_proxy_exec {
        params.add_flags(*compat::SCX_OPS_ENQ_BLOCKED);
    }
    Ok(())
}
```

Every tunable has to be set, by an option of its name or by
`settings()`. A scheduler with one that nothing sets does not start,
which is what a misspelled option comes to.

## Statistics

A scheduler has no statistics unless it provides them. `--stats`,
`--monitor` and `--help-stats` are every scheduler's options, and they
work for the one whose `Scheduler::stats()` returns its two callbacks:

```rust
impl Scheduler for Opts {
    fn stats(&self) -> Option<Stats> {
        Some(Stats::new(
            server_data,                           // describes Metrics
            |object| metrics(object),              // reads one sample
            |metrics, interval| show(&metrics),    // prints one sample
        ))
    }
}
```

The first callback reads the scheduler's metrics, a structure of its own
that scx_stats can serve, from the running object when a client asks. The
second prints what a client received, with `--stats` beside the scheduler
and with `--monitor` from another process.

`Stats::idle()` adds a third, called about ten times a second while
nobody asks, for what is kept only for a client, such as the callback
profiler's accounting, to be dropped.

`OpsProfiler`, `QueueSampler`, `arena_usage()` and `ArenaView` are there
for a scheduler's metrics to use.

## Startup and exit

What a scheduler prints when it starts and stops is its own. The loader
calls `Scheduler::attached()` once the scheduler is attached and its init
has run, and `Scheduler::stopped()` when it was unregistered without an
error. Each prints one line by default. `Attached` has a method for each
thing the loader knows about the run, such as `nr_cpus()`, `tick_ns()`,
`ops_flags()`, `tiers()` and `arena_usage()`, and `object()` to read what
the scheduler's init computed:

```rust
impl Scheduler for Opts {
    fn attached(&self, attached: &Attached<'_>) {
        info!("{} on {} CPUs, flags {:#x}", attached.name(),
              attached.nr_cpus().unwrap_or(0), attached.ops_flags());
    }
}
```

An error exit is reported by the loader, with the kernel's debug dump.
Every line goes through the logger the loader sets up, at info level, with
the time.

## The runtime's options

`Scheduler::runtime()` returns what the scheduler asks of the runtime, a
mask of `config::runtime`'s bits, and `Scheduler::capacity()` how the
CPUs' capacities and packing ranks are read.

## Load-time plugins

`--plugin PATH` loads a plugin archive (`.bpf.a`) or a standalone BPF ELF
object (`.bpf.o`) that replaces callbacks exported by the scheduler.
Repeat the option for disjoint callback sets. Conflicts are
errors; command-line order does not give a plugin precedence. `--verify`
loads the providers and populates the composed table without registering a
scheduler. Initialization and scheduling behavior require an attached test.

An archive is a standard `ar` file containing `legacy.bpf.o` and
`sized.bpf.o`. The loader selects the same topology ABI as the host, then
opens only that member with libbpf. Missing variants, duplicate members,
unexpected member names and thin archives are rejected. Selection depends
on the contents rather than the filename, and adds no runtime dispatch.

A scheduler opts in by returning a manifest from `plugin_contract()`:

```rust,ignore
fn plugin_contract(&self) -> Option<&'static str> {
    Some(include_str!("../plugin.contract"))
}
```

The manifest describes the host identity, its semantic contract version,
the runtime ABI, and explicit callback and map exports:

```text
format=1
host=my_scheduler
contract=1
runtime=1
callback=enqueue
map=arena
map=task_refs
map=.rodata.config
map=.rodata.param.*
```

The plugin embeds an import manifest of the same format, with the callbacks
and maps it needs. Its imports must be subsets of the host's exports. The
runtime ABI must equal `scx_rustsched_abi::PLUGIN_ABI`. A host contract is
scheduler-specific: bump it when arena layouts or callback semantics change.
The verifier and layout checks do not establish semantic compatibility.

`#[scx_rustsched::plugin(manifest = "path")]` generates standalone callback
entries from an `impl` block, with the same typed arguments and returns as
`#[scheduler]`. The path is relative to the BPF crate's Cargo.toml. Only
callbacks listed in the manifest become entries; ordinary code is inlined
or called as BPF subprograms. Use `scx_rustsched_build::build_plugin()` for
the existing kfunc/BTF fixups and object variants. The host build script
must track manifest changes with `cargo:rerun-if-changed`.

The initial implementation supports CID-form callbacks. It protects the
framework lifecycle callbacks: init, exit, init_task, exit_task, enable,
dequeue, dispatch and update_idle. Replacing a callback replaces all of it,
including any scheduler accounting it performs. Plugins cannot call through
to the original implementation or change scheduler identity and ops flags.

Imported maps reuse the host's FDs before plugin program loading. Map types,
flags, dimensions, map_extra and BTF layouts must match; runtime-sized entry
counts and the exit dump buffer are adjusted to the host. Matching sizes
alone are insufficient. The `.rodata.param.*` pattern imports the host's
tunables; other patterns are unsupported. Map entries unused by a particular
compiled variant are allowed in the manifest. All state reached through a
plugin's APIs must be exported, including allocator metadata and task/cgroup
references, not just the arena map.

Read-only literal data remains private. Deliberately private mutable maps
use `plugin_` names or `.data.plugin`/`.bss.plugin` sections. Other undeclared
maps are rejected, so a missing runtime import cannot silently create a
second allocator or independent task-state table.

Each plugin has a partial struct_ops map for libbpf's verifier-target
resolution. That map is never populated or attached. The loader translates
the host's selected shadow table to the running kernel's BTF layout, puts
the selected program FDs into it, then populates and attaches the host map
once. This avoids cross-object pointers in libbpf's shadow table and keeps
every selected program associated with only the final table.
The host is loaded in full, so replaced built-in callbacks are still
verified even though the composed scheduler does not execute them.

`Loaded` retains all provider objects along with the host. Detachment
precedes their destruction. `OpsProfiler::sample_loaded()` reports the
selected callback providers; `sample()` remains available for an individual
object. Replacing callbacks adds no plugin dispatch to the scheduling path.

Plugins can declare scalar counters as `counter=label:.data.plugin_map` in
their own manifests. Labels must be unique across providers. Each map must
be a private, single-entry array with a u32 key and a u64-sized value.
`Loaded::plugin_counters()` reads them by label, allowing a host to transport
and display a generic map of counters without knowing any plugin's policy,
map names or individual fields. `Loaded::plugin_objects()` remains available
for custom readers. See `scheds/experimental/scx_reevdf/plugins/` for a
virtual-time borrowing plugin and a VM integration test. There is no runtime
replacement or plugin initialization protocol yet; restart to change providers.
