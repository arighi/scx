# Virtual-time borrowing plugin

`borrowing/src/main.rs` replaces reevdf's `enqueue` callback with a wakeup-credit
policy inspired by scx_rburst. It grants queued wakeups 1 ms of service at
their effective pack weight, retaining a larger credit they already have.
It does not implement rburst's wakeup clock bias or CPU-selection policy.

Build the scheduler and its plugin with:

```sh
cargo build -p scx_reevdf
sudo target/debug/scx_reevdf --plugin target/debug/scx_reevdf_borrowing.bpf.a --stats 1
```

The plugin is exported beside the executable as `scx_reevdf_borrowing.bpf.a`.
With `--release`, both are in `target/release`; otherwise they are in
`target/debug`. Custom Cargo profiles, targets and target directories follow
the executable's location too. The BPF code itself is always optimized.

The artifact is a standard `ar` archive with `legacy.bpf.o` and
`sized.bpf.o` members. The loader chooses the topology ABI matching the
host scheduler before opening the selected ELF object with libbpf. No
variant selection or plugin dispatch is added to the scheduling paths.
Standalone `.bpf.o` ELF plugins are also accepted.

Use `ar t scx_reevdf_borrowing.bpf.a` to list its members. Builds remove the
old separate `.bpf.o` exports. Without the Rust BPF toolchain, builds do
not export placeholders or retain a stale archive.

```sh
cargo build --release -p scx_reevdf
sudo target/release/scx_reevdf --plugin target/release/scx_reevdf_borrowing.bpf.a --verify
sudo target/release/scx_reevdf --plugin target/release/scx_reevdf_borrowing.bpf.a --stats 1
```

The plugin declares `borrowing.wakeups` in `borrowing/src/imports.plugin`.
The generic counter transport prints `plugin borrowing.wakeups N` for
intervals in which credit was granted. The host does not know this label or
its map name. Changing `CREDIT_NS` in `borrowing/src/main.rs` changes the
budget; rebuild after editing it.
There is no plugin-specific command-line configuration yet.

The example is a standalone BPF crate under `borrowing/`. It links the
shared reevdf library, rather than compiling or replacing the host's native
entry-point source. Example build registration lives in `plugins/build.rs`;
the host build script invokes that collection without naming a policy.

The plugin calls `Reevdf::enqueue_with` with a statically selected policy.
The host uses ordinary enqueue with an empty policy. Both are specialized
at build time, with no indirect policy call or runtime dispatcher.

`QueuedTask::adjust_vruntime` exposes a numeric `VruntimePosition` to the
policy: current vruntime, projected placement reference, effective weight
and peer weight. The policy selects a coordinate; the host handles pack
removal/rejoin and relative-deadline rebasing, preserving cgroup membership
and the empty-generation counter. The API rejects the published running
task and exposes no mutable task context.

All borrowing arithmetic lives in `borrowing/src/policy.rs`. Wakeup, fork
and re-enqueue eligibility, the credit budget and the counter belong to the
plugin. The host neither grants credit nor restricts adjustments to credit.
The plugin retains larger existing lag and skips packs without peers.
Normal placement and bandwidth parking precede this hook; idle dispatches
keep their existing path. Ordinary running and stopping charge service from
the selected coordinate. Credit can intentionally override negative lag
remaining after normal placement settles delayed debt.

This policy favors wakeups over continuously runnable tasks. Fresh wakeups
can receive fresh credit indefinitely; there is no cumulative debt limit or
repayment scheme. CPU bandwidth enforcement and ordinary preemption rules
remain in force, so credit does not guarantee immediate preemption.

The host owns `../plugin.contract`, with callback and shared-state exports.
The plugin owns `borrowing/src/imports.plugin`. Contract version 3 describes
the generic provider API. New policy or counter implementations do not
require edits to the host's callbacks, math or statistics schema.

Reevdf exports `select_cid`, `enqueue`, `tick`, `running`, `stopping` and
`yield_task` for load-time replacement. A plugin declares only the callbacks
it replaces in its imports manifest. Unclaimed callbacks use the host's
programs, with no runtime plugin checks or dispatch. These additional
exports are compatible with existing contract version 3 plugins.

Replacements own the entire callback, including its scheduler bookkeeping.
In particular, `running` and `stopping` maintain runtime accounting and pack
state. A plugin extending the existing behavior can call the corresponding
`Reevdf` method, which is statically inlined into its program.

Policy arithmetic tests run without the BPF toolchain:

```sh
cargo test --manifest-path scheds/experimental/scx_reevdf/plugins/borrowing/Cargo.toml --target-dir target/plugin-tests
```

The VM test checks verification, conflicts, callback selection, positive
borrowing under pinned CPU contention, and clean arena teardown. It requires
bpftool and a disposable VM with a CID-capable kernel and BPF arena support:

```sh
# From a built kernel tree, using absolute paths:
vng --cpus 4 --memory 4G -- 'python3 /path/to/scx/scheds/experimental/scx_reevdf/plugins/test.py /path/to/scx/target/debug/scx_reevdf /path/to/scx/target/debug/scx_reevdf_borrowing.bpf.a'
```
