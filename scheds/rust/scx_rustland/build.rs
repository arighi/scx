// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

fn main() {
    scx_utils::BpfBuilder::new()
        .unwrap()
        .enable_intf("../../../rust/scx_user/src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("../../../rust/scx_user/src/bpf/main.bpf.c", "bpf")
        .build()
        .unwrap();
}
