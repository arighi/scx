// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::env;
use std::fs::File;
use std::path::PathBuf;

const BPF_H: &str = "bpf_h";

fn gen_bpf_h() {
    let file =
        File::create(PathBuf::from(env::var("OUT_DIR").unwrap()).join(format!("{}.tar", BPF_H)))
            .unwrap();
    let mut ar = tar::Builder::new(file);

    ar.follow_symlinks(false);
    ar.append_dir_all(".", BPF_H).unwrap();
    ar.finish().unwrap();

    for ent in walkdir::WalkDir::new(BPF_H) {
        let ent = ent.unwrap();
        if !ent.file_type().is_dir() {
            println!("cargo:rerun-if-changed={}", ent.path().to_string_lossy());
        }
    }
}

fn gen_bindings() {
    // FIXME - bindgen's API changed between 0.68 and 0.69 so that
    // `bindgen::CargoCallbacks::new()` should be used instead of
    // `bindgen::CargoCallbacks`. Unfortunately, as of Dec 2023, fedora is
    // shipping 0.68. To accommodate fedora, allow both 0.68 and 0.69 of
    // bindgen and suppress deprecation warning. Remove the following once
    // fedora can be updated to bindgen >= 0.69.
    #[allow(deprecated)]
    let bindings = bindgen::Builder::default()
        .header("bindings.h")
	.allowlist_type("scx_exit_kind")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bindings.rs"))
        .expect("Couldn't write bindings");
}

fn main() {
    gen_bpf_h();
    gen_bindings();
}
