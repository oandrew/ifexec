use std::{path::{PathBuf}, env};

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "./src/bpf/sock.bpf.c";

fn main() {
    let mut out =
        PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"));
    out.push("sock.skel.rs");
    SkeletonBuilder::new()
        .source(SRC)
        .debug(true)
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={}", SRC);
}
