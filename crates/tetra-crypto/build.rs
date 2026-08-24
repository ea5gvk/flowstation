fn main() {
    cc::Build::new()
        .file("vendor/taa1.c")
        .file("vendor/hurdle.c")
        .file("vendor/common.c")
        .include("vendor")
        .warnings(false)
        .compile("tetra_taa1");

    println!("cargo:rerun-if-changed=vendor/taa1.c");
    println!("cargo:rerun-if-changed=vendor/taa1.h");
    println!("cargo:rerun-if-changed=vendor/hurdle.c");
    println!("cargo:rerun-if-changed=vendor/hurdle.h");
    println!("cargo:rerun-if-changed=vendor/common.c");
    println!("cargo:rerun-if-changed=vendor/common.h");
}
