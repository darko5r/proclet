fn main() {
    cc::Build::new()
        .file("c/sandbox.c")
        .include("c")
        .compile("sandbox_c");

    // Rebuild if these change
    println!("cargo:rerun-if-changed=c/sandbox.c");
    println!("cargo:rerun-if-changed=c/sandbox.h");
}
