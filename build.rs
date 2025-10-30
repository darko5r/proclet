fn main() {
    cc::Build::new()
        .file("c/sandbox.c")
        .include("c")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .compile("procletc");
}

