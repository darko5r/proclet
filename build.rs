fn main() {
    cc::Build::new()
        .file("c/proclet.c")
        .include("c")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .compile("procletc");
}

