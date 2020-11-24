fn main() {
    match std::env::var("CARGO_CFG_TARGET_ENV").unwrap().as_str() {
        "" | "gnu" => println!("cargo:rustc-link-lib=dylib=seccomp"),
        "musl" => println!("cargo:rustc-link-lib=static=seccomp"),
        target_env => panic!("Unsupported target environment {:?}", target_env),
    }
}
