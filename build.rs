fn main() {
    // Sanity check
    assert_eq!(
        std::env::var("CARGO_CFG_TARGET_OS").unwrap(),
        "linux",
        "This crate is Linux-only",
    );

    if link_static() {
        println!("cargo:rustc-link-lib=static=seccomp");
    } else {
        println!("cargo:rustc-link-lib=dylib=seccomp");
    }

    println!("cargo:rerun-if-env-changed=LIBSECCOMP_STATIC");
    println!("cargo:rerun-if-env-changed=LIBSCMP_STATIC");
}

fn link_static() -> bool {
    // Check LIBSCMP_STATIC or LIBSECCOMP_STATIC
    if let Ok(link_type) =
        std::env::var("LIBSCMP_STATIC").or_else(|_| std::env::var("LIBSECCOMP_STATIC"))
    {
        return !matches!(link_type.as_str(), "0" | "false");
    }

    std::env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap_or_default()
        .contains("crt-static")
}
