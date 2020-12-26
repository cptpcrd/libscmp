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
        return match link_type.as_str() {
            "0" | "false" => false,
            _ => true,
        };
    }

    let target_vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap();

    match (target_vendor.as_str(), target_env.as_str()) {
        // When linking against glibc, or Alpine's built-in musl target, default to dynamic linking.
        (_, "") | (_, "gnu") | ("alpine", "musl") => false,

        // Against other musl setups, default to static linking.
        (_, "musl") => true,

        _ => panic!(
            "Unsupported target vendor/environment {:?}/{:?}",
            target_vendor, target_env
        ),
    }
}
