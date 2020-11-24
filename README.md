# libscmp

[![crates.io](https://img.shields.io/crates/v/libscmp.svg)](https://crates.io/crates/libscmp)
[![Docs](https://docs.rs/libscmp/badge.svg)](https://docs.rs/libscmp)
[![GitHub Actions](https://github.com/cptpcrd/libscmp/workflows/CI/badge.svg?branch=master&event=push)](https://github.com/cptpcrd/libscmp/actions?query=workflow%3ACI+branch%3Amaster+event%3Apush)
[![codecov](https://codecov.io/gh/cptpcrd/libscmp/branch/master/graph/badge.svg)](https://codecov.io/gh/cptpcrd/libscmp)

A safe, **sane** Rust interface to `libseccomp` on Linux.

Note: This is not a high-level interface; most functions/methods in this library directly correspond to a `libseccomp` function. However, this library provides a sane, usable interface to `libseccomp`, something that seems to be lacking.

## Supported versions of `libseccomp`

By default, `libscmp` supports libseccomp v2.3.0+. Enabling the `libseccomp-2-4` feature enables support for libseccomp v2.4.0+ APIs (and also tells `libscmp` that it can assume it will never run against a version of libseccomp prior to 2.4.0). (The `libseccomp-2-5` feature works similarly, and implies `libseccomp-2-4`.)

**IMPORTANT**: `libscmp` does NOT check the version of `libseccomp` that gets loaded (though there are some debug assertions that perform feature checks). If you need to ensure the version matches, you can use `libseccomp_version()` like so: `assert!(libscmp::libseccomp_version() >= (2, 3, 0));`.

## Building

You need `libseccomp` installed to build.
