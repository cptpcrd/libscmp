# libscmp

[![crates.io](https://img.shields.io/crates/v/libscmp.svg)](https://crates.io/crates/libscmp)
[![Docs](https://docs.rs/libscmp/badge.svg)](https://docs.rs/libscmp)
[![GitHub Actions](https://github.com/cptpcrd/libscmp/workflows/CI/badge.svg?branch=master&event=push)](https://github.com/cptpcrd/libscmp/actions?query=workflow%3ACI+branch%3Amaster+event%3Apush)
[![codecov](https://codecov.io/gh/cptpcrd/libscmp/branch/master/graph/badge.svg)](https://codecov.io/gh/cptpcrd/libscmp)

A safe, **sane** Rust interface to `libseccomp` on Linux.

Note: This is not a high-level interface; most functions/methods in this library directly correspond to a `libseccomp` function. However, this library provides a sane, usable interface to `libseccomp`, something that seems to be lacking.

## Supported versions of `libseccomp`

By default, `libscmp` supports libseccomp v2.3.0+. Enabling the `libseccomp-2-4` feature enables support for libseccomp v2.4.0+ APIs (and also tells `libscmp` that it can assume it will never run against a version of libseccomp prior to v2.4.0). The `libseccomp-2-5` feature works similarly (and implies `libseccomp-2-4`).

### IMPORTANT: minimum version detection

`libscmp` assumes that the minimum version as specified by the feature flags is correct. For example, if the `libseccomp-2-4` feature is specified, `libscmp` may perform optimizations by assuming that features added in libseccomp v2.4.0 are present, rather than explicitly probing for them. However, it does NOT check the version of `libseccomp` that actually gets loaded at runtime to see if this is correct.

This is unlikely to cause any serious issues, and in most cases everything will be fine. However, if you cannot guarantee that the correct version of `libseccomp` will always be loaded (for example, if you are distributing compiled binaries that end users may download and run on older systems), it is recommended to check `libseccomp_version()` like so: `assert!(libscmp::libseccomp_version() >= (2, 4, 0));`.

## Building dependent crates

To build a crate that depends on `libscmp`, you need `libseccomp` installed :-). You may need to install the "development" `libseccomp` package (for example, `libseccomp-dev` on Debian/Ubuntu) so that it can be found properly.

### Statically linking against musl libc

Building this crate against musl libc is tricky, because you need to have a statically-linked version of `libseccomp` installed that was compiled **against musl**. This usually means you have to either build `libseccomp` manually (!) or use a musl-based distribution that provides a statically-linked `libseccomp`.

Here's a proof of concept for building against musl using an Alpine Linux Docker container. In most cases you'd want to create a separate Docker image with the dependencies installed (and then switch users when actually compiling), but this illustrates the process:

```bash
docker run -v $PWD:/src --rm alpine:latest sh -c '
set -e
apk add libseccomp-dev gcc
wget -O- https://sh.rustup.rs | sh /dev/stdin -y --default-host x86_64-unknown-linux-musl --default-toolchain stable
source $HOME/.cargo/env
cd /src
export RUSTFLAGS="-L /usr/lib"
cargo build
'
```
