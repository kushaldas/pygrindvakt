#!/bin/bash
set -euo pipefail

: "${UV_VERSION:=0.11.23}"
: "${RUSTUP_HOME:=/opt/rustup}"
: "${CARGO_HOME:=/opt/cargo}"
# Exact Rust version for the wheel build. Required: ci.yml and release.yml are the
# single source and pass it with `docker run -e`, so it cannot silently drift.
: "${RUST_TOOLCHAIN:?set RUST_TOOLCHAIN (see the env block in ci.yml / release.yml)}"
# rustup-init is pinned by version and verified against a SHA-256 recorded here
# (x86_64-unknown-linux-gnu, matches the published .sha256). To bump: fetch the new
# archive, check its hash against the published one, and update both values.
: "${RUSTUP_VERSION:=1.29.3}"
: "${RUSTUP_INIT_SHA256:=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55}"

export RUSTUP_HOME
export CARGO_HOME
export PATH="${CARGO_HOME}/bin:/opt/python/cp314-cp314/bin:${PATH}"

curl --proto '=https' --tlsv1.2 -sSf \
    -o /tmp/rustup-init \
    "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init"
echo "${RUSTUP_INIT_SHA256}  /tmp/rustup-init" | sha256sum -c -
chmod +x /tmp/rustup-init
/tmp/rustup-init -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"
rustc --version
cargo --version

/opt/python/cp314-cp314/bin/python3.14 -m pip install --upgrade "uv==${UV_VERSION}"
uv --version

/io/build-wheels.sh
