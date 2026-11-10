#!/bin/bash
set -ex

command -v cargo >/dev/null 2>&1 || {
    echo "cargo is required; install Rust in the build image before running this script" >&2
    exit 1
}
command -v uv >/dev/null 2>&1 || {
    echo "uv is required; install it in the build image before running this script" >&2
    exit 1
}

PYTHON="${PYTHON:-/opt/python/cp314-cp314/bin/python3.14}"
test -x "$PYTHON" || {
    echo "Python build driver not found or not executable: $PYTHON" >&2
    exit 1
}

uv venv --python "$PYTHON" /opt/venv
source /opt/venv/bin/activate
uv pip install --upgrade "maturin==1.14.1"
cd /io/
# pygrindvakt builds an abi3 (py310+) wheel, so the single artifact produced
# here covers every supported CPython; the cp314 interpreter above is only the
# build driver.
# --locked: fail the build if Cargo.lock is stale instead of silently re-resolving.
maturin build --release --strip --manylinux --sdist --locked
mkdir -p dist/
cp target/wheels/pygrindvakt*.whl ./dist/
cp target/wheels/pygrindvakt*.tar.gz ./dist/
