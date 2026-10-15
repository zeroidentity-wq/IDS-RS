#!/usr/bin/env bash
# =============================================================================
# Compileaza binarul release pentru RHEL 9 intr-un container UBI 9 (podman).
#
#   deploy/build-rhel9.sh            →  target/rhel9/release/ids-rs
#
# Un binar compilat pe o distributie mai noua (ex: Fedora) cere un glibc mai
# nou decat 2.34 si nu porneste pe RHEL 9. Pe o masina RHEL 9 cu Rust
# instalat, `cargo build --release` direct este echivalent.
#
# Toolchain-ul (Rust 1.85, din rust-toolchain.toml) si crate-urile descarcate
# raman in volumele podman ids-rs-rustup / ids-rs-cargo pentru rularile urmatoare.
# =============================================================================
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
image=${IDS_RS_BUILD_IMAGE:-registry.access.redhat.com/ubi9/ubi:9.6}

# label=disable: proiectul este montat fara reetichetare SELinux (:Z ar
# schimba contextul tuturor fisierelor din proiect).
podman run --rm \
    --security-opt label=disable \
    -v "$project_dir:/src" \
    -v ids-rs-rustup:/root/.rustup \
    -v ids-rs-cargo:/root/.cargo \
    -e CARGO_TARGET_DIR=/src/target/rhel9 \
    -w /src \
    "$image" \
    bash -euo pipefail -c '
        dnf install -y --setopt=install_weak_deps=False \
            gcc openssl-devel pkgconf-pkg-config >/dev/null
        if [[ ! -x /root/.cargo/bin/rustup ]]; then
            curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs |
                sh -s -- -y --profile minimal --default-toolchain none
        fi
        export PATH=/root/.cargo/bin:$PATH
        channel=$(sed -n "s/^channel *= *\"\(.*\)\"/\1/p" rust-toolchain.toml)
        rustup toolchain install "$channel" --profile minimal
        cargo build --release --locked
    '

echo "Binar RHEL 9: $project_dir/target/rhel9/release/ids-rs"
