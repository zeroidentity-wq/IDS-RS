#!/usr/bin/env bash
# =============================================================================
# Creeaza arhiva de livrare pentru serverele RHEL 9 din reteaua izolata.
# Ruleaza pe masina conectata, dupa deploy/build-rhel9.sh:
#
#   deploy/package.sh [binar]     (implicit target/rhel9/release/ids-rs)
#     →  target/dist/ids-rs-<versiune>-rhel9.tar.gz (+ .sha256)
#
# Pe server (fara internet):
#   sha256sum -c ids-rs-<versiune>-rhel9.tar.gz.sha256
#   tar xzf ids-rs-<versiune>-rhel9.tar.gz && cd ids-rs-<versiune>-rhel9
#   sha256sum -c SHA256SUMS && sudo ./install.sh
# =============================================================================
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
binary=${1:-$project_dir/target/rhel9/release/ids-rs}

if [[ ! -x $binary ]]; then
    echo "Nu gasesc binarul $binary — ruleaza intai deploy/build-rhel9.sh." >&2
    exit 1
fi

# RHEL 9 are glibc 2.34; un binar care cere o versiune mai noua nu porneste.
required_glibc=$(objdump -T "$binary" | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -1)
if [[ $(printf '%s\n' "$required_glibc" GLIBC_2.34 | sort -V | tail -1) != GLIBC_2.34 ]]; then
    echo "Binarul cere $required_glibc, dar RHEL 9 are GLIBC_2.34 — compileaza cu deploy/build-rhel9.sh." >&2
    exit 1
fi

version=$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$project_dir/Cargo.toml" | head -1)
commit=$(git -C "$project_dir" rev-parse --short HEAD 2>/dev/null || echo unknown)
if [[ -n $(git -C "$project_dir" status --porcelain --untracked-files=no 2>/dev/null) ]]; then
    commit="$commit-dirty"
fi
name="ids-rs-$version-$commit-rhel9"
dist_dir="$project_dir/target/dist"
staging=$(mktemp -d)
trap 'rm -rf "$staging"' EXIT

package="$staging/$name"
install -d "$package/systemd"
install -m 0755 "$binary" "$package/ids-rs"
install -m 0755 "$project_dir/deploy/install.sh" "$package/install.sh"
install -m 0644 "$project_dir/deploy/systemd/ids-rs@.service" "$package/systemd/ids-rs@.service"
install -m 0644 "$project_dir/config.toml" "$package/example.toml"
install -m 0644 "$project_dir/README.md" "$package/README.md"
(cd "$package" && find . -type f ! -name SHA256SUMS -printf '%P\n' | sort | xargs sha256sum >SHA256SUMS)

install -d "$dist_dir"
tar -C "$staging" --owner=0 --group=0 -czf "$dist_dir/$name.tar.gz" "$name"
(cd "$dist_dir" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256")

echo "Arhiva: $dist_dir/$name.tar.gz"
cat "$dist_dir/$name.tar.gz.sha256"
