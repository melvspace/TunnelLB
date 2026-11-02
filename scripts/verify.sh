#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

verify_rust() {
  cargo fmt --all -- --check
  cargo clippy --locked --all-targets --all-features -- -D warnings
  cargo test --locked --all-features

  mkdir -p /tmp/codex
  crd_file="$(mktemp /tmp/codex/tunnellb-crd.XXXXXX)"
  trap 'rm -f "$crd_file"' EXIT
  cargo run --locked -- crd > "$crd_file"
  diff -u charts/tunnellb/crds/servers.yaml "$crd_file"
}

verify_helm() {
  # The API server CIDR is an offline validation fixture only.
  helm lint charts/tunnellb --strict \
    --namespace tunnellb-system \
    --set 'networkPolicy.apiServerCIDRs[0]=192.0.2.1/32'
  helm template tunnellb charts/tunnellb --include-crds \
    --namespace tunnellb-system \
    --set 'networkPolicy.apiServerCIDRs[0]=192.0.2.1/32' > /dev/null
}

if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [all|rust|helm]" >&2

  exit 2
fi

case "${1:-all}" in
  all)
    verify_rust
    verify_helm
    ;;
  rust)
    verify_rust
    ;;
  helm)
    verify_helm
    ;;
  *)
    echo "Usage: $0 [all|rust|helm]" >&2

    exit 2
    ;;
esac
