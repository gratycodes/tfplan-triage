#!/usr/bin/env bash
# Regenerates testdata/plans/*.json from the scenarios in this directory.
#
#   aws, gcp, azure: plan base/ (create-only, no credentials), turn the
#     planned values into a state file, then plan head/ against that state
#     with -refresh=false. The provider itself decides create/update/replace
#     and which attributes force replacement; nothing is hand-edited.
#   local: real apply with the local/random/terraform providers, an
#     out-of-band edit, then a refreshing plan, so resource_drift is real.
#
# Usage: ./gen.sh [scenario...]   (TF=terraform or TF=tofu per scenario)
set -euo pipefail
export TF_PLUGIN_CACHE_DIR=${TF_PLUGIN_CACHE_DIR:-$HOME/.cache/tfplan-triage-plugins}
mkdir -p "$TF_PLUGIN_CACHE_DIR"
# Plans run behind a dead proxy so any attempt to reach a cloud API fails
# loudly instead of silently depending on the network.
offline() { HTTPS_PROXY=http://127.0.0.1:9 HTTP_PROXY=http://127.0.0.1:9 NO_PROXY=127.0.0.1,localhost "$@"; }
here=$(cd "$(dirname "$0")" && pwd)
out="${OUT:-$here/../plans}"
mkdir -p "$out"

cloud() {
  local name=$1 tf=$2 work
  work=$(mktemp -d)
  cp -r "$here/$name/base/." "$work/"
  ( cd "$work"
    $tf init -input=false -no-color >/dev/null
    offline $tf plan -input=false -refresh=false -no-color -out=base.bin >/dev/null
    $tf providers schema -json > schema.json
    $tf show -json base.bin > base.json
    "$here/build_state.py" base.json schema.json > terraform.tfstate
    # Re-plan base against the synthetic state so references to ids and
    # ARNs settle to known values; two passes are enough for these configs.
    for _ in 1 2; do
      offline $tf plan -input=false -refresh=false -no-color -out=base.bin >/dev/null
      $tf show -json base.bin > base.json
      "$here/build_state.py" base.json schema.json > state.next
      mv state.next terraform.tfstate
    done
    find . -name '*.tf' -not -path './.terraform/*' -delete
    cp -r "$here/$name/head/." "$work/"
    $tf init -input=false -no-color >/dev/null
    offline $tf plan -input=false -refresh=false -no-color -out=head.bin >/dev/null
    $tf show -json head.bin | jq -S . > "$out/$name.json"
  )
  rm -rf "$work"
  echo "wrote plans/$name.json ($tf)"
}

local_drift() {
  local tf=$1 work
  work=$(mktemp -d)
  cp -r "$here/local/base/." "$work/"
  ( cd "$work"
    $tf init -input=false -no-color >/dev/null
    $tf apply -input=false -auto-approve -no-color >/dev/null
    # Someone "fixes" production by hand.
    rm -f out/feature-flags.json
    find . -name '*.tf' -not -path './.terraform/*' -delete
    cp -r "$here/local/head/." "$work/"
    $tf plan -input=false -no-color -out=head.bin >/dev/null
    # Strip the box-specific temp path from local_file filenames.
    $tf show -json head.bin | jq -S . | sed "s#$work/##g" > "$out/local.json"
  )
  rm -rf "$work"
  echo "wrote plans/local.json ($tf)"
}

scenarios=("$@")
[[ ${#scenarios[@]} -eq 0 ]] && scenarios=(aws gcp azure local)
for s in "${scenarios[@]}"; do
  case $s in
    aws) cloud aws "${TF_AWS:-terraform}" ;;
    gcp) cloud gcp "${TF_GCP:-tofu}" ;;
    azure)
      # azurerm wants a token at configure time; serve a synthetic one.
      python3 "$here/fake_msi.py" 8765 & msi=$!
      trap 'kill $msi 2>/dev/null || true' EXIT
      sleep 1
      ARM_PROVIDER_ENHANCED_VALIDATION=false cloud azure "${TF_AZURE:-terraform}"
      kill $msi ;;
    local) local_drift "${TF_LOCAL:-terraform}" ;;
    *) echo "unknown scenario $s" >&2; exit 1 ;;
  esac
done
