#!/usr/bin/env bash
# Runs tfplan-triage for the composite GitHub Action: reads the PR's live
# labels, writes the job summary, creates or updates one PR comment per
# title, then exits with the CLI's code so a failed gate still comments.
set -euo pipefail

title=${TPT_TITLE:-}
marker="<!-- tfplan-triage:${title:-default} -->"
md="$RUNNER_TEMP/tfplan-triage-${title:-default}.md"
json="$RUNNER_TEMP/tfplan-triage-${title:-default}.json"
pr=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH")
api="repos/$GITHUB_REPOSITORY/issues"

labels=${TPT_LABELS:-}
if [[ -z "$labels" && -n "$pr" ]]; then
  # Read labels live: a re-run of an old job would otherwise see the
  # labels from when the event fired.
  labels=$(gh api "$api/$pr/labels" --jq '[.[].name] | join(",")' 2>/dev/null ||
    jq -r '[.pull_request.labels[].name] | join(",")' "$GITHUB_EVENT_PATH")
fi

args=(--format markdown --output "$md" --json-output "$json" --labels "$labels")
[[ -n "${TPT_TF_DIR:-}" ]] && args+=(--tf-dir "$TPT_TF_DIR")
[[ -n "${TPT_CONFIG:-}" ]] && args+=(--config "$TPT_CONFIG")
[[ -n "${TPT_FAIL_ON:-}" ]] && args+=(--fail-on "$TPT_FAIL_ON")
[[ -n "$title" ]] && args+=(--title "$title")

set +e
"$TPT_BIN" "${args[@]}" "$TPT_PLAN"
code=$?
set -e
if [[ $code -ne 0 && $code -ne 2 ]]; then
  echo "::error::tfplan-triage failed with exit code $code"
  exit "$code"
fi

cat "$md" >>"$GITHUB_STEP_SUMMARY"
{
  echo "critical=$(jq '[.result.findings[] | select(.severity == "critical")] | length' "$json")"
  echo "high=$(jq '[.result.findings[] | select(.severity == "high")] | length' "$json")"
  echo "blocked=$(jq '.gate.blocked' "$json")"
  echo "missing-labels=$(jq -r '(.gate.missing_labels // []) | join(",")' "$json")"
  echo "report-json=$json"
} >>"$GITHUB_OUTPUT"

if [[ "$TPT_COMMENT" == "true" && -n "$pr" ]]; then
  existing=$(gh api --paginate "$api/$pr/comments" \
    --jq ".[] | select(.body | startswith(\"$marker\")) | .id" | head -n1 || true)
  if [[ -n "$existing" ]]; then
    gh api -X PATCH "$api/comments/$existing" -F "body=@$md" >/dev/null &&
      echo "Updated PR comment $existing" ||
      echo "::warning::could not update the PR comment (fork PRs get a read-only token)"
  else
    gh api -X POST "$api/$pr/comments" -F "body=@$md" >/dev/null &&
      echo "Posted PR comment" ||
      echo "::warning::could not post a PR comment (fork PRs get a read-only token)"
  fi
fi

if [[ $code -eq 2 ]]; then
  missing=$(jq -r '(.gate.missing_labels // []) | join(" and ")' "$json")
  if [[ -n "$missing" ]]; then
    echo "::error::tfplan-triage: unapproved findings at or above fail-on; after review, add the label $missing"
  else
    echo "::error::tfplan-triage: findings at or above fail-on"
  fi
fi
exit "$code"
