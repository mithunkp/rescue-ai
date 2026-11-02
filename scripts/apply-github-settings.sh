#!/usr/bin/env bash
# Turn on GitHub's protections for the public repository. Run once, after it is made public
# (rules for main, secret scanning and code scanning are only free on public repositories).
#   bash scripts/apply-github-settings.sh [owner/repo]
set -euo pipefail
REPO="${1:-mithunkp/rescue-ai}"

echo "== merge settings: squash only, delete merged branches"
gh repo edit "$REPO" --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false \
  --delete-branch-on-merge --enable-issues --enable-wiki=false

echo "== GitHub Actions: read-only token by default; outside contributors' runs need approval"
gh api -X PUT "repos/$REPO/actions/permissions/workflow" \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
gh api -X PUT "repos/$REPO/actions/permissions/fork-pr-contributor-approval" \
  -f approval_policy=all_external_contributors

echo "== security: secret scanning + push protection, Dependabot alerts and fixes, private reports"
gh api -X PATCH "repos/$REPO" --input - <<'JSON'
{"security_and_analysis": {"secret_scanning": {"status": "enabled"},
                           "secret_scanning_push_protection": {"status": "enabled"}}}
JSON
gh api -X PUT "repos/$REPO/vulnerability-alerts"
gh api -X PUT "repos/$REPO/automated-security-fixes"
gh api -X PUT "repos/$REPO/private-vulnerability-reporting"

echo "== main: only through pull requests with green checks; no force-push or deletion (no bypass)"
gh api -X POST "repos/$REPO/rulesets" --input - <<'JSON'
{"name": "main: always", "target": "branch", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
 "rules": [
   {"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "required_linear_history"},
   {"type": "pull_request", "parameters": {"required_approving_review_count": 0, "dismiss_stale_reviews_on_push": true,
     "require_code_owner_review": false, "require_last_push_approval": false, "required_review_thread_resolution": true}},
   {"type": "required_status_checks", "parameters": {"strict_required_status_checks_policy": true,
     "required_status_checks": [{"context": "test"}, {"context": "build"}, {"context": "boot-test"},
                                {"context": "analyze (python)"}, {"context": "analyze (actions)"}]}}]}
JSON

echo "== main: the maintainer (code owner) must approve; admins may merge their own PRs"
gh api -X POST "repos/$REPO/rulesets" --input - <<'JSON'
{"name": "main: maintainer review", "target": "branch", "enforcement": "active",
 "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}],
 "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
 "rules": [
   {"type": "pull_request", "parameters": {"required_approving_review_count": 1, "dismiss_stale_reviews_on_push": true,
     "require_code_owner_review": true, "require_last_push_approval": true, "required_review_thread_resolution": true}}]}
JSON

echo "== topics"
gh repo edit "$REPO" --add-topic windows-repair --add-topic mcp --add-topic live-usb --add-topic debian \
  --add-topic claude --add-topic system-rescue
echo "Done."
