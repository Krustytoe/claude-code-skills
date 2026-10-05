---
name: terraform-change-review
description: Review a Terraform change before it is applied. Runs fmt/validate/plan, scores the plan for risk (destroys, replacements of stateful resources, IAM wildcards, world-open security groups, public S3), and writes a reviewer-ready change summary with impact and rollback. Use when the user asks to "review this terraform", "check the plan", "is this safe to apply", "summarize the infra change", or before any terraform apply.
---

# Terraform change review

Goal: give a human approver everything they need to say yes or no to a Terraform change, **without applying anything**.

## Hard rules

- **Never run `terraform apply`, `destroy`, `import`, `state rm/mv`, or `taint`** as part of this skill. Review only.
- Never print secret values. Plan JSON can contain sensitive attributes; the bundled analyzer prints only addresses and reasons, never values. Don't `cat` the plan JSON into the transcript.
- If the plan needs credentials that aren't available, stop and tell the user which ones; don't guess or work around it.

## Steps

1. **Locate the root module.** Look for the directory with the `backend`/`provider` blocks the user means. If there are several environments (`envs/dev`, `envs/prod`, workspaces), confirm which one.
2. **Static checks** (cheap, fail fast):
   ```bash
   terraform fmt -check -recursive -diff
   terraform init -input=false        # use -backend=false if only validating
   terraform validate
   ```
   Run `tflint` too if a `.tflint.hcl` exists.
3. **Plan to a file and render JSON:**
   ```bash
   terraform plan -input=false -lock=false -out=tfplan
   terraform show -json tfplan > tfplan.json
   ```
   `-lock=false` is fine for a read-only review; say so in the summary.
4. **Score the plan** with the bundled analyzer:
   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/skills/terraform-change-review/scripts/plan_risk.py" tfplan.json
   ```
   It prints a Markdown table of findings (CRITICAL/HIGH/MEDIUM) plus action counts and exits non-zero at or above `--fail-on` (default `high`).
5. **Read the risky diffs yourself.** For every CRITICAL/HIGH row, look at the actual attribute change (`terraform show tfplan | less`, or targeted `jq` on `resource_changes[] | select(.address=="...")`) and explain *why* it's happening: forced replacement from an immutable attribute, a provider upgrade, a renamed resource that needs a `moved` block, and so on.
6. **Write the summary** using the template below. Clean up `tfplan` / `tfplan.json` afterwards, or remind the user they're git-ignored.

## Common causes worth checking

| Symptom | Usual cause | Fix |
|---|---|---|
| Replace on a renamed resource | Address changed | Add a `moved {}` block |
| Replace of RDS / EBS / bucket | Immutable attribute changed (engine, AZ, name) | Usually re-plan the approach; never accept data loss silently |
| Unexpected diff on every plan | Provider default drift, `ignore_changes` missing, computed tags | Pin the provider and set the attribute explicitly |
| `(known after apply)` everywhere | Dependency on a resource being replaced | Trace upstream to the real change |

## Summary template

```markdown
### Terraform change review: <root module / env>

**Verdict:** ✅ Safe to apply | ⚠️ Apply with care | ⛔ Do not apply as-is

**What changes:** <N> to add, <N> to change, <N> to destroy (<N> replacements)
<2-4 bullet plain-English description of the intent>

**Risks**
| Severity | Resource | Why it matters | Mitigation |
|---|---|---|---|

**Validation:** fmt ✅ · validate ✅ · tflint ✅ · plan ✅ (lock-free, read-only)

**Rollback:** <revert commit + re-apply / restore from snapshot X / not reversible because Y>
```

Pick the verdict like this: any CRITICAL → ⛔ unless the user has explicitly said the destroy is intended. Any HIGH → ⚠️ with the specific mitigation. Otherwise ✅.
