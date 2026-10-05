# claude-code-skills

[![CI](https://github.com/Krustytoe/claude-code-skills/actions/workflows/ci.yml/badge.svg)](https://github.com/Krustytoe/claude-code-skills/actions/workflows/ci.yml)

[Claude Code](https://claude.com/claude-code) skills for cloud infrastructure, SRE, and observability work, packaged as a plugin marketplace.

They encode how I actually run these workflows: **inspect → validate → plan → approve → apply → record**, read-only by default, no secrets in transcripts, and no claiming something was tested when it wasn't.

## Install

```text
/plugin marketplace add Krustytoe/claude-code-skills
/plugin install sre-toolkit@krustytoe-skills
```

## `sre-toolkit` skills

| Skill | Triggers on | What it does |
|---|---|---|
| **terraform-change-review** | "review this terraform", "is this safe to apply" | fmt → validate → tflint → plan, then scores the plan with a bundled analyzer and writes an approver-ready summary with verdict, risks, and rollback. Never applies. |
| **prometheus-alert-authoring** | "add an alert", "SLO alert", "noisy alert" | Severity conventions, runbook links, multi-window burn-rate SLO patterns, and **required** promtool tests (firing *and* non-firing cases). |
| **incident-triage** | "we have an incident", "what changed", "status update" | Frame → golden signals → change correlation → hypothesis table → proposed mitigation (executed only with approval) → stakeholder updates and a blameless post-incident summary. |
| **govcloud-readiness-review** | "will this work in GovCloud", "make this partition-aware" | Static scan for hard-coded `arn:aws:`, commercial endpoints and regions, FIPS endpoint gaps, identity anti-patterns, and data-handling risks; flags service availability as *verify* instead of guessing. |

### `plan_risk.py`

The Terraform skill ships a stdlib-only analyzer for `terraform show -json` output:

```bash
terraform plan -out=tfplan && terraform show -json tfplan > tfplan.json
python3 plugins/sre-toolkit/skills/terraform-change-review/scripts/plan_risk.py tfplan.json --fail-on high
```

| Severity | Examples |
|---|---|
| CRITICAL | Destroy or replace of stateful resources: RDS, DynamoDB, S3, EBS, EFS, KMS keys, log groups, Key Vault, Cloud SQL, … |
| HIGH | IAM `Action: "*"`, AdministratorAccess attachments, world-open ingress (non-web ports), S3 public-access-block off, public or unencrypted databases |
| MEDIUM | Other destroys/replacements, public 80/443 ingress, service-wide `svc:*` on `Resource: "*"`, unencrypted EBS |

It prints **addresses and reasons only, never attribute values**, so sensitive plan data stays out of logs. Exit codes: `0` clean, `2` threshold met, `1` bad input. That makes it usable as a CI gate on its own.

## Development

```bash
python -m pytest tests                              # analyzer unit tests
claude plugin validate --strict .                   # marketplace manifest
claude plugin validate --strict plugins/sre-toolkit # plugin + skills
```

## License

MIT
