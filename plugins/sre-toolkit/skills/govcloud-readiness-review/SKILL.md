---
name: govcloud-readiness-review
description: Review infrastructure code, scripts and pipelines for AWS GovCloud (aws-us-gov partition) compatibility and compliance hygiene. Finds hard-coded commercial ARNs, non-partition-aware endpoints, missing FIPS endpoints, services/features not available in GovCloud, and secrets or data-handling risks. Use when the user asks "will this work in GovCloud", "port this to GovCloud", "make this partition-aware", "check for FedRAMP/IL issues", or is reviewing IaC that targets us-gov-west-1 / us-gov-east-1.
---

# GovCloud readiness review

Code written for commercial AWS often breaks in GovCloud in predictable ways. This review finds those breaks **statically**, before a failed deploy in a regulated account does it for you.

## Ground rules

- Read-only review. Report findings with `file:line` references and a concrete fix for each.
- **Don't assert service or feature availability from memory.** GovCloud availability changes. For anything uncertain, flag it as "verify" and point to the AWS GovCloud User Guide's per-service pages instead of guessing.
- Never call non-approved endpoints or external services from the review itself.

## 1. Partition-hardcoding scan

Run from the repo root and triage every hit (comments and docs are fine; code isn't):

```bash
# ARNs pinned to the commercial partition
grep -rnE 'arn:aws:' --include='*.tf' --include='*.py' --include='*.ps1' --include='*.sh' \
  --include='*.json' --include='*.yaml' --include='*.yml' --include='*.ts' --include='*.js' .

# Hard-coded endpoints / domains / regions
grep -rnE 'amazonaws\.com|console\.aws\.amazon\.com|us-(east|west)-[12]' \
  --include='*.tf' --include='*.py' --include='*.ps1' --include='*.sh' --include='*.yaml' --include='*.yml' .
```

| Finding | Fix |
|---|---|
| `"arn:aws:iam::aws:policy/..."` in Terraform | `"arn:${data.aws_partition.current.partition}:iam::aws:policy/..."` |
| ARN built by string concatenation in Python/PowerShell | Get the partition from `sts get-caller-identity` (ARN prefix) or a config value |
| `*.amazonaws.com` service principal | Usually still correct in GovCloud (e.g. `ec2.amazonaws.com`). **Verify** per service; prefer `data.aws_partition.current.dns_suffix` where the provider supports it |
| Hard-coded `us-east-1` | Variable / provider region. Note that global-service calls (IAM, STS, some Route 53 APIs) behave differently in GovCloud |
| Console / doc links to `console.aws.amazon.com` | `console.amazonaws-us-gov.com` |

## 2. FIPS and transport

- SDK and CLI calls should use **FIPS endpoints** where the compliance boundary requires them: `AWS_USE_FIPS_ENDPOINT=true`, `use_fips_endpoint = true` in the Terraform AWS provider, or `--endpoint-url` for the odd service. Flag pipelines that don't set this when the target is FedRAMP High / DoD IL.
- TLS everywhere: `aws:SecureTransport` deny statements on S3/SNS/SQS policies, and no `http://` endpoints.

## 3. Identity

- No long-lived IAM user keys in pipelines. Prefer OIDC federation or instance/task roles, and check that trust policies pin `sub` / `aud`.
- GovCloud accounts are separate from their paired commercial accounts: different IAM, different credentials. Flag code that assumes cross-partition role assumption (it doesn't work).
- Check whether the org mandates permissions boundaries on created roles.

## 4. Service and feature availability (verify, don't assume)

List every AWS service, and any notable feature (e.g. specific instance families, managed integrations, marketplace AMIs), that the code uses. Mark each one ✅ confirmed (with the doc link the user or you checked) or ❓ verify. Common sources of surprise are newer services, third-party SaaS integrations, and console-only features.

## 5. Data handling and logging

- Encryption at rest with customer-managed KMS keys where the baseline requires it; key policies partition-aware.
- Logging: CloudTrail (org/multi-region), VPC flow logs, and access logs on load balancers and buckets, with retention that meets the AU-family controls the system is assessed against.
- No CUI, secrets, or account identifiers in logs, pipeline output, Terraform outputs, or committed `*.tfvars`.
- Outbound calls from workloads or pipelines to SaaS endpoints outside the authorization boundary need to be flagged for the ISSO / boundary owner.

## Report format

```markdown
### GovCloud readiness: <repo/path>

**Summary:** <n> blocking · <n> should-fix · <n> to verify

| Severity | Location | Issue | Fix |
|---|---|---|---|
| Blocking | modules/x/main.tf:42 | Hard-coded `arn:aws:` managed policy ARN | Use `data.aws_partition` |

**Verify list:** services/features to confirm against the GovCloud User Guide
**Assumptions:** <anything you couldn't determine from the code>
```

Blocking = will fail to deploy or run in `aws-us-gov`. Should-fix = works, but is a compliance or maintainability risk. Verify = availability or behaviour you couldn't confirm statically.
