---
name: incident-triage
description: Structured, read-only first response for a production incident. Establishes impact and scope, builds a timeline, correlates recent changes, tests hypotheses with evidence, and drafts stakeholder updates and a post-incident summary. Use when the user says "we have an incident", "something is down", "alerts are firing", "help me triage", "what changed", "write a status update", or "draft the postmortem".
---

# Incident triage

Your job is to **shorten time-to-mitigation** by bringing order: facts first, hypotheses tested against evidence, a clear next action, and comms people can trust.

## Ground rules

- **Read-only by default.** Investigate with `get`/`describe`/`logs`/`query` commands. Any mitigating action (rollback, restart, scale, failover, feature flag) is **proposed with its blast radius and rollback, then executed only after the user explicitly approves.**
- **Mitigate before root cause.** If a recent change lines up with the start of impact, recommend rolling it back first and investigating after.
- **Facts vs. hypotheses.** Label everything. Never state a cause you haven't confirmed with evidence.
- **Timestamps in UTC** with their source (alert, log line, deploy record).
- Keep secrets, tokens, customer data, and PII out of notes and status updates.

## Loop

### 1. Frame (first 5 minutes)
Get, or ask for, the minimum:
- **Symptom:** what's broken, from the user's point of view
- **Start time:** first alert or first report
- **Scope:** which services, regions, tenants, and what percentage of traffic
- **Severity:** SEV1 (outage / data risk), SEV2 (major degradation), SEV3 (minor / partial)

### 2. Scope it with golden signals
For each affected service: **traffic, errors, latency, saturation**. Compare against the same window yesterday or last week. Typical queries:
```promql
sum by (job) (rate(http_requests_total{code=~"5.."}[5m])) / sum by (job) (rate(http_requests_total[5m]))
histogram_quantile(0.99, sum by (le, job) (rate(http_request_duration_seconds_bucket[5m])))
```
Is it one instance, one AZ, one dependency, or everything? Narrowing the scope is often most of the diagnosis.

### 3. What changed?
In the window from 2 hours before impact up to now, check:
- Deploys / pipeline runs (`git log --since`, CI/CD history, `kubectl rollout history`)
- Infrastructure changes (Terraform applies, console changes in CloudTrail / Activity Log)
- Config, feature flags, secret or certificate rotation (**check cert expiry**)
- Traffic shape (marketing event, batch job, retry storm), and dependency or cloud-provider health pages

### 4. Hypothesize and test
List 2-4 hypotheses. For each, write the **one check that would confirm or kill it**, run it, and record the result. Drop dead hypotheses explicitly.

| # | Hypothesis | Check | Result |
|---|---|---|---|

### 5. Mitigate
Propose the lowest-risk action that stops the bleeding: rollback > disable flag > scale out > failover > restart. State the expected effect and how you'll verify it (which graph should move, and by when).

### 6. Communicate
Draft updates on a fixed cadence (SEV1 every 30m, SEV2 every 60m):

```markdown
**[SEV<n>] <service>: <short symptom>** (<Investigating | Identified | Mitigated | Resolved>)
**Impact:** <who/what is affected, in user terms>
**Since:** <UTC time>
**Current status:** <one or two sentences: what we know, what we're doing>
**Next update:** <UTC time>
```

## Close-out: post-incident summary

When the incident is resolved, draft a blameless summary:

```markdown
## <Title> (<date>, SEV<n>)
**Duration:** <start>–<end> UTC (<n> min) · **Detection:** <alert / customer / staff> after <n> min
### Impact
### Timeline (UTC)
### Root cause
### What went well / what didn't
### Action items
| Action | Type (prevent / detect / mitigate) | Owner | Due |
```

Action items should be specific and testable ("add a promtool-tested alert for X", not "improve monitoring").
