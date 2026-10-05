#!/usr/bin/env python3
"""Score a Terraform plan for review risk.

Input : JSON from `terraform show -json tfplan`
Output: Markdown summary + findings table on stdout. Only resource addresses and
        reasons are printed -- never attribute values, so sensitive data stays out
        of logs and transcripts.
Exit  : 0 = below --fail-on threshold, 2 = threshold met, 1 = bad input.

Stdlib only so it runs anywhere Terraform does.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

SEVERITY_ORDER = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}

# Deleting or replacing these loses data or breaks consumers that can't be rebuilt from code.
STATEFUL_TYPES = {
    "aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance", "aws_dynamodb_table",
    "aws_s3_bucket", "aws_efs_file_system", "aws_ebs_volume", "aws_fsx_windows_file_system",
    "aws_fsx_lustre_file_system", "aws_elasticache_cluster", "aws_elasticache_replication_group",
    "aws_opensearch_domain", "aws_elasticsearch_domain", "aws_kms_key", "aws_secretsmanager_secret",
    "aws_cloudwatch_log_group", "aws_backup_vault", "aws_msk_cluster", "aws_redshift_cluster",
    "aws_docdb_cluster", "aws_neptune_cluster", "aws_ecr_repository",
    "azurerm_storage_account", "azurerm_mssql_database", "azurerm_mssql_server",
    "azurerm_postgresql_flexible_server", "azurerm_cosmosdb_account", "azurerm_key_vault",
    "google_sql_database_instance", "google_storage_bucket", "google_kms_crypto_key",
}

IAM_POLICY_ATTRS = {
    "aws_iam_policy": "policy",
    "aws_iam_role_policy": "policy",
    "aws_iam_user_policy": "policy",
    "aws_iam_group_policy": "policy",
}
IAM_ATTACHMENT_TYPES = {
    "aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
    "aws_iam_group_policy_attachment", "aws_iam_policy_attachment",
}
WORLD_CIDRS = {"0.0.0.0/0", "::/0"}
PUBLIC_WEB_PORTS = {80, 443}


@dataclass(frozen=True)
class Finding:
    severity: str
    address: str
    reason: str


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def classify_action(actions: list[str]) -> str:
    if actions in (["delete", "create"], ["create", "delete"]):
        return "replace"
    if actions == ["delete"]:
        return "delete"
    if actions == ["create"]:
        return "create"
    if actions == ["update"]:
        return "update"
    return "other"  # no-op, read, forget


def check_destructive(rc: dict, action: str) -> list[Finding]:
    if action not in ("delete", "replace"):
        return []
    rtype, addr = rc["type"], rc["address"]
    verb = "destroyed" if action == "delete" else "replaced (destroy + create)"
    if rtype in STATEFUL_TYPES:
        return [Finding("CRITICAL", addr, f"stateful resource {verb}; data loss unless backed up or intended")]
    return [Finding("MEDIUM", addr, f"resource {verb}")]


def _port_range_is_web_only(from_port, to_port) -> bool:
    try:
        lo, hi = int(from_port), int(to_port)
    except (TypeError, ValueError):
        return False
    return lo == hi and lo in PUBLIC_WEB_PORTS


def _world_ingress_finding(addr: str, cidrs: set[str], from_port, to_port, protocol) -> Finding | None:
    if not cidrs & WORLD_CIDRS:
        return None
    if str(protocol) == "-1":
        return Finding("HIGH", addr, "ingress from the internet on ALL ports/protocols")
    if _port_range_is_web_only(from_port, to_port):
        return Finding("MEDIUM", addr, f"ingress from the internet on port {from_port} (confirm this is a public endpoint)")
    return Finding("HIGH", addr, f"ingress from the internet on ports {from_port}-{to_port}")


def check_security_groups(rc: dict, after: dict) -> list[Finding]:
    rtype, addr, out = rc["type"], rc["address"], []
    if rtype == "aws_security_group":
        for rule in _as_list(after.get("ingress")):
            cidrs = set(_as_list(rule.get("cidr_blocks"))) | set(_as_list(rule.get("ipv6_cidr_blocks")))
            f = _world_ingress_finding(addr, cidrs, rule.get("from_port"), rule.get("to_port"), rule.get("protocol"))
            if f:
                out.append(f)
    elif rtype == "aws_security_group_rule" and after.get("type") == "ingress":
        cidrs = set(_as_list(after.get("cidr_blocks"))) | set(_as_list(after.get("ipv6_cidr_blocks")))
        f = _world_ingress_finding(addr, cidrs, after.get("from_port"), after.get("to_port"), after.get("protocol"))
        if f:
            out.append(f)
    elif rtype == "aws_vpc_security_group_ingress_rule":
        cidrs = {c for c in (after.get("cidr_ipv4"), after.get("cidr_ipv6")) if c}
        f = _world_ingress_finding(addr, cidrs, after.get("from_port"), after.get("to_port"), after.get("ip_protocol"))
        if f:
            out.append(f)
    return out


def check_iam(rc: dict, after: dict) -> list[Finding]:
    rtype, addr, out = rc["type"], rc["address"], []

    if rtype in IAM_ATTACHMENT_TYPES:
        arn = after.get("policy_arn") or ""
        if arn.endswith(":policy/AdministratorAccess"):
            out.append(Finding("HIGH", addr, "attaches AdministratorAccess"))
        return out

    attr = IAM_POLICY_ATTRS.get(rtype)
    raw = after.get(attr) if attr else None
    if not isinstance(raw, str):
        return out  # unknown until apply, or not an IAM policy resource
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return out

    for stmt in _as_list(doc.get("Statement")):
        if stmt.get("Effect") != "Allow":
            continue
        actions = _as_list(stmt.get("Action"))
        resources = _as_list(stmt.get("Resource"))
        if "*" in actions or "*:*" in actions:
            out.append(Finding("HIGH", addr, "IAM policy allows Action \"*\" (full admin)"))
        elif "*" in resources and any(a.endswith(":*") for a in actions):
            services = sorted({a.split(":")[0] for a in actions if a.endswith(":*")})
            out.append(Finding("MEDIUM", addr, f"service-wide wildcard on Resource \"*\": {', '.join(services)}"))
    return out


def check_data_exposure(rc: dict, after: dict) -> list[Finding]:
    rtype, addr = rc["type"], rc["address"]
    if rtype == "aws_s3_bucket_public_access_block":
        flags = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
        off = [f for f in flags if after.get(f) is False]
        if off:
            return [Finding("HIGH", addr, f"S3 public access block disabled: {', '.join(off)}")]
    if rtype == "aws_s3_bucket_acl" and after.get("acl") in ("public-read", "public-read-write"):
        return [Finding("HIGH", addr, f"S3 bucket ACL is {after['acl']}")]
    if rtype in ("aws_db_instance", "aws_rds_cluster") and after.get("storage_encrypted") is False:
        return [Finding("HIGH", addr, "database storage is not encrypted")]
    if rtype in ("aws_db_instance", "aws_rds_cluster_instance") and after.get("publicly_accessible") is True:
        return [Finding("HIGH", addr, "database is publicly accessible")]
    if rtype == "aws_ebs_volume" and after.get("encrypted") is False:
        return [Finding("MEDIUM", addr, "EBS volume is not encrypted")]
    return []


def analyze(plan: dict) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    counts = {"create": 0, "update": 0, "replace": 0, "delete": 0}

    for rc in plan.get("resource_changes", []):
        if rc.get("mode") == "data":
            continue
        change = rc.get("change", {})
        action = classify_action(change.get("actions", []))
        if action in counts:
            counts[action] += 1

        findings += check_destructive(rc, action)
        if action in ("create", "update", "replace"):
            after = change.get("after") or {}
            findings += check_security_groups(rc, after)
            findings += check_iam(rc, after)
            findings += check_data_exposure(rc, after)

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.address))
    return findings, counts


def render(findings: list[Finding], counts: dict[str, int]) -> str:
    lines = [
        "## Plan risk summary",
        "",
        f"**Actions:** {counts['create']} create · {counts['update']} update · "
        f"{counts['replace']} replace · {counts['delete']} delete",
        "",
    ]
    if not findings:
        lines.append("No risk findings.")
        return "\n".join(lines)

    by_sev = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    lines.append("**Findings:** " + " · ".join(f"{n} {s}" for s, n in by_sev.items() if n))
    lines += ["", "| Severity | Resource | Reason |", "|---|---|---|"]
    lines += [f"| {f.severity} | `{f.address}` | {f.reason} |" for f in findings]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("plan_json", help="output of `terraform show -json tfplan` ('-' for stdin)")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "none"], default="high",
                        help="exit 2 when any finding is at or above this severity (default: high)")
    args = parser.parse_args(argv)

    try:
        text = sys.stdin.read() if args.plan_json == "-" else Path(args.plan_json).read_text(encoding="utf-8")
        plan = json.loads(text)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read plan JSON: {exc}", file=sys.stderr)
        return 1
    if "resource_changes" not in plan and "format_version" not in plan:
        print("error: input does not look like `terraform show -json` plan output", file=sys.stderr)
        return 1

    findings, counts = analyze(plan)
    print(render(findings, counts))

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on.upper()]
    return 2 if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
