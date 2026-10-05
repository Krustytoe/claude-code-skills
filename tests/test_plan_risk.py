import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "plugins/sre-toolkit/skills/terraform-change-review/scripts/plan_risk.py"
spec = importlib.util.spec_from_file_location("plan_risk", SCRIPT)
plan_risk = importlib.util.module_from_spec(spec)
sys.modules["plan_risk"] = plan_risk  # dataclasses resolve string annotations via sys.modules
spec.loader.exec_module(plan_risk)


def rc(address, actions, after=None, mode="managed"):
    rtype = address.split(".")[-2] if address.count(".") > 1 else address.split(".")[0]
    return {"address": address, "mode": mode, "type": rtype, "change": {"actions": actions, "after": after}}


def plan(*changes):
    return {"format_version": "1.2", "resource_changes": list(changes)}


def severities(p):
    findings, _ = plan_risk.analyze(p)
    return {(f.severity, f.address) for f in findings}


def test_replacing_stateful_resource_is_critical():
    p = plan(rc("aws_db_instance.main", ["delete", "create"], {"storage_encrypted": True}))
    assert severities(p) == {("CRITICAL", "aws_db_instance.main")}


def test_create_before_destroy_replace_also_detected():
    p = plan(rc("aws_s3_bucket.logs", ["create", "delete"], {}))
    assert ("CRITICAL", "aws_s3_bucket.logs") in severities(p)


def test_deleting_stateless_resource_is_medium():
    p = plan(rc("aws_iam_role.old", ["delete"], None))
    assert severities(p) == {("MEDIUM", "aws_iam_role.old")}


def test_noop_and_data_sources_ignored():
    p = plan(
        rc("aws_db_instance.main", ["no-op"], {}),
        rc("data.aws_iam_policy_document.x", ["read"], {}, mode="data"),
    )
    assert severities(p) == set()


@pytest.mark.parametrize(
    "rule, expected",
    [
        ({"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22, "protocol": "tcp"}, "HIGH"),
        ({"cidr_blocks": ["0.0.0.0/0"], "from_port": 443, "to_port": 443, "protocol": "tcp"}, "MEDIUM"),
        ({"cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"], "from_port": 0, "to_port": 0, "protocol": "-1"}, "HIGH"),
        ({"cidr_blocks": ["10.0.0.0/8"], "from_port": 22, "to_port": 22, "protocol": "tcp"}, None),
    ],
)
def test_security_group_inline_ingress(rule, expected):
    p = plan(rc("aws_security_group.web", ["create"], {"ingress": [rule]}))
    got = severities(p)
    assert got == ({(expected, "aws_security_group.web")} if expected else set())


def test_vpc_security_group_ingress_rule_resource():
    p = plan(rc("aws_vpc_security_group_ingress_rule.rdp", ["create"],
                {"cidr_ipv4": "0.0.0.0/0", "from_port": 3389, "to_port": 3389, "ip_protocol": "tcp"}))
    assert severities(p) == {("HIGH", "aws_vpc_security_group_ingress_rule.rdp")}


def test_iam_full_admin_is_high_and_service_wildcard_is_medium():
    admin = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    s3_all = json.dumps({"Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]})
    deny_all = json.dumps({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
    p = plan(
        rc("aws_iam_policy.admin", ["create"], {"policy": admin}),
        rc("aws_iam_role_policy.s3", ["update"], {"policy": s3_all}),
        rc("aws_iam_policy.guardrail", ["create"], {"policy": deny_all}),
    )
    assert severities(p) == {("HIGH", "aws_iam_policy.admin"), ("MEDIUM", "aws_iam_role_policy.s3")}


def test_unknown_policy_is_skipped_not_crashed():
    p = plan(rc("aws_iam_policy.later", ["create"], {"policy": None}))
    assert severities(p) == set()


def test_admin_attachment_any_partition():
    p = plan(rc("aws_iam_role_policy_attachment.ci", ["create"],
                {"policy_arn": "arn:aws-us-gov:iam::aws:policy/AdministratorAccess"}))
    assert severities(p) == {("HIGH", "aws_iam_role_policy_attachment.ci")}


def test_public_s3_and_unencrypted_db():
    p = plan(
        rc("aws_s3_bucket_public_access_block.b", ["update"],
           {"block_public_acls": True, "block_public_policy": False, "ignore_public_acls": True, "restrict_public_buckets": True}),
        rc("aws_db_instance.reporting", ["create"], {"storage_encrypted": False, "publicly_accessible": False}),
    )
    assert severities(p) == {("HIGH", "aws_s3_bucket_public_access_block.b"), ("HIGH", "aws_db_instance.reporting")}


def test_module_addresses_resolve_type():
    p = plan({"address": "module.data.aws_rds_cluster.this", "mode": "managed", "type": "aws_rds_cluster",
              "change": {"actions": ["delete"], "after": None}})
    assert severities(p) == {("CRITICAL", "module.data.aws_rds_cluster.this")}


def test_counts_and_render():
    p = plan(
        rc("aws_vpc.a", ["create"], {}),
        rc("aws_vpc.b", ["update"], {}),
        rc("aws_s3_bucket.c", ["delete", "create"], {}),
        rc("aws_iam_role.d", ["delete"], None),
    )
    findings, counts = plan_risk.analyze(p)
    assert counts == {"create": 1, "update": 1, "replace": 1, "delete": 1}
    out = plan_risk.render(findings, counts)
    assert "1 CRITICAL" in out and "`aws_s3_bucket.c`" in out
    # CRITICAL rows sort first
    assert out.index("CRITICAL |") < out.index("MEDIUM |")


def test_output_never_contains_attribute_values(capsys, tmp_path):
    secret = "hunter2-super-secret"
    p = plan(rc("aws_db_instance.main", ["delete", "create"], {"password": secret, "storage_encrypted": False}))
    f = tmp_path / "plan.json"
    f.write_text(json.dumps(p))
    plan_risk.main([str(f), "--fail-on", "none"])
    assert secret not in capsys.readouterr().out


@pytest.mark.parametrize("fail_on, expected_rc", [("critical", 0), ("high", 2), ("medium", 2), ("none", 0)])
def test_exit_codes(tmp_path, fail_on, expected_rc):
    admin = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    f = tmp_path / "plan.json"
    f.write_text(json.dumps(plan(rc("aws_iam_policy.admin", ["create"], {"policy": admin}))))
    assert plan_risk.main([str(f), "--fail-on", fail_on]) == expected_rc


def test_rejects_non_plan_input(tmp_path):
    f = tmp_path / "state.json"
    f.write_text(json.dumps({"version": 4, "resources": []}))
    assert plan_risk.main([str(f)]) == 1
