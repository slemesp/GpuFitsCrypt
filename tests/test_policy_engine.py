"""Tests for the policy engine (policy_engine.py)."""

from datetime import datetime

import pytest

from gpufitscrypt.policy_engine import (
    AccessRequest,
    Action,
    Effect,
    PolicyEngine,
    PolicyRule,
)


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def make_engine(*rules):
    e = PolicyEngine()
    for r in rules:
        e.add_rule(r)
    return e


def allow_rule(rule_id, actions, principals, resources, conditions=None):
    return PolicyRule(
        rule_id=rule_id,
        effect=Effect.ALLOW,
        actions=actions,
        principals=principals,
        resources=resources,
        conditions=conditions or {},
    )


def deny_rule(rule_id, actions, principals, resources, conditions=None):
    return PolicyRule(
        rule_id=rule_id,
        effect=Effect.DENY,
        actions=actions,
        principals=principals,
        resources=resources,
        conditions=conditions or {},
    )


# ---------------------------------------------------------------------------
# Basic allow / deny
# ---------------------------------------------------------------------------

class TestPolicyEngineBasics:
    def test_implicit_deny_no_rules(self):
        engine = PolicyEngine()
        req = AccessRequest("user:alice", Action.READ, "fits:cat.fits")
        assert not engine.is_allowed(req)

    def test_explicit_allow(self):
        engine = make_engine(allow_rule("r1", [Action.READ], ["user:alice"], ["fits:cat.fits"]))
        req = AccessRequest("user:alice", Action.READ, "fits:cat.fits")
        assert engine.is_allowed(req)

    def test_allow_does_not_grant_other_action(self):
        engine = make_engine(allow_rule("r1", [Action.READ], ["user:alice"], ["fits:cat.fits"]))
        req = AccessRequest("user:alice", Action.DECRYPT, "fits:cat.fits")
        assert not engine.is_allowed(req)

    def test_allow_does_not_grant_other_principal(self):
        engine = make_engine(allow_rule("r1", [Action.READ], ["user:alice"], ["fits:cat.fits"]))
        req = AccessRequest("user:bob", Action.READ, "fits:cat.fits")
        assert not engine.is_allowed(req)

    def test_deny_overrides_allow(self):
        engine = make_engine(
            allow_rule("allow-all", [Action.READ], ["*"], ["*"]),
            deny_rule("deny-bob", [Action.READ], ["user:bob"], ["*"]),
        )
        assert engine.is_allowed(AccessRequest("user:alice", Action.READ, "fits:data.fits"))
        assert not engine.is_allowed(AccessRequest("user:bob", Action.READ, "fits:data.fits"))

    def test_explicit_deny_alone(self):
        engine = make_engine(deny_rule("d1", [Action.DECRYPT], ["user:eve"], ["fits:*"]))
        req = AccessRequest("user:eve", Action.DECRYPT, "fits:secret.fits")
        assert not engine.is_allowed(req)

    def test_evaluate_returns_reason(self):
        engine = make_engine(allow_rule("r1", [Action.READ], ["user:alice"], ["fits:*"]))
        allowed, reason = engine.evaluate(AccessRequest("user:alice", Action.READ, "fits:x.fits"))
        assert allowed
        assert "r1" in reason

    def test_evaluate_deny_reason(self):
        engine = make_engine(deny_rule("d1", [Action.READ], ["user:bob"], ["fits:*"]))
        allowed, reason = engine.evaluate(AccessRequest("user:bob", Action.READ, "fits:x.fits"))
        assert not allowed
        assert "d1" in reason


# ---------------------------------------------------------------------------
# Principal matching
# ---------------------------------------------------------------------------

class TestPrincipalMatching:
    def test_wildcard_principal(self):
        engine = make_engine(allow_rule("r1", [Action.READ], ["*"], ["fits:*"]))
        for p in ["user:alice", "user:bob", "role:researcher", "service:etl"]:
            assert engine.is_allowed(AccessRequest(p, Action.READ, "fits:any.fits"))

    def test_role_principal(self):
        engine = make_engine(allow_rule("r1", [Action.DECRYPT], ["role:researcher"], ["fits:*"]))
        assert engine.is_allowed(AccessRequest("role:researcher", Action.DECRYPT, "fits:a.fits"))
        assert not engine.is_allowed(AccessRequest("user:alice", Action.DECRYPT, "fits:a.fits"))


# ---------------------------------------------------------------------------
# Resource pattern matching
# ---------------------------------------------------------------------------

class TestResourceMatching:
    def test_exact_match(self):
        engine = make_engine(allow_rule("r1", [Action.READ], ["*"], ["fits:exact.fits"]))
        assert engine.is_allowed(AccessRequest("user:x", Action.READ, "fits:exact.fits"))
        assert not engine.is_allowed(AccessRequest("user:x", Action.READ, "fits:other.fits"))

    def test_wildcard_extension(self):
        engine = make_engine(allow_rule("r1", [Action.READ], ["*"], ["fits:survey/*.fits"]))
        assert engine.is_allowed(AccessRequest("user:x", Action.READ, "fits:survey/dr1.fits"))
        assert not engine.is_allowed(AccessRequest("user:x", Action.READ, "fits:archive/dr1.fits"))

    def test_global_wildcard(self):
        engine = make_engine(allow_rule("r1", [Action.READ], ["*"], ["*"]))
        assert engine.is_allowed(AccessRequest("user:x", Action.READ, "anything"))


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

class TestConditions:
    def test_embargo_before_condition_passes(self):
        engine = make_engine(allow_rule(
            "r1", [Action.READ], ["*"], ["fits:*"],
            conditions={"time": {"before": "2099-01-01"}},
        ))
        req = AccessRequest("user:x", Action.READ, "fits:a.fits",
                            context={"time": datetime(2025, 6, 1)})
        assert engine.is_allowed(req)

    def test_embargo_before_condition_fails(self):
        engine = make_engine(allow_rule(
            "r1", [Action.READ], ["*"], ["fits:*"],
            conditions={"time": {"before": "2020-01-01"}},
        ))
        req = AccessRequest("user:x", Action.READ, "fits:a.fits",
                            context={"time": datetime(2025, 6, 1)})
        assert not engine.is_allowed(req)

    def test_after_condition(self):
        engine = make_engine(allow_rule(
            "r1", [Action.READ], ["*"], ["fits:*"],
            conditions={"time": {"after": "2020-01-01"}},
        ))
        req = AccessRequest("user:x", Action.READ, "fits:a.fits",
                            context={"time": datetime(2025, 6, 1)})
        assert engine.is_allowed(req)

    def test_missing_context_key_fails(self):
        engine = make_engine(allow_rule(
            "r1", [Action.READ], ["*"], ["fits:*"],
            conditions={"clearance_level": 3},
        ))
        req = AccessRequest("user:x", Action.READ, "fits:a.fits")
        assert not engine.is_allowed(req)

    def test_exact_value_condition(self):
        engine = make_engine(allow_rule(
            "r1", [Action.READ], ["*"], ["fits:*"],
            conditions={"team": "survey-team-a"},
        ))
        assert engine.is_allowed(
            AccessRequest("user:x", Action.READ, "fits:a.fits", {"team": "survey-team-a"})
        )
        assert not engine.is_allowed(
            AccessRequest("user:x", Action.READ, "fits:a.fits", {"team": "survey-team-b"})
        )


# ---------------------------------------------------------------------------
# Rule management (add / remove / list)
# ---------------------------------------------------------------------------

class TestRuleManagement:
    def test_add_and_remove_rule(self):
        engine = PolicyEngine()
        rule = allow_rule("r1", [Action.READ], ["user:alice"], ["fits:*"])
        engine.add_rule(rule)
        assert engine.is_allowed(AccessRequest("user:alice", Action.READ, "fits:x.fits"))
        engine.remove_rule("r1")
        assert not engine.is_allowed(AccessRequest("user:alice", Action.READ, "fits:x.fits"))

    def test_list_rules(self):
        engine = PolicyEngine()
        r1 = allow_rule("r1", [Action.READ], ["*"], ["*"])
        r2 = deny_rule("r2", [Action.WRITE], ["user:guest"], ["*"])
        engine.add_rule(r1)
        engine.add_rule(r2)
        rules = engine.list_rules()
        assert len(rules) == 2
        ids = {r.rule_id for r in rules}
        assert ids == {"r1", "r2"}

    def test_remove_nonexistent_rule_is_noop(self):
        engine = make_engine(allow_rule("r1", [Action.READ], ["*"], ["*"]))
        engine.remove_rule("does-not-exist")
        assert engine.is_allowed(AccessRequest("user:x", Action.READ, "fits:a.fits"))
