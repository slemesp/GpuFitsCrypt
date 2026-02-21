"""Fine-grained policy engine for access control to astronomical data.

Policies are composed of :class:`PolicyRule` objects, each specifying:
  - *principals*: users or roles the rule applies to (e.g. ``"user:alice"``,
    ``"role:researcher"``, or ``"*"`` for any principal).
  - *resources*: glob-style resource patterns (e.g. ``"fits:survey/*.fits"``).
  - *actions*: the operations the rule governs.
  - *conditions*: optional key/value constraints evaluated against the
    request *context* (e.g. embargo dates).
  - *effect*: ``ALLOW`` or ``DENY``.  **DENY rules always take precedence.**

Example usage::

    engine = PolicyEngine()
    engine.add_rule(PolicyRule(
        rule_id="allow-researchers",
        effect=Effect.ALLOW,
        actions=[Action.READ, Action.DECRYPT],
        principals=["role:researcher"],
        resources=["fits:*"],
    ))
    request = AccessRequest(
        principal="role:researcher",
        action=Action.DECRYPT,
        resource="fits:survey2025.fits",
    )
    allowed, reason = engine.evaluate(request)
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Action(Enum):
    """Operations that can be granted or denied by a policy rule."""

    READ = "read"
    WRITE = "write"
    DECRYPT = "decrypt"
    ENCRYPT = "encrypt"
    ADMIN = "admin"


class Effect(Enum):
    """Whether a matching rule permits or forbids the requested action."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass
class PolicyRule:
    """A single access-control rule.

    Attributes:
        rule_id:    Unique identifier used for auditing and removal.
        effect:     :attr:`Effect.ALLOW` or :attr:`Effect.DENY`.
        actions:    Set of :class:`Action` values this rule governs.
        principals: Principals the rule applies to.  Supported formats:
                    ``"*"`` (any), ``"user:<name>"``, ``"role:<name>"``.
        resources:  Glob-style resource patterns.  ``"*"`` matches anything;
                    ``"fits:survey/*.fits"`` uses ``*`` and ``?`` wildcards.
        conditions: Optional mapping of context keys to required values.
                    Supports ``{"before": "<iso-date>"}`` and
                    ``{"after": "<iso-date>"}`` for temporal constraints.
    """

    rule_id: str
    effect: Effect
    actions: list
    principals: list
    resources: list
    conditions: dict = field(default_factory=dict)

    def matches_principal(self, principal: str) -> bool:
        """Return True if *principal* is covered by this rule."""
        for p in self.principals:
            if p in ("*", principal):
                return True
        return False

    def matches_resource(self, resource: str) -> bool:
        """Return True if *resource* matches any of the rule's patterns."""
        for pattern in self.resources:
            if pattern == "*":
                return True
            regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
            if re.fullmatch(regex, resource):
                return True
        return False

    def matches_action(self, action: Action) -> bool:
        """Return True if *action* is covered by this rule."""
        return action in self.actions

    def evaluate_conditions(self, context: dict) -> bool:
        """Return True if all conditions are satisfied by *context*.

        Supported condition formats:
          - ``{"before": "<iso-datetime>"}`` – context value must be earlier.
          - ``{"after": "<iso-datetime>"}`` – context value must be later.
          - Any other value: context value must equal the condition value.
        """
        for key, constraint in self.conditions.items():
            ctx_value = context.get(key)
            if ctx_value is None:
                return False
            if isinstance(constraint, dict):
                if "before" in constraint:
                    threshold = datetime.fromisoformat(constraint["before"])
                    if ctx_value >= threshold:
                        return False
                if "after" in constraint:
                    threshold = datetime.fromisoformat(constraint["after"])
                    if ctx_value <= threshold:
                        return False
            elif ctx_value != constraint:
                return False
        return True


@dataclass
class AccessRequest:
    """An access request to be evaluated against the policy engine.

    Attributes:
        principal: The entity making the request (e.g. ``"user:alice"``).
        action:    The requested :class:`Action`.
        resource:  The target resource identifier (e.g. ``"fits:cat.fits"``).
        context:   Arbitrary key/value pairs for condition evaluation,
                   such as ``{"time": datetime.now()}``.
    """

    principal: str
    action: Action
    resource: str
    context: dict = field(default_factory=dict)


class PolicyEngine:
    """Evaluate access requests against a set of :class:`PolicyRule` objects.

    DENY rules always take precedence over ALLOW rules.  If no rule
    matches, the request is implicitly denied.
    """

    def __init__(self) -> None:
        self._rules: list = []

    def add_rule(self, rule: PolicyRule) -> None:
        """Append *rule* to the policy set."""
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> None:
        """Remove the rule with the given *rule_id* (no-op if not found)."""
        self._rules = [r for r in self._rules if r.rule_id != rule_id]

    def list_rules(self) -> list:
        """Return a copy of the current rule list."""
        return list(self._rules)

    def evaluate(self, request: AccessRequest) -> tuple:
        """Evaluate *request* and return ``(is_allowed, reason)``.

        DENY rules are collected first.  If any DENY rule matches, the
        request is refused regardless of ALLOW rules.

        Args:
            request: The :class:`AccessRequest` to evaluate.

        Returns:
            A ``(bool, str)`` tuple – ``(True, reason)`` if allowed,
            ``(False, reason)`` otherwise.
        """
        allow_reasons = []
        deny_reasons = []

        for rule in self._rules:
            if (
                rule.matches_principal(request.principal)
                and rule.matches_resource(request.resource)
                and rule.matches_action(request.action)
                and rule.evaluate_conditions(request.context)
            ):
                if rule.effect == Effect.DENY:
                    deny_reasons.append(f"Denied by rule '{rule.rule_id}'")
                else:
                    allow_reasons.append(f"Allowed by rule '{rule.rule_id}'")

        if deny_reasons:
            return False, "; ".join(deny_reasons)
        if allow_reasons:
            return True, allow_reasons[0]
        return False, "No matching allow rule found"

    def is_allowed(self, request: AccessRequest) -> bool:
        """Convenience wrapper – return True only if the request is allowed."""
        allowed, _ = self.evaluate(request)
        return allowed
