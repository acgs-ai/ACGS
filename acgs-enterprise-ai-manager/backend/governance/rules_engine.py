"""
Rule-Based Validation Engine
Implements pattern matching and validation logic for governance rules.
"""

import re
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.utils.timeutil import utcnow
import yaml

logger = logging.getLogger(__name__)


class RulesEngine:
    """
    Rule-based validation engine for governance framework.

    Validates operations against constitutional rules with pattern matching,
    severity levels, and action enforcement.
    """

    def __init__(self, constitution_path: str):
        """
        Initialize rules engine with constitution file.

        Args:
            constitution_path: Path to YAML constitution file
        """
        self.constitution_path = constitution_path
        self.rules: List[Dict[str, Any]] = []
        self.enforcement_config: Dict[str, Any] = {}
        self.audit_config: Dict[str, Any] = {}

        self._load_constitution()

    def _load_constitution(self):
        """Load and parse constitution YAML file."""
        try:
            with open(self.constitution_path, "r") as f:
                constitution = yaml.safe_load(f)

            self.rules = constitution.get("rules", [])
            self.enforcement_config = constitution.get("enforcement", {})
            self.audit_config = constitution.get("audit", {})

            # Compile regex patterns for efficiency
            for rule in self.rules:
                if "pattern" in rule:
                    try:
                        rule["_compiled_pattern"] = re.compile(
                            rule["pattern"], re.IGNORECASE
                        )
                    except re.error as e:
                        logger.error(f"Invalid regex in rule {rule.get('id')}: {e}")
                        rule["_compiled_pattern"] = None

            logger.info(f"Loaded {len(self.rules)} governance rules")

        except FileNotFoundError:
            logger.error(f"Constitution file not found: {self.constitution_path}")
            self.rules = []
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse constitution YAML: {e}")
            self.rules = []
        except Exception as e:
            logger.error(f"Error loading constitution: {e}")
            self.rules = []

    def validate(self, operation: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate an operation against all governance rules.

        Args:
            operation: Description of the operation to validate
            context: Additional context for validation

        Returns:
            Dict containing validation result:
                - valid: bool
                - violations: List[Dict]
                - requires_approval: bool
                - matched_rules: List[str]
        """
        violations = []
        matched_rules = []
        requires_approval = False

        # Check each rule
        for rule in self.rules:
            match_result = self._check_rule(rule, operation, context)

            if match_result["matched"]:
                matched_rules.append(rule["id"])

                action = rule.get("action", "BLOCK")
                severity = rule.get("severity", "MEDIUM")

                if action == "BLOCK":
                    violations.append(
                        {
                            "rule_id": rule["id"],
                            "severity": severity,
                            "description": rule.get("description", "Rule violation"),
                            "pattern": rule.get("pattern", ""),
                            "action": action,
                        }
                    )
                elif action == "REQUIRE_APPROVAL":
                    requires_approval = True
                    violations.append(
                        {
                            "rule_id": rule["id"],
                            "severity": severity,
                            "description": rule.get("description", "Approval required"),
                            "pattern": rule.get("pattern", ""),
                            "action": action,
                        }
                    )
                elif action == "VALIDATE":
                    # Perform additional validation checks
                    validation_result = self._perform_validation(
                        rule, operation, context
                    )
                    if not validation_result["valid"]:
                        violations.append(
                            {
                                "rule_id": rule["id"],
                                "severity": severity,
                                "description": validation_result["reason"],
                                "action": "BLOCK",
                            }
                        )

        # Determine overall validity
        # Operation is valid if no blocking violations
        blocking_violations = [v for v in violations if v["action"] == "BLOCK"]

        valid = len(blocking_violations) == 0

        return {
            "valid": valid,
            "violations": violations,
            "requires_approval": requires_approval,
            "matched_rules": matched_rules,
            "timestamp": utcnow().isoformat(),
        }

    def _check_rule(
        self, rule: Dict[str, Any], operation: str, context: Dict[str, Any]
    ) -> Dict[str, bool]:
        """
        Check if a rule matches the operation.

        Args:
            rule: Rule definition
            operation: Operation to check
            context: Additional context

        Returns:
            Dict with 'matched' boolean
        """
        # Pattern matching against the route operation plus bounded request context text.
        if "_compiled_pattern" in rule and rule["_compiled_pattern"]:
            operation_text = f"{operation} {context.get('operation_text', '')}"
            if rule["_compiled_pattern"].search(operation_text):
                return {"matched": True}

        # Context-based matching
        if "context_key" in rule:
            context_value = context.get(rule["context_key"])
            if context_value and rule.get("context_pattern"):
                try:
                    pattern = re.compile(rule["context_pattern"], re.IGNORECASE)
                    if pattern.search(str(context_value)):
                        return {"matched": True}
                except re.error:
                    pass

        return {"matched": False}

    def _perform_validation(
        self, rule: Dict[str, Any], operation: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Perform validation checks defined in rule.

        Args:
            rule: Rule with validation configuration
            operation: Operation being validated
            context: Additional context

        Returns:
            Dict with 'valid' boolean and 'reason' string
        """
        validation_config = rule.get("validation", {})

        # Check confidence threshold
        if "min_confidence" in validation_config:
            confidence = context.get("confidence", 0.0)
            min_confidence = validation_config["min_confidence"]
            if confidence < min_confidence:
                return {
                    "valid": False,
                    "reason": f"Confidence {confidence} below threshold {min_confidence}",
                }

        # Check amount limits
        if "max_amount" in validation_config:
            amount = context.get("amount", 0)
            max_amount = validation_config["max_amount"]
            if amount > max_amount:
                return {
                    "valid": False,
                    "reason": f"Amount {amount} exceeds limit {max_amount}",
                }

        # Check batch size limits
        if "max_batch_size" in validation_config:
            batch_size = context.get("batch_size", 0)
            max_batch_size = validation_config["max_batch_size"]
            if batch_size > max_batch_size:
                return {
                    "valid": False,
                    "reason": f"Batch size {batch_size} exceeds limit {max_batch_size}",
                }

        # Check retention policy
        if "min_retention_days" in validation_config:
            retention_days = context.get("retention_days", 0)
            min_retention = validation_config["min_retention_days"]
            if retention_days < min_retention:
                return {
                    "valid": False,
                    "reason": f"Retention {retention_days} days below minimum {min_retention}",
                }

        return {"valid": True, "reason": "Validation passed"}

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get rule by ID.

        Args:
            rule_id: Rule identifier

        Returns:
            Rule dict or None if not found
        """
        for rule in self.rules:
            if rule.get("id") == rule_id:
                return rule
        return None

    def get_rules_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Get all rules with specified severity.

        Args:
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            List of matching rules
        """
        return [rule for rule in self.rules if rule.get("severity") == severity]

    def reload_constitution(self):
        """Reload constitution from file."""
        self._load_constitution()
        logger.info("Constitution reloaded")
