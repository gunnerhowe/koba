"""
Advanced Policy Engine Extensions for Koba

Provides enhanced policy matching beyond simple glob patterns:
- Regex pattern matching for tool names
- Semantic tool matching (understanding that "db.write" and "database.insert" are similar)
- Parameter validation rules
- Context-aware policies (session history)
- Policy conflict detection
- Anomaly-based policy triggers
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
from datetime import datetime, timezone, timedelta

from vacp.core.policy import (
    PolicyDecision,
    PolicyRule,
    PolicyBundle,
    PolicyEvaluationContext,
    PolicyEvaluationResult,
    PolicyEngine,
)


class PatternType(Enum):
    """Extended pattern matching types."""
    GLOB = "glob"           # Standard glob (fnmatch)
    REGEX = "regex"         # Full regex
    EXACT = "exact"         # Exact match
    SEMANTIC = "semantic"   # Semantic similarity
    CATEGORY = "category"   # Category-based matching


# Semantic tool categories - tools that have similar purposes
TOOL_CATEGORIES = {
    "read_data": {
        "patterns": ["*.read", "*.get", "*.fetch", "*.query", "*.select", "*.list", "*.view"],
        "similar_tools": ["database.read", "db.query", "storage.get", "api.fetch", "data.retrieve"],
        "keywords": ["read", "get", "fetch", "query", "select", "retrieve", "view", "list"],
    },
    "write_data": {
        "patterns": ["*.write", "*.set", "*.put", "*.insert", "*.create", "*.add"],
        "similar_tools": ["database.write", "db.insert", "storage.put", "data.create"],
        "keywords": ["write", "set", "put", "insert", "create", "add", "store", "save"],
    },
    "modify_data": {
        "patterns": ["*.update", "*.modify", "*.change", "*.edit", "*.patch"],
        "similar_tools": ["database.update", "db.modify", "record.edit"],
        "keywords": ["update", "modify", "change", "edit", "patch", "alter", "revise"],
    },
    "delete_data": {
        "patterns": ["*.delete", "*.remove", "*.drop", "*.truncate", "*.destroy", "*.purge"],
        "similar_tools": ["database.delete", "db.drop", "storage.remove", "data.destroy"],
        "keywords": ["delete", "remove", "drop", "truncate", "destroy", "purge", "erase"],
    },
    "execute_code": {
        "patterns": ["*.exec", "*.execute", "*.run", "*.eval", "*.shell"],
        "similar_tools": ["system.exec", "code.run", "script.execute", "command.shell"],
        "keywords": ["exec", "execute", "run", "eval", "shell", "system", "command"],
    },
    "network_access": {
        "patterns": ["*.connect", "*.request", "*.call", "http.*", "https.*", "api.*"],
        "similar_tools": ["network.connect", "http.request", "api.call", "web.fetch"],
        "keywords": ["connect", "request", "http", "https", "api", "network", "web", "url"],
    },
    "file_access": {
        "patterns": ["file.*", "fs.*", "filesystem.*", "*.read_file", "*.write_file"],
        "similar_tools": ["file.read", "file.write", "fs.open", "filesystem.access"],
        "keywords": ["file", "fs", "filesystem", "path", "directory", "folder"],
    },
    "authentication": {
        "patterns": ["auth.*", "*.login", "*.logout", "*.authenticate", "credential.*"],
        "similar_tools": ["auth.login", "user.authenticate", "session.create"],
        "keywords": ["auth", "login", "logout", "authenticate", "credential", "password", "token"],
    },
    "privilege_escalation": {
        "patterns": ["*.sudo", "*.admin", "*.root", "*.elevate", "privilege.*"],
        "similar_tools": ["system.sudo", "user.elevate", "privilege.escalate"],
        "keywords": ["sudo", "admin", "root", "elevate", "privilege", "escalate", "superuser"],
    },
    "self_modification": {
        "patterns": ["self.*", "*.self_*", "agent.*", "capability.*"],
        "similar_tools": ["self.modify", "agent.upgrade", "capability.add"],
        "keywords": ["self", "agent", "capability", "modify", "upgrade", "enhance", "improve"],
    },
}


@dataclass
class SemanticPattern:
    """A semantic pattern that matches tools based on meaning, not just string."""
    pattern: str
    pattern_type: PatternType = PatternType.GLOB
    category: Optional[str] = None  # For category-based matching
    keywords: List[str] = field(default_factory=list)  # For keyword-based semantic matching
    similarity_threshold: float = 0.7  # For semantic matching

    def matches(self, tool_name: str) -> Tuple[bool, float]:
        """
        Check if tool matches this pattern.

        Returns (matches, confidence) where confidence is 0.0-1.0
        """
        tool_lower = tool_name.lower()

        if self.pattern_type == PatternType.EXACT:
            if tool_name == self.pattern:
                return True, 1.0
            return False, 0.0

        elif self.pattern_type == PatternType.GLOB:
            import fnmatch
            if fnmatch.fnmatch(tool_name, self.pattern):
                return True, 0.95
            return False, 0.0

        elif self.pattern_type == PatternType.REGEX:
            try:
                if re.match(self.pattern, tool_name):
                    return True, 0.95
            except re.error:
                pass
            return False, 0.0

        elif self.pattern_type == PatternType.CATEGORY:
            if self.category and self.category in TOOL_CATEGORIES:
                cat = TOOL_CATEGORIES[self.category]
                # Check patterns
                import fnmatch
                for p in cat["patterns"]:
                    if fnmatch.fnmatch(tool_name, p):
                        return True, 0.9

                # Check similar tools
                if tool_name in cat["similar_tools"]:
                    return True, 0.95

                # Check keywords in tool name
                keyword_matches = sum(1 for kw in cat["keywords"] if kw in tool_lower)
                if keyword_matches > 0:
                    confidence = min(0.85, 0.5 + keyword_matches * 0.15)
                    return True, confidence

            return False, 0.0

        elif self.pattern_type == PatternType.SEMANTIC:
            # Keyword-based semantic matching
            if self.keywords:
                tool_parts = set(re.split(r'[._\-]', tool_lower))
                keyword_set = set(kw.lower() for kw in self.keywords)
                overlap = tool_parts & keyword_set

                if overlap:
                    confidence = len(overlap) / max(len(keyword_set), len(tool_parts))
                    if confidence >= self.similarity_threshold:
                        return True, confidence

            return False, 0.0

        return False, 0.0


@dataclass
class ParameterRule:
    """
    Rule for validating tool parameters.

    This catches attacks where the tool name is allowed but parameters are malicious.
    """
    name: str
    parameter_name: str
    validation_type: str  # "regex", "whitelist", "blacklist", "range", "type"
    validation_value: Any  # Pattern, list, or range depending on type
    error_message: str = "Parameter validation failed"
    applies_to_tools: List[str] = field(default_factory=list)  # Empty = all tools

    def validate(self, tool_name: str, parameters: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validate parameters against this rule.

        Returns (is_valid, error_message)
        """
        # Check if rule applies to this tool
        if self.applies_to_tools:
            import fnmatch
            if not any(fnmatch.fnmatch(tool_name, p) for p in self.applies_to_tools):
                return True, None  # Rule doesn't apply

        # Get parameter value
        value = parameters.get(self.parameter_name)
        if value is None:
            return True, None  # Parameter not present

        # Validate based on type
        if self.validation_type == "regex":
            if isinstance(value, str):
                if not re.match(self.validation_value, value):
                    return False, f"{self.error_message}: {self.parameter_name} doesn't match pattern"
            return True, None

        elif self.validation_type == "whitelist":
            if value not in self.validation_value:
                return False, f"{self.error_message}: {self.parameter_name} not in whitelist"
            return True, None

        elif self.validation_type == "blacklist":
            if value in self.validation_value:
                return False, f"{self.error_message}: {self.parameter_name} is blacklisted"
            return True, None

        elif self.validation_type == "range":
            if isinstance(value, (int, float)):
                min_val, max_val = self.validation_value
                if not (min_val <= value <= max_val):
                    return False, f"{self.error_message}: {self.parameter_name} out of range [{min_val}, {max_val}]"
            return True, None

        elif self.validation_type == "type":
            expected_type = self.validation_value
            if expected_type == "string" and not isinstance(value, str):
                return False, f"{self.error_message}: {self.parameter_name} must be string"
            elif expected_type == "number" and not isinstance(value, (int, float)):
                return False, f"{self.error_message}: {self.parameter_name} must be number"
            elif expected_type == "boolean" and not isinstance(value, bool):
                return False, f"{self.error_message}: {self.parameter_name} must be boolean"
            elif expected_type == "array" and not isinstance(value, list):
                return False, f"{self.error_message}: {self.parameter_name} must be array"
            return True, None

        elif self.validation_type == "max_length":
            if isinstance(value, str) and len(value) > self.validation_value:
                return False, f"{self.error_message}: {self.parameter_name} exceeds max length {self.validation_value}"
            return True, None

        elif self.validation_type == "no_injection":
            # Check for common injection patterns
            if isinstance(value, str):
                injection_patterns = [
                    r";\s*--",           # SQL comment
                    r"'\s*OR\s+'",       # SQL OR injection
                    r"<script",          # XSS
                    r"javascript:",      # XSS
                    r"\$\{.*\}",         # Template injection
                    r"__import__",       # Python code injection
                    r"eval\s*\(",        # Code execution
                    r"exec\s*\(",        # Code execution
                ]
                for pattern in injection_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        return False, f"{self.error_message}: {self.parameter_name} contains injection pattern"
            return True, None

        return True, None


@dataclass
class ContextPolicy:
    """
    Context-aware policy that considers session history.

    This catches patterns like:
    - Agent rapidly escalating requests
    - Agent probing for weak points
    - Unusual sequence of operations
    """
    name: str
    trigger_condition: str  # "sequence", "frequency", "escalation", "pattern"
    config: Dict[str, Any] = field(default_factory=dict)
    action: PolicyDecision = PolicyDecision.DENY
    cooldown_seconds: int = 60

    def evaluate(
        self,
        context: PolicyEvaluationContext,
        session_history: List[Dict],
    ) -> Tuple[bool, Optional[str]]:
        """
        Evaluate context-based policy.

        Returns (triggered, reason)
        """
        if self.trigger_condition == "sequence":
            # Check for specific sequence of tools
            required_sequence = self.config.get("sequence", [])
            if len(session_history) >= len(required_sequence):
                recent = [h.get("tool_name", "") for h in session_history[-len(required_sequence):]]
                if all(
                    any(re.match(p, t) for t in recent)
                    for p in required_sequence
                ):
                    return True, f"Suspicious sequence detected: {required_sequence}"
            return False, None

        elif self.trigger_condition == "frequency":
            # Check for high frequency of specific tool
            window_seconds = self.config.get("window_seconds", 60)
            max_count = self.config.get("max_count", 10)
            tool_pattern = self.config.get("tool_pattern", "*")

            cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
            count = sum(
                1 for h in session_history
                if h.get("timestamp", datetime.min) > cutoff
                and re.match(tool_pattern.replace("*", ".*"), h.get("tool_name", ""))
            )

            if count >= max_count:
                return True, f"High frequency of {tool_pattern}: {count} in {window_seconds}s"
            return False, None

        elif self.trigger_condition == "escalation":
            # Check for privilege escalation patterns
            recent_categories = []
            for h in session_history[-10:]:
                tool = h.get("tool_name", "")
                for cat_name, cat_info in TOOL_CATEGORIES.items():
                    for p in cat_info["patterns"]:
                        import fnmatch
                        if fnmatch.fnmatch(tool, p):
                            recent_categories.append(cat_name)
                            break

            # Check for escalation pattern: read -> write -> delete/exec
            escalation_order = ["read_data", "write_data", "delete_data", "execute_code", "privilege_escalation"]
            seen_order = [c for c in escalation_order if c in recent_categories]
            if len(seen_order) >= 3:
                return True, f"Privilege escalation pattern detected: {' -> '.join(seen_order)}"
            return False, None

        elif self.trigger_condition == "pattern":
            # Custom pattern matching on history
            pattern = self.config.get("pattern", "")
            # Concatenate recent tool names and match
            history_str = " ".join(h.get("tool_name", "") for h in session_history[-20:])
            if re.search(pattern, history_str):
                return True, f"Suspicious pattern in history: {pattern}"
            return False, None

        return False, None


class PolicyConflictDetector:
    """
    Detects conflicts between policy rules.

    Finds cases where:
    - Two rules match the same request but have different decisions
    - A higher priority rule is effectively overridden
    - Rules create ambiguous behavior
    """

    def __init__(self):
        pass

    def detect_conflicts(self, bundle: PolicyBundle) -> List[Dict]:
        """
        Analyze a policy bundle for conflicts.

        Returns list of conflict descriptions.
        """
        conflicts = []
        rules = bundle.get_rules_by_priority()

        for i, rule1 in enumerate(rules):
            for rule2 in rules[i + 1:]:
                # Check for potential overlap
                overlap = self._check_rule_overlap(rule1, rule2)
                if overlap:
                    if rule1.decision != rule2.decision:
                        conflicts.append({
                            "type": "decision_conflict",
                            "rule1_id": rule1.id,
                            "rule2_id": rule2.id,
                            "overlap": overlap,
                            "description": f"Rules '{rule1.name}' and '{rule2.name}' can match same request but have different decisions",
                            "resolution": f"Rule '{rule1.name}' will take precedence (priority {rule1.priority} vs {rule2.priority})",
                        })

        # Check for unreachable rules
        for i, rule in enumerate(rules):
            if i > 0:
                # Check if any previous rule would always match first
                for prev_rule in rules[:i]:
                    if self._rule_subsumes(prev_rule, rule):
                        conflicts.append({
                            "type": "unreachable_rule",
                            "rule_id": rule.id,
                            "blocked_by": prev_rule.id,
                            "description": f"Rule '{rule.name}' is unreachable - always blocked by '{prev_rule.name}'",
                        })

        return conflicts

    def _check_rule_overlap(self, rule1: PolicyRule, rule2: PolicyRule) -> Optional[str]:
        """Check if two rules can potentially match the same request."""
        # Check tool pattern overlap
        tool_overlap = self._patterns_overlap(rule1.tool_patterns, rule2.tool_patterns)
        agent_overlap = self._patterns_overlap(rule1.agent_patterns, rule2.agent_patterns)
        tenant_overlap = self._patterns_overlap(rule1.tenant_patterns, rule2.tenant_patterns)

        if tool_overlap and agent_overlap and tenant_overlap:
            return f"tools: {tool_overlap}"

        return None

    def _patterns_overlap(self, patterns1: List[str], patterns2: List[str]) -> Optional[str]:
        """Check if two pattern lists can match the same string."""
        # Empty pattern list matches everything
        if not patterns1 or not patterns2:
            return "any"

        # Check for explicit overlaps
        for p1 in patterns1:
            for p2 in patterns2:
                if p1 == p2:
                    return p1
                # Check if one contains the other
                if "*" in p1 or "*" in p2:
                    # Simplified check - could be more sophisticated
                    p1_base = p1.replace("*", "")
                    p2_base = p2.replace("*", "")
                    if p1_base in p2 or p2_base in p1:
                        return f"{p1} <-> {p2}"

        return None

    def _rule_subsumes(self, rule1: PolicyRule, rule2: PolicyRule) -> bool:
        """Check if rule1 would always match before rule2."""
        # If rule1 has lower priority number (higher priority), check if it matches everything rule2 matches
        if rule1.priority >= rule2.priority:
            return False

        # Rule1 subsumes rule2 if rule1's patterns are supersets of rule2's patterns
        # This is a simplified check

        # If rule1 has no tool patterns (matches all), it subsumes anything
        if not rule1.tool_patterns:
            return True

        # Check if rule1's patterns include rule2's specific patterns
        for p2 in rule2.tool_patterns:
            subsumed = False
            for p1 in rule1.tool_patterns:
                if p1 == "*" or (p1.endswith("*") and p2.startswith(p1[:-1])):
                    subsumed = True
                    break
            if not subsumed:
                return False

        return True


class AdvancedPolicyEngine(PolicyEngine):
    """
    Extended policy engine with advanced matching and validation.
    """

    def __init__(self, keypair=None):
        super().__init__(keypair)
        self._semantic_patterns: Dict[str, List[SemanticPattern]] = {}
        self._parameter_rules: Dict[str, List[ParameterRule]] = {}
        self._context_policies: List[ContextPolicy] = []
        self._session_history: Dict[str, List[Dict]] = {}  # session_id -> history

    def add_semantic_pattern(self, rule_id: str, pattern: SemanticPattern) -> None:
        """Add a semantic pattern for a rule."""
        if rule_id not in self._semantic_patterns:
            self._semantic_patterns[rule_id] = []
        self._semantic_patterns[rule_id].append(pattern)

    def add_parameter_rule(self, bundle_id: str, rule: ParameterRule) -> None:
        """Add a parameter validation rule."""
        if bundle_id not in self._parameter_rules:
            self._parameter_rules[bundle_id] = []
        self._parameter_rules[bundle_id].append(rule)

    def add_context_policy(self, policy: ContextPolicy) -> None:
        """Add a context-aware policy."""
        self._context_policies.append(policy)

    def evaluate(
        self,
        context: PolicyEvaluationContext,
        bundle_id: Optional[str] = None,
    ) -> PolicyEvaluationResult:
        """
        Enhanced evaluation with semantic matching and parameter validation.
        """
        import time
        start_time = time.perf_counter()

        # First, validate parameters
        bid = bundle_id or self._active_bundle_id
        if bid and bid in self._parameter_rules:
            for param_rule in self._parameter_rules[bid]:
                valid, error = param_rule.validate(
                    context.tool_name,
                    context.request_data or {},
                )
                if not valid:
                    elapsed = (time.perf_counter() - start_time) * 1000
                    return PolicyEvaluationResult(
                        decision=PolicyDecision.DENY,
                        matched_rule=None,
                        matched_rule_id=f"param:{param_rule.name}",
                        denial_reason=error,
                        evaluation_time_ms=elapsed,
                    )

        # Check context-aware policies
        session_history = self._session_history.get(context.session_id, [])
        for ctx_policy in self._context_policies:
            triggered, reason = ctx_policy.evaluate(context, session_history)
            if triggered:
                elapsed = (time.perf_counter() - start_time) * 1000
                return PolicyEvaluationResult(
                    decision=ctx_policy.action,
                    matched_rule=None,
                    matched_rule_id=f"context:{ctx_policy.name}",
                    denial_reason=reason,
                    evaluation_time_ms=elapsed,
                )

        # Regular evaluation
        result = super().evaluate(context, bundle_id)

        # If no rule matched, try semantic matching
        if result.matched_rule is None and bid:
            semantic_result = self._evaluate_semantic(context, bid, start_time)
            if semantic_result:
                return semantic_result

        return result

    def _evaluate_semantic(
        self,
        context: PolicyEvaluationContext,
        bundle_id: str,
        start_time: float,
    ) -> Optional[PolicyEvaluationResult]:
        """Try semantic matching if regular matching fails."""
        import time

        bundle = self._bundles.get(bundle_id)
        if not bundle:
            return None

        best_match = None
        best_confidence = 0.0

        for rule in bundle.get_rules_by_priority():
            rule_patterns = self._semantic_patterns.get(rule.id, [])
            for pattern in rule_patterns:
                matches, confidence = pattern.matches(context.tool_name)
                if matches and confidence > best_confidence:
                    best_match = rule
                    best_confidence = confidence

            # Also try category matching
            for pattern_str in rule.tool_patterns:
                # Convert to semantic pattern and check
                for cat_name in TOOL_CATEGORIES:
                    if cat_name in pattern_str.lower() or pattern_str == "*":
                        semantic_p = SemanticPattern(
                            pattern=pattern_str,
                            pattern_type=PatternType.CATEGORY,
                            category=cat_name,
                        )
                        matches, confidence = semantic_p.matches(context.tool_name)
                        if matches and confidence > best_confidence and confidence >= 0.7:
                            best_match = rule
                            best_confidence = confidence

        if best_match and best_confidence >= 0.7:
            elapsed = (time.perf_counter() - start_time) * 1000
            return PolicyEvaluationResult(
                decision=best_match.decision,
                matched_rule=best_match,
                matched_rule_id=f"semantic:{best_match.id}",
                evaluation_time_ms=elapsed,
                conditions={"semantic_confidence": best_confidence},
            )

        return None

    def record_action(
        self,
        context: PolicyEvaluationContext,
        result: PolicyEvaluationResult,
        bundle_id: Optional[str] = None,
    ) -> None:
        """Record action and update session history."""
        super().record_action(context, result, bundle_id)

        # Update session history for context-aware policies
        if context.session_id not in self._session_history:
            self._session_history[context.session_id] = []

        self._session_history[context.session_id].append({
            "tool_name": context.tool_name,
            "timestamp": context.timestamp or datetime.now(timezone.utc),
            "decision": result.decision.value,
            "rule_id": result.matched_rule_id,
        })

        # Trim history to last 100 entries
        if len(self._session_history[context.session_id]) > 100:
            self._session_history[context.session_id] = self._session_history[context.session_id][-100:]


# Default parameter rules for security
def create_default_parameter_rules() -> List[ParameterRule]:
    """Create default parameter validation rules for security."""
    return [
        ParameterRule(
            name="no_sql_injection",
            parameter_name="query",
            validation_type="no_injection",
            validation_value=None,
            error_message="Potential SQL injection detected",
        ),
        ParameterRule(
            name="no_command_injection",
            parameter_name="command",
            validation_type="no_injection",
            validation_value=None,
            error_message="Potential command injection detected",
        ),
        ParameterRule(
            name="max_query_length",
            parameter_name="query",
            validation_type="max_length",
            validation_value=10000,
            error_message="Query exceeds maximum length",
        ),
        ParameterRule(
            name="url_whitelist",
            parameter_name="url",
            validation_type="regex",
            validation_value=r"^https?://[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(/.*)?$",
            error_message="Invalid URL format",
        ),
        ParameterRule(
            name="path_no_traversal",
            parameter_name="path",
            validation_type="regex",
            validation_value=r"^(?!.*\.\.)(?!.*//)[a-zA-Z0-9_\-/\.]+$",
            error_message="Path traversal attempt detected",
            applies_to_tools=["file.*", "fs.*"],
        ),
    ]


def create_default_context_policies() -> List[ContextPolicy]:
    """Create default context-aware policies."""
    return [
        ContextPolicy(
            name="rapid_escalation",
            trigger_condition="escalation",
            config={},
            action=PolicyDecision.DENY,
            cooldown_seconds=300,
        ),
        ContextPolicy(
            name="high_frequency_exec",
            trigger_condition="frequency",
            config={
                "tool_pattern": "*.exec*",
                "window_seconds": 60,
                "max_count": 5,
            },
            action=PolicyDecision.DENY,
            cooldown_seconds=120,
        ),
        ContextPolicy(
            name="auth_probing",
            trigger_condition="frequency",
            config={
                "tool_pattern": "auth.*",
                "window_seconds": 60,
                "max_count": 10,
            },
            action=PolicyDecision.DENY,
            cooldown_seconds=300,
        ),
    ]
