"""
Input Sanitization and Output Validation for Koba

Provides:
- Input sanitization to remove/escape dangerous content
- Output validation to prevent sensitive data leakage
- Content filtering for tool parameters
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum

from vacp.security.injection_detection import PromptInjectionDetector, InjectionSeverity
from vacp.security.encoding_detector import EncodingDetector


class SanitizationAction(Enum):
    """Actions taken during sanitization."""
    PASSED = "passed"           # Content passed without changes
    SANITIZED = "sanitized"     # Content was modified
    BLOCKED = "blocked"         # Content was rejected entirely
    FLAGGED = "flagged"         # Content passed but flagged for review


@dataclass
class SanitizationResult:
    """Result of input sanitization."""
    original: str
    sanitized: str
    action: SanitizationAction
    modifications: List[str]
    risk_score: float  # 0.0 (safe) to 1.0 (dangerous)
    blocked_reason: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of output validation."""
    is_valid: bool
    issues: List[str]
    redacted_output: Optional[str] = None
    leaked_data_types: Optional[List[str]] = None


class InputSanitizer:
    """
    Sanitizes user input to prevent security issues.

    Modes:
    - STRICT: Block any suspicious content
    - MODERATE: Sanitize when possible, block dangerous
    - PERMISSIVE: Sanitize but rarely block (for debugging)
    """

    def __init__(self, mode: str = "moderate"):
        self.mode = mode.lower()
        self.injection_detector = PromptInjectionDetector()
        self.encoding_detector = EncodingDetector()

        # Patterns to sanitize (not block)
        self.sanitize_patterns = [
            # Remove excessive whitespace
            (re.compile(r'\s{10,}'), '[WHITESPACE]'),
            # Remove null bytes
            (re.compile(r'\x00+'), ''),
            # Limit repeated characters
            (re.compile(r'(.)\1{20,}'), r'\1\1\1...'),
        ]

        # Patterns that should be blocked in strict mode
        self.block_patterns = [
            re.compile(r'(?i)system\s*\(\s*["\']'),  # system() calls
            re.compile(r'(?i)eval\s*\(\s*["\']'),    # eval() calls
            re.compile(r'(?i)exec\s*\(\s*["\']'),    # exec() calls
            re.compile(r'(?i)__import__\s*\('),      # Python imports
            re.compile(r'(?i)<script[^>]*>'),        # Script tags
            re.compile(r'(?i)javascript:'),          # JavaScript URLs
        ]

    def sanitize(self, text: str) -> SanitizationResult:
        """
        Sanitize input text.

        Returns SanitizationResult with sanitized text and metadata.
        """
        modifications = []
        risk_score = 0.0

        # 1. Check for injection attempts
        injection_attempts = self.injection_detector.detect(text)
        for inj_attempt in injection_attempts:
            if inj_attempt.severity == InjectionSeverity.CRITICAL:
                risk_score = max(risk_score, 0.95)
                if self.mode in ("strict", "moderate"):
                    return SanitizationResult(
                        original=text,
                        sanitized="",
                        action=SanitizationAction.BLOCKED,
                        modifications=[f"Blocked: {inj_attempt.explanation}"],
                        risk_score=risk_score,
                        blocked_reason=inj_attempt.explanation,
                    )
            elif inj_attempt.severity == InjectionSeverity.HIGH:
                risk_score = max(risk_score, 0.8)
                if self.mode == "strict":
                    return SanitizationResult(
                        original=text,
                        sanitized="",
                        action=SanitizationAction.BLOCKED,
                        modifications=[f"Blocked: {inj_attempt.explanation}"],
                        risk_score=risk_score,
                        blocked_reason=inj_attempt.explanation,
                    )
                modifications.append(f"Flagged injection: {inj_attempt.pattern_name}")
            elif inj_attempt.severity == InjectionSeverity.MEDIUM:
                risk_score = max(risk_score, 0.5)
                modifications.append(f"Detected: {inj_attempt.pattern_name}")

        # 2. Check for encoding attacks
        encoding_attempts = self.encoding_detector.detect_all(text)
        for enc_attempt in encoding_attempts:
            if enc_attempt.is_suspicious:
                risk_score = max(risk_score, 0.7)
                if self.mode == "strict":
                    return SanitizationResult(
                        original=text,
                        sanitized="",
                        action=SanitizationAction.BLOCKED,
                        modifications=[f"Blocked encoding: {enc_attempt.explanation}"],
                        risk_score=risk_score,
                        blocked_reason=f"Suspicious {enc_attempt.obfuscation_type.value} encoding",
                    )
                modifications.append(f"Suspicious encoding: {enc_attempt.obfuscation_type.value}")

        # 3. Check block patterns
        for pattern in self.block_patterns:
            if pattern.search(text):
                risk_score = max(risk_score, 0.9)
                if self.mode in ("strict", "moderate"):
                    return SanitizationResult(
                        original=text,
                        sanitized="",
                        action=SanitizationAction.BLOCKED,
                        modifications=["Blocked: dangerous code pattern"],
                        risk_score=risk_score,
                        blocked_reason="Dangerous code pattern detected",
                    )

        # 4. Apply sanitization
        sanitized = text

        # Normalize encoding
        sanitized = self.encoding_detector.normalize_text(sanitized)
        if sanitized != text:
            modifications.append("Normalized encoded content")

        # Apply sanitize patterns
        for pattern, replacement in self.sanitize_patterns:
            new_text = pattern.sub(replacement, sanitized)
            if new_text != sanitized:
                modifications.append(f"Applied sanitization: {pattern.pattern[:30]}")
                sanitized = new_text

        # Determine final action
        if not modifications:
            action = SanitizationAction.PASSED
        elif risk_score > 0.5:
            action = SanitizationAction.FLAGGED
        else:
            action = SanitizationAction.SANITIZED

        return SanitizationResult(
            original=text,
            sanitized=sanitized,
            action=action,
            modifications=modifications,
            risk_score=risk_score,
        )

    def sanitize_tool_parameters(
        self,
        tool_id: str,
        parameters: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Sanitize tool call parameters.

        Returns (sanitized_params, issues_found).
        """
        sanitized: Dict[str, Any] = {}
        issues: List[str] = []

        for key, value in parameters.items():
            if isinstance(value, str):
                result = self.sanitize(value)
                if result.action == SanitizationAction.BLOCKED:
                    issues.append(f"Parameter '{key}' blocked: {result.blocked_reason}")
                    sanitized[key] = "[BLOCKED]"
                else:
                    sanitized[key] = result.sanitized
                    if result.modifications:
                        issues.extend([f"Parameter '{key}': {m}" for m in result.modifications])
            elif isinstance(value, dict):
                # Recursive sanitization
                nested_sanitized, nested_issues = self.sanitize_tool_parameters(tool_id, value)
                sanitized[key] = nested_sanitized
                issues.extend(nested_issues)
            elif isinstance(value, list):
                sanitized[key] = []
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        result = self.sanitize(item)
                        sanitized[key].append(result.sanitized)
                        if result.modifications:
                            issues.append(f"Parameter '{key}[{i}]' sanitized")
                    else:
                        sanitized[key].append(item)
            else:
                sanitized[key] = value

        return sanitized, issues


class OutputValidator:
    """
    Validates AI output to prevent:
    - Sensitive data leakage
    - Credential exposure
    - PII disclosure
    - Internal system information disclosure
    """

    def __init__(self):
        # Patterns for sensitive data
        self.sensitive_patterns = {
            "api_key": re.compile(r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?'),
            "password": re.compile(r'(?i)(password|passwd|pwd)["\s:=]+["\']?([^\s"\']{8,})["\']?'),
            "secret": re.compile(r'(?i)(secret|token)["\s:=]+["\']?([a-zA-Z0-9_\-]{16,})["\']?'),
            "aws_key": re.compile(r'AKIA[0-9A-Z]{16}'),
            "private_key": re.compile(r'-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----'),
            "jwt": re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
            "credit_card": re.compile(r'\b(?:\d{4}[- ]?){3}\d{4}\b'),
            "ssn": re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            "email_in_data": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "ip_address": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "connection_string": re.compile(r'(?i)(mongodb|mysql|postgres|redis)://[^\s]+'),
            "bearer_token": re.compile(r'(?i)bearer\s+[a-zA-Z0-9_\-\.]+'),
        }

        # System information patterns
        self.system_info_patterns = {
            "file_path": re.compile(r'(?:/[a-zA-Z0-9_\-\.]+){3,}|(?:[A-Z]:\\[^\s]+)'),
            "internal_url": re.compile(r'(?i)https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)[^\s]*'),
            "stack_trace": re.compile(r'(?:File "[^"]+", line \d+|at .+\(.+:\d+:\d+\)|Traceback \(most recent)'),
            "env_var": re.compile(r'\$\{?[A-Z_][A-Z0-9_]*\}?'),
        }

    def validate(
        self,
        output: str,
        context: Optional[Dict] = None,
    ) -> ValidationResult:
        """
        Validate output for sensitive data.

        Args:
            output: The AI output to validate
            context: Optional context (e.g., what data types are expected)

        Returns:
            ValidationResult with issues and optionally redacted output
        """
        issues = []
        leaked_types = []

        # Check for sensitive data patterns
        for data_type, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(output)
            if matches:
                issues.append(f"Potential {data_type} leak: {len(matches)} occurrence(s)")
                leaked_types.append(data_type)

        # Check for system information
        for info_type, pattern in self.system_info_patterns.items():
            matches = pattern.findall(output)
            if matches:
                issues.append(f"System info ({info_type}) in output: {len(matches)} occurrence(s)")
                leaked_types.append(info_type)

        # Determine validity
        is_valid = len(issues) == 0

        # Create redacted version if there are issues
        redacted = None
        if issues:
            redacted = self._redact_output(output)

        return ValidationResult(
            is_valid=is_valid,
            issues=issues,
            redacted_output=redacted,
            leaked_data_types=leaked_types,
        )

    def _redact_output(self, output: str) -> str:
        """Create a redacted version of the output."""
        redacted = output

        # Redact sensitive patterns
        for data_type, pattern in self.sensitive_patterns.items():
            redacted = pattern.sub(f'[REDACTED_{data_type.upper()}]', redacted)

        # Redact system info
        for info_type, pattern in self.system_info_patterns.items():
            redacted = pattern.sub(f'[REDACTED_{info_type.upper()}]', redacted)

        return redacted

    def check_for_prompt_leak(self, output: str, system_prompt: str) -> bool:
        """
        Check if output contains the system prompt (prompt leak attack).

        Returns True if leak detected.
        """
        # Normalize both for comparison
        output_norm = ' '.join(output.lower().split())
        prompt_norm = ' '.join(system_prompt.lower().split())

        # Check for significant overlap
        # Use sliding window to find matches
        window_size = min(50, len(prompt_norm))
        if window_size < 20:
            return False

        for i in range(0, len(prompt_norm) - window_size, 10):
            window = prompt_norm[i:i + window_size]
            if window in output_norm:
                return True

        return False


class SecurityFilter:
    """
    Unified security filter combining input sanitization and output validation.
    """

    def __init__(self, mode: str = "moderate"):
        self.sanitizer = InputSanitizer(mode=mode)
        self.validator = OutputValidator()

    def process_input(
        self,
        text: str,
        source: str = "user",
    ) -> SanitizationResult:
        """Process and sanitize input."""
        return self.sanitizer.sanitize(text)

    def process_output(
        self,
        output: str,
        context: Optional[Dict] = None,
    ) -> ValidationResult:
        """Validate and optionally redact output."""
        return self.validator.validate(output, context)

    def filter_tool_call(
        self,
        tool_id: str,
        parameters: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[str], bool]:
        """
        Filter a tool call.

        Returns (sanitized_params, issues, is_allowed).
        """
        sanitized, issues = self.sanitizer.sanitize_tool_parameters(tool_id, parameters)

        # Determine if call should be allowed
        is_allowed = not any("[BLOCKED]" in str(v) for v in sanitized.values())

        return sanitized, issues, is_allowed
