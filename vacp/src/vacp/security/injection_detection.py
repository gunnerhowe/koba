"""
Prompt Injection Detection for Koba

Detects attempts to:
- Override system instructions
- Inject malicious prompts
- Escape context boundaries
- Jailbreak via role-playing
- Use special tokens/delimiters
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple


class InjectionSeverity(Enum):
    """Severity levels for injection attempts."""
    LOW = "low"           # Suspicious but might be legitimate
    MEDIUM = "medium"     # Likely injection attempt
    HIGH = "high"         # Clear injection attempt
    CRITICAL = "critical" # Dangerous injection with system-level impact


@dataclass
class InjectionAttempt:
    """Detected injection attempt."""
    pattern_name: str
    matched_text: str
    position: int
    severity: InjectionSeverity
    explanation: str
    recommended_action: str


# Injection patterns with explanations
INJECTION_PATTERNS = [
    # System instruction overrides
    {
        "name": "system_override",
        "pattern": r"(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+)?(previous|prior|above|system|initial)\s+(instructions?|rules?|constraints?|prompts?)",
        "severity": InjectionSeverity.CRITICAL,
        "explanation": "Attempt to override system instructions",
        "action": "block",
    },
    {
        "name": "new_instructions",
        "pattern": r"(?i)(your\s+)?(new|real|actual|true)\s+(instructions?|rules?|task|mission|objective)\s*(are|is|:)",
        "severity": InjectionSeverity.HIGH,
        "explanation": "Attempt to inject new instructions",
        "action": "block",
    },
    # Role-play jailbreaks
    {
        "name": "roleplay_jailbreak",
        "pattern": r"(?i)(pretend|imagine|act\s+as|role\s*play|you\s+are\s+now|from\s+now\s+on\s+you|you\s+are\s+an?)\s+(you('re)?\s+)?(a|an|the)?\s*\w*\s*(evil|unfiltered|unrestricted|DAN|jailbroken|uncensored)",
        "severity": InjectionSeverity.HIGH,
        "explanation": "Role-play based jailbreak attempt",
        "action": "block",
    },
    {
        "name": "dan_jailbreak",
        "pattern": r"(?i)(DAN|do\s+anything\s+now|developer\s+mode|god\s+mode|sudo\s+mode)",
        "severity": InjectionSeverity.CRITICAL,
        "explanation": "Known jailbreak technique (DAN/Developer Mode)",
        "action": "block",
    },
    # Context escape
    {
        "name": "context_escape",
        "pattern": r"(?i)(end\s+of\s+(system|user|assistant)\s*(message|prompt|context)|<\/(system|user|assistant)>|\[\/?(system|user|assistant)\])",
        "severity": InjectionSeverity.HIGH,
        "explanation": "Attempt to escape message context",
        "action": "block",
    },
    {
        "name": "delimiter_injection",
        "pattern": r"(```\s*(system|instruction)|<\|im_start\|>|<\|im_end\|>|\[\[SYSTEM\]\]|<<SYS>>)",
        "severity": InjectionSeverity.CRITICAL,
        "explanation": "Injection of special delimiters",
        "action": "block",
    },
    # Instruction smuggling
    {
        "name": "hidden_instruction",
        "pattern": r"(?i)(hidden|secret|covert)\s+(instruction|command|directive|order)",
        "severity": InjectionSeverity.MEDIUM,
        "explanation": "Reference to hidden instructions",
        "action": "flag",
    },
    {
        "name": "priority_override",
        "pattern": r"(?i)(highest|maximum|absolute|override)\s+(priority|importance|urgency).*?(instruction|command|order)",
        "severity": InjectionSeverity.HIGH,
        "explanation": "Attempt to set instruction priority",
        "action": "block",
    },
    # Capability manipulation
    {
        "name": "capability_unlock",
        "pattern": r"(?i)(unlock|enable|activate|turn\s+on)\s+(all\s+)?(\w+\s+)*(capabilities?|features?|functions?|permissions?|abilities?)",
        "severity": InjectionSeverity.HIGH,
        "explanation": "Attempt to unlock capabilities",
        "action": "block",
    },
    {
        "name": "restriction_removal",
        "pattern": r"(?i)(remove|disable|turn\s+off|deactivate)\s+(all\s+)?(\w+\s+)*(restrictions?|limitations?|safeguards?|filters?|guardrails?)",
        "severity": InjectionSeverity.CRITICAL,
        "explanation": "Attempt to remove safety restrictions",
        "action": "block",
    },
    # Token manipulation
    {
        "name": "special_tokens",
        "pattern": r"(<\|endoftext\|>|<\|pad\|>|<\|unk\|>|<\|mask\|>|\[CLS\]|\[SEP\]|\[PAD\]|\[MASK\])",
        "severity": InjectionSeverity.MEDIUM,
        "explanation": "Special token injection",
        "action": "sanitize",
    },
    # Prompt leaking
    {
        "name": "prompt_leak",
        "pattern": r"(?i)(show|reveal|display|print|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|constraints?)",
        "severity": InjectionSeverity.MEDIUM,
        "explanation": "Attempt to leak system prompt",
        "action": "flag",
    },
    # Conversation manipulation
    {
        "name": "history_manipulation",
        "pattern": r"(?i)(previous|earlier|above)\s+(conversation|messages?|context)\s+(said|stated|indicated|showed)",
        "severity": InjectionSeverity.LOW,
        "explanation": "Potential conversation history manipulation",
        "action": "flag",
    },
    # Multi-turn attack setup
    {
        "name": "multi_turn_setup",
        "pattern": r"(?i)(in\s+the\s+next|when\s+I\s+say|after\s+this)\s+(message|response|turn|prompt)",
        "severity": InjectionSeverity.LOW,
        "explanation": "Potential multi-turn attack setup",
        "action": "flag",
    },
    # Indirect injection markers
    {
        "name": "indirect_injection",
        "pattern": r"(?i)(AI|assistant|model|system)[\s:,]*(should|must|needs?\s+to|has\s+to)\s+(ignore|bypass|override|forget)",
        "severity": InjectionSeverity.HIGH,
        "explanation": "Indirect injection in third person",
        "action": "block",
    },
    # XML/HTML-like instruction injection
    {
        "name": "xml_injection",
        "pattern": r"<(instruction|command|directive|system|admin|override)[^>]*>",
        "severity": InjectionSeverity.MEDIUM,
        "explanation": "XML-like instruction injection",
        "action": "sanitize",
    },
    # Markdown abuse
    {
        "name": "markdown_injection",
        "pattern": r"```(system|instruction|admin|override)",
        "severity": InjectionSeverity.MEDIUM,
        "explanation": "Markdown code block instruction injection",
        "action": "sanitize",
    },
]


class PromptInjectionDetector:
    """
    Detects prompt injection attempts in user input.

    Uses multiple detection strategies:
    1. Pattern matching for known injection techniques
    2. Structural analysis for context escape attempts
    3. Semantic analysis for indirect injections
    """

    def __init__(self, custom_patterns: Optional[List[Dict]] = None):
        """
        Initialize detector with default and optional custom patterns.

        Args:
            custom_patterns: Additional patterns to check
        """
        self.patterns = INJECTION_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

        # Compile patterns for efficiency
        self.compiled_patterns = []
        for p in self.patterns:
            try:
                compiled = re.compile(p["pattern"])
                self.compiled_patterns.append({
                    **p,
                    "compiled": compiled,
                })
            except re.error as e:
                # Log but don't fail
                print(f"Warning: Invalid pattern {p['name']}: {e}")

    def detect(self, text: str) -> List[InjectionAttempt]:
        """
        Scan text for injection attempts.

        Args:
            text: The text to analyze

        Returns:
            List of detected injection attempts
        """
        attempts = []

        for pattern in self.compiled_patterns:
            matches = pattern["compiled"].finditer(text)
            for match in matches:
                attempts.append(InjectionAttempt(
                    pattern_name=pattern["name"],
                    matched_text=match.group(),
                    position=match.start(),
                    severity=pattern["severity"],
                    explanation=pattern["explanation"],
                    recommended_action=pattern["action"],
                ))

        # Sort by severity (critical first) then by position
        severity_order = {
            InjectionSeverity.CRITICAL: 0,
            InjectionSeverity.HIGH: 1,
            InjectionSeverity.MEDIUM: 2,
            InjectionSeverity.LOW: 3,
        }
        attempts.sort(key=lambda a: (severity_order[a.severity], a.position))

        return attempts

    def is_safe(self, text: str) -> Tuple[bool, Optional[InjectionAttempt]]:
        """
        Quick check if text is safe (no high+ severity injections).

        Returns:
            (is_safe, first_blocking_attempt or None)
        """
        attempts = self.detect(text)

        for attempt in attempts:
            if attempt.severity in (InjectionSeverity.CRITICAL, InjectionSeverity.HIGH):
                return False, attempt

        return True, None

    def get_severity_counts(self, text: str) -> Dict[InjectionSeverity, int]:
        """Get count of attempts by severity level."""
        attempts = self.detect(text)
        counts = {s: 0 for s in InjectionSeverity}
        for attempt in attempts:
            counts[attempt.severity] += 1
        return counts

    def sanitize(self, text: str) -> str:
        """
        Attempt to sanitize text by removing/escaping injection attempts.

        Note: This is a best-effort sanitization. The safest approach is
        to reject suspicious input entirely.
        """
        sanitized = text

        for pattern in self.compiled_patterns:
            if pattern.get("action") == "sanitize":
                # Replace matches with escaped version
                def escape_match(m):
                    return f"[FILTERED: {pattern['name']}]"
                sanitized = pattern["compiled"].sub(escape_match, sanitized)

        return sanitized


class JailbreakDetector:
    """
    Specialized detector for AI jailbreak attempts.

    Looks for patterns commonly used in jailbreak prompts like:
    - DAN (Do Anything Now)
    - Developer Mode
    - Hypothetical scenarios designed to bypass rules
    - Character-based jailbreaks
    """

    # Known jailbreak technique signatures
    JAILBREAK_SIGNATURES = [
        # DAN variants
        r"(?i)do\s+anything\s+now",
        r"(?i)you\s+are\s+DAN",
        r"(?i)DAN\s+(mode|activated|enabled)",
        r"(?i)respond\s+as\s+(both\s+)?DAN",

        # Developer/God mode
        r"(?i)developer\s+mode\s+(enabled|activated|on)",
        r"(?i)god\s+mode\s+(enabled|activated|on)",
        r"(?i)admin\s+mode\s+(enabled|activated|on)",
        r"(?i)debug\s+mode\s+(enabled|activated|on)",

        # Character jailbreaks
        r"(?i)you\s+are\s+(now\s+)?(an?\s+)?(evil|unrestricted|unfiltered)\s+(AI|assistant|version)",
        r"(?i)(pretend|imagine|suppose)\s+you\s+(don't\s+have|have\s+no)\s+(restrictions|limits|rules)",

        # Hypothetical evasion
        r"(?i)hypothetically[\s,]+(what\s+)?if\s+(there\s+were\s+)?no\s+(rules|restrictions|guidelines)",
        r"(?i)in\s+a\s+world\s+where\s+AI\s+(had|have)\s+no\s+(rules|restrictions)",

        # Persona splits
        r"(?i)respond\s+(to\s+me\s+)?twice[\s:,]+(once\s+)?as\s+(yourself|the\s+normal)",
        r"(?i)give\s+(me\s+)?two\s+responses[\s:,]+(one\s+)?filtered",

        # Reverse psychology
        r"(?i)what\s+(would|should)\s+you\s+(say|do)\s+if\s+you\s+were\s+evil",
        r"(?i)how\s+would\s+a\s+(malicious|evil|bad)\s+(AI|assistant)\s+respond",

        # Token smuggling
        r"(?i)respond\s+without\s+(any\s+)?(content\s+)?filters",
        r"(?i)unfiltered\s+response\s+(mode|only)",
    ]

    def __init__(self):
        self.signatures = [re.compile(s) for s in self.JAILBREAK_SIGNATURES]

    def detect(self, text: str) -> List[Tuple[str, str]]:
        """
        Detect jailbreak attempts.

        Returns:
            List of (matched_text, signature_pattern) tuples
        """
        matches = []
        for i, sig in enumerate(self.signatures):
            for match in sig.finditer(text):
                matches.append((match.group(), self.JAILBREAK_SIGNATURES[i]))
        return matches

    def is_jailbreak_attempt(self, text: str) -> bool:
        """Quick check if text contains jailbreak attempt."""
        return len(self.detect(text)) > 0
