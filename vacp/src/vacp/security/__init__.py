"""
Security module for Koba

Provides:
- Prompt injection detection
- Encoding attack detection (base64, hex, unicode)
- Input sanitization
- Output validation
- Jailbreak attempt detection
"""

from vacp.security.injection_detection import (
    PromptInjectionDetector,
    InjectionAttempt,
    InjectionSeverity,
)
from vacp.security.encoding_detector import (
    EncodingDetector,
    EncodingAttempt,
    ObfuscationType,
)
from vacp.security.sanitizer import (
    InputSanitizer,
    OutputValidator,
    SanitizationResult,
)

__all__ = [
    "PromptInjectionDetector",
    "InjectionAttempt",
    "InjectionSeverity",
    "EncodingDetector",
    "EncodingAttempt",
    "ObfuscationType",
    "InputSanitizer",
    "OutputValidator",
    "SanitizationResult",
]
