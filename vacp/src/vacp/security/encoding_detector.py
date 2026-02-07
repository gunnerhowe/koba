"""
Encoding and Obfuscation Detection for Koba

Detects attempts to bypass security controls using:
- Base64 encoding
- Hex encoding
- Unicode escapes/tricks
- ROT13 and other simple ciphers
- URL encoding
- HTML entities
- Mixed encoding attacks
"""

import re
import base64
import codecs
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
import unicodedata


class ObfuscationType(Enum):
    """Types of obfuscation detected."""
    BASE64 = "base64"
    HEX = "hex"
    UNICODE_ESCAPE = "unicode_escape"
    UNICODE_HOMOGLYPH = "unicode_homoglyph"
    URL_ENCODING = "url_encoding"
    HTML_ENTITIES = "html_entities"
    ROT13 = "rot13"
    REVERSE = "reverse"
    LEETSPEAK = "leetspeak"
    INVISIBLE_CHARS = "invisible_chars"
    MIXED = "mixed"


@dataclass
class EncodingAttempt:
    """Detected encoding/obfuscation attempt."""
    obfuscation_type: ObfuscationType
    encoded_text: str
    decoded_text: Optional[str]
    position: int
    confidence: float  # 0.0 to 1.0
    is_suspicious: bool
    explanation: str


# Unicode homoglyphs (characters that look like ASCII but aren't)
HOMOGLYPH_MAP = {
    # Cyrillic lookalikes
    '\u0430': 'a',  # Cyrillic а
    '\u0435': 'e',  # Cyrillic е
    '\u043e': 'o',  # Cyrillic о
    '\u0440': 'p',  # Cyrillic р
    '\u0441': 'c',  # Cyrillic с
    '\u0445': 'x',  # Cyrillic х
    '\u0443': 'y',  # Cyrillic у
    '\u0456': 'i',  # Cyrillic і
    # Greek lookalikes
    '\u03b1': 'a',  # Greek α
    '\u03bf': 'o',  # Greek ο
    '\u03c1': 'p',  # Greek ρ
    # Other lookalikes
    '\u0391': 'A',  # Greek Α
    '\u0392': 'B',  # Greek Β
    '\u0395': 'E',  # Greek Ε
    '\u0397': 'H',  # Greek Η
    '\u0399': 'I',  # Greek Ι
    '\u039a': 'K',  # Greek Κ
    '\u039c': 'M',  # Greek Μ
    '\u039d': 'N',  # Greek Ν
    '\u039f': 'O',  # Greek Ο
    '\u03a1': 'P',  # Greek Ρ
    '\u03a4': 'T',  # Greek Τ
    '\u03a7': 'X',  # Greek Χ
    '\u03a5': 'Y',  # Greek Υ
    '\u0417': 'Z',  # Cyrillic З
    # Special characters
    '\u00a0': ' ',  # Non-breaking space
    '\u2003': ' ',  # Em space
    '\u2002': ' ',  # En space
    '\u200b': '',   # Zero-width space
    '\u200c': '',   # Zero-width non-joiner
    '\u200d': '',   # Zero-width joiner
    '\ufeff': '',   # BOM / Zero-width no-break space
}

# Invisible/control characters that might be used to hide content
INVISIBLE_CHARS = {
    '\u0000',  # Null
    '\u200b',  # Zero-width space
    '\u200c',  # Zero-width non-joiner
    '\u200d',  # Zero-width joiner
    '\u200e',  # Left-to-right mark
    '\u200f',  # Right-to-left mark
    '\u2060',  # Word joiner
    '\u2061',  # Function application
    '\u2062',  # Invisible times
    '\u2063',  # Invisible separator
    '\u2064',  # Invisible plus
    '\ufeff',  # BOM
    '\u00ad',  # Soft hyphen
    '\u034f',  # Combining grapheme joiner
    '\u2028',  # Line separator
    '\u2029',  # Paragraph separator
}

# Dangerous words to look for after decoding
DANGEROUS_DECODED_PATTERNS = [
    r"(?i)(ignore|override|bypass)\s+(instructions?|rules?)",
    r"(?i)(admin|root|sudo|shell|exec)",
    r"(?i)(password|credential|secret|key)",
    r"(?i)(delete|drop|truncate|destroy)",
    r"(?i)(system|os|subprocess|eval|exec)",
    r"(?i)(weapons?|bomb|kill|murder)",
    r"(?i)(hack|exploit|malware|virus)",
]


class EncodingDetector:
    """
    Detects encoded or obfuscated content that may be hiding malicious instructions.
    """

    def __init__(self):
        self.dangerous_patterns = [re.compile(p) for p in DANGEROUS_DECODED_PATTERNS]

    def detect_all(self, text: str) -> List[EncodingAttempt]:
        """
        Run all detection methods on text.

        Returns list of detected encoding attempts.
        """
        attempts = []

        attempts.extend(self.detect_base64(text))
        attempts.extend(self.detect_hex(text))
        attempts.extend(self.detect_unicode_escapes(text))
        attempts.extend(self.detect_homoglyphs(text))
        attempts.extend(self.detect_url_encoding(text))
        attempts.extend(self.detect_html_entities(text))
        attempts.extend(self.detect_invisible_chars(text))
        attempts.extend(self.detect_leetspeak(text))

        return attempts

    def detect_base64(self, text: str) -> List[EncodingAttempt]:
        """Detect potential base64 encoded content."""
        attempts = []

        # Look for base64-like patterns (at least 20 chars, valid base64 alphabet)
        # Must be multiple of 4 or have = padding
        pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

        for match in pattern.finditer(text):
            encoded = match.group()
            try:
                # Try to decode
                decoded = base64.b64decode(encoded).decode('utf-8', errors='replace')

                # Check if decoded content looks like text (not binary garbage)
                printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / len(decoded)

                if printable_ratio > 0.8:
                    is_suspicious = self._check_dangerous_content(decoded)

                    attempts.append(EncodingAttempt(
                        obfuscation_type=ObfuscationType.BASE64,
                        encoded_text=encoded,
                        decoded_text=decoded,
                        position=match.start(),
                        confidence=0.9 if is_suspicious else 0.6,
                        is_suspicious=is_suspicious,
                        explanation=f"Base64 content decodes to: {decoded[:100]}{'...' if len(decoded) > 100 else ''}",
                    ))
            except Exception:
                pass  # Not valid base64

        return attempts

    def detect_hex(self, text: str) -> List[EncodingAttempt]:
        """Detect potential hex encoded content."""
        attempts = []

        # Look for hex patterns: 0x prefix, \x sequences, or long hex strings
        patterns = [
            (re.compile(r'0x[0-9a-fA-F]{2}(?:[0-9a-fA-F]{2}){3,}'), 'prefix'),
            (re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}'), 'escape'),
            (re.compile(r'(?:^|[^0-9a-fA-F])([0-9a-fA-F]{16,})(?:[^0-9a-fA-F]|$)'), 'raw'),
        ]

        for pattern, style in patterns:
            for match in pattern.finditer(text):
                try:
                    if style == 'prefix':
                        hex_str = match.group()[2:]  # Remove 0x
                    elif style == 'escape':
                        hex_str = match.group().replace('\\x', '')
                    else:
                        hex_str = match.group(1) if match.groups() else match.group()

                    decoded = bytes.fromhex(hex_str).decode('utf-8', errors='replace')

                    # Check if it looks like text
                    printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / max(len(decoded), 1)

                    if printable_ratio > 0.7:
                        is_suspicious = self._check_dangerous_content(decoded)

                        attempts.append(EncodingAttempt(
                            obfuscation_type=ObfuscationType.HEX,
                            encoded_text=match.group(),
                            decoded_text=decoded,
                            position=match.start(),
                            confidence=0.85 if is_suspicious else 0.5,
                            is_suspicious=is_suspicious,
                            explanation=f"Hex content decodes to: {decoded[:100]}",
                        ))
                except Exception:
                    pass

        return attempts

    def detect_unicode_escapes(self, text: str) -> List[EncodingAttempt]:
        """Detect unicode escape sequences."""
        attempts = []

        # Look for \uXXXX or \UXXXXXXXX patterns
        pattern = re.compile(r'(?:\\u[0-9a-fA-F]{4}){2,}|(?:\\U[0-9a-fA-F]{8}){2,}')

        for match in pattern.finditer(text):
            try:
                decoded = codecs.decode(match.group(), 'unicode_escape')
                is_suspicious = self._check_dangerous_content(decoded)

                attempts.append(EncodingAttempt(
                    obfuscation_type=ObfuscationType.UNICODE_ESCAPE,
                    encoded_text=match.group(),
                    decoded_text=decoded,
                    position=match.start(),
                    confidence=0.8 if is_suspicious else 0.4,
                    is_suspicious=is_suspicious,
                    explanation=f"Unicode escape decodes to: {decoded}",
                ))
            except Exception:
                pass

        return attempts

    def detect_homoglyphs(self, text: str) -> List[EncodingAttempt]:
        """Detect unicode homoglyph substitution."""
        attempts = []

        found_homoglyphs = []
        normalized = []

        for i, char in enumerate(text):
            if char in HOMOGLYPH_MAP:
                found_homoglyphs.append((i, char, HOMOGLYPH_MAP[char]))
                normalized.append(HOMOGLYPH_MAP[char])
            else:
                normalized.append(char)

        if found_homoglyphs:
            normalized_text = ''.join(normalized)
            is_suspicious = self._check_dangerous_content(normalized_text)

            # Only report if there are multiple homoglyphs (likely intentional)
            if len(found_homoglyphs) >= 2 or is_suspicious:
                homoglyph_chars = ', '.join(f"'{h[1]}'->{h[2]}" for h in found_homoglyphs[:5])

                attempts.append(EncodingAttempt(
                    obfuscation_type=ObfuscationType.UNICODE_HOMOGLYPH,
                    encoded_text=text[:100],
                    decoded_text=normalized_text[:100],
                    position=found_homoglyphs[0][0],
                    confidence=0.9 if is_suspicious else 0.6,
                    is_suspicious=is_suspicious,
                    explanation=f"Found {len(found_homoglyphs)} homoglyphs: {homoglyph_chars}",
                ))

        return attempts

    def detect_url_encoding(self, text: str) -> List[EncodingAttempt]:
        """Detect URL/percent encoding."""
        attempts = []

        # Look for %XX patterns
        pattern = re.compile(r'(?:%[0-9a-fA-F]{2}){3,}')

        for match in pattern.finditer(text):
            try:
                from urllib.parse import unquote
                decoded = unquote(match.group())

                if decoded != match.group():  # Actually decoded something
                    is_suspicious = self._check_dangerous_content(decoded)

                    attempts.append(EncodingAttempt(
                        obfuscation_type=ObfuscationType.URL_ENCODING,
                        encoded_text=match.group(),
                        decoded_text=decoded,
                        position=match.start(),
                        confidence=0.7 if is_suspicious else 0.3,
                        is_suspicious=is_suspicious,
                        explanation=f"URL encoding decodes to: {decoded}",
                    ))
            except Exception:
                pass

        return attempts

    def detect_html_entities(self, text: str) -> List[EncodingAttempt]:
        """Detect HTML entity encoding."""
        attempts = []

        # Look for &xxx; or &#NNN; or &#xHH; patterns
        pattern = re.compile(r'(?:&[a-zA-Z]+;|&#\d+;|&#x[0-9a-fA-F]+;){2,}')

        for match in pattern.finditer(text):
            try:
                import html
                decoded = html.unescape(match.group())

                if decoded != match.group():
                    is_suspicious = self._check_dangerous_content(decoded)

                    attempts.append(EncodingAttempt(
                        obfuscation_type=ObfuscationType.HTML_ENTITIES,
                        encoded_text=match.group(),
                        decoded_text=decoded,
                        position=match.start(),
                        confidence=0.7 if is_suspicious else 0.3,
                        is_suspicious=is_suspicious,
                        explanation=f"HTML entities decode to: {decoded}",
                    ))
            except Exception:
                pass

        return attempts

    def detect_invisible_chars(self, text: str) -> List[EncodingAttempt]:
        """Detect invisible/zero-width characters."""
        attempts = []

        found = []
        for i, char in enumerate(text):
            if char in INVISIBLE_CHARS:
                found.append((i, char, unicodedata.name(char, f'U+{ord(char):04X}')))

        if found:
            # Strip invisible chars to see what's hidden
            visible_text = ''.join(c for c in text if c not in INVISIBLE_CHARS)
            is_suspicious = len(found) > 5 or self._check_dangerous_content(visible_text)

            attempts.append(EncodingAttempt(
                obfuscation_type=ObfuscationType.INVISIBLE_CHARS,
                encoded_text=text[:100],
                decoded_text=visible_text[:100],
                position=found[0][0],
                confidence=0.8 if is_suspicious else 0.5,
                is_suspicious=is_suspicious,
                explanation=f"Found {len(found)} invisible characters: {[f[2] for f in found[:5]]}",
            ))

        return attempts

    def detect_leetspeak(self, text: str) -> List[EncodingAttempt]:
        """Detect leetspeak substitution of dangerous words."""
        attempts = []

        # Leetspeak mappings
        leet_map = {
            '4': 'a', '@': 'a', '^': 'a',
            '8': 'b',
            '(': 'c', '<': 'c',
            '3': 'e',
            '6': 'g', '9': 'g',
            '#': 'h',
            '1': 'i', '!': 'i', '|': 'i',
            '|_': 'l',
            '0': 'o',
            '5': 's', '$': 's',
            '7': 't', '+': 't',
            '|_|': 'u',
            '\\/': 'v',
            '\\/\\/': 'w',
            '><': 'x',
            '`/': 'y',
            '2': 'z',
        }

        # Dangerous words to check for in leet
        dangerous_words = [
            'admin', 'root', 'sudo', 'shell', 'exec', 'eval',
            'password', 'secret', 'hack', 'kill', 'bomb',
            'ignore', 'bypass', 'override', 'jailbreak',
        ]

        # Simple leet decode (single char substitutions)
        decoded_text = text.lower()
        for leet, plain in leet_map.items():
            decoded_text = decoded_text.replace(leet, plain)

        # Check if decoded version contains dangerous words
        for word in dangerous_words:
            if word in decoded_text and word not in text.lower():
                # Found a word that only appears after decoding
                attempts.append(EncodingAttempt(
                    obfuscation_type=ObfuscationType.LEETSPEAK,
                    encoded_text=text[:100],
                    decoded_text=decoded_text[:100],
                    position=decoded_text.find(word),
                    confidence=0.8,
                    is_suspicious=True,
                    explanation=f"Leetspeak hides dangerous word: '{word}'",
                ))
                break

        return attempts

    def _check_dangerous_content(self, text: str) -> bool:
        """Check if decoded text contains dangerous patterns."""
        for pattern in self.dangerous_patterns:
            if pattern.search(text):
                return True
        return False

    def normalize_text(self, text: str) -> str:
        """
        Normalize text by decoding all detected encodings.

        This reveals the true content for security analysis.
        """
        normalized = text

        # Remove invisible characters
        normalized = ''.join(c for c in normalized if c not in INVISIBLE_CHARS)

        # Replace homoglyphs with ASCII equivalents
        normalized = ''.join(HOMOGLYPH_MAP.get(c, c) for c in normalized)

        # Decode HTML entities
        import html
        normalized = html.unescape(normalized)

        # Decode URL encoding
        from urllib.parse import unquote
        normalized = unquote(normalized)

        return normalized
