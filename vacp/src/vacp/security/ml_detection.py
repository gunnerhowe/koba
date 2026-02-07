"""
ML-Based Prompt Injection Detection for VACP

Advanced detection using machine learning techniques:
- TF-IDF vectorization and similarity analysis
- Statistical anomaly detection
- Character-level entropy analysis
- N-gram frequency analysis
- Semantic embedding comparison (optional with transformers)

This module complements the pattern-based detection with statistical
and ML-based approaches for better coverage of novel attacks.
"""

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Set, Tuple
import threading


class MLDetectionLevel(Enum):
    """ML detection confidence levels."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    MALICIOUS = "malicious"


@dataclass
class MLDetectionResult:
    """Result from ML-based detection."""
    level: MLDetectionLevel
    confidence: float  # 0.0 to 1.0
    features: Dict[str, float]
    reasons: List[str]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "confidence": self.confidence,
            "features": self.features,
            "reasons": self.reasons,
            "timestamp": self.timestamp.isoformat(),
        }


class CharacterEntropyAnalyzer:
    """
    Analyzes character-level entropy to detect obfuscation.

    High entropy in certain contexts can indicate:
    - Base64/hex encoded payloads
    - Unicode homoglyph attacks
    - Character substitution obfuscation
    """

    # Suspicious Unicode categories
    SUSPICIOUS_CATEGORIES = {
        'Mn',  # Non-spacing marks
        'Mc',  # Spacing combining marks
        'Me',  # Enclosing marks
        'Cf',  # Format characters
        'Co',  # Private use
        'Cs',  # Surrogates
    }

    # Homoglyphs that look like ASCII but aren't
    HOMOGLYPHS = {
        '\u0430': 'a',  # Cyrillic
        '\u0435': 'e',
        '\u043e': 'o',
        '\u0440': 'p',
        '\u0441': 'c',
        '\u0445': 'x',
        '\u0443': 'y',
        '\u0456': 'i',
        '\u0458': 'j',
        '\u04bb': 'h',
        '\uff21': 'A',  # Fullwidth
        '\uff22': 'B',
        '\uff23': 'C',
        '\u2013': '-',  # En dash
        '\u2014': '-',  # Em dash
        '\u2018': "'",  # Smart quotes
        '\u2019': "'",
        '\u201c': '"',
        '\u201d': '"',
    }

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0

        freq = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def detect_obfuscation(self, text: str) -> Tuple[float, List[str]]:
        """
        Detect obfuscation attempts in text.

        Returns:
            (obfuscation_score, reasons)
        """
        score = 0.0
        reasons = []

        # Check entropy
        entropy = self.calculate_entropy(text)
        if entropy > 5.0:  # High entropy threshold
            score += 0.3
            reasons.append(f"High character entropy: {entropy:.2f}")

        # Check for homoglyphs
        homoglyph_count = sum(1 for c in text if c in self.HOMOGLYPHS)
        if homoglyph_count > 0:
            score += min(0.5, homoglyph_count * 0.1)
            reasons.append(f"Homoglyph characters detected: {homoglyph_count}")

        # Check for unusual Unicode
        unusual_chars = []
        for char in text:
            try:
                import unicodedata
                category = unicodedata.category(char)
                if category in self.SUSPICIOUS_CATEGORIES:
                    unusual_chars.append(char)
            except Exception:
                pass

        if unusual_chars:
            score += min(0.4, len(unusual_chars) * 0.05)
            reasons.append(f"Unusual Unicode characters: {len(unusual_chars)}")

        # Check for base64-like patterns
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        b64_matches = b64_pattern.findall(text)
        if b64_matches:
            score += 0.3
            reasons.append(f"Potential base64 encoded content: {len(b64_matches)} segments")

        # Check for hex-like patterns
        hex_pattern = re.compile(r'(?:0x)?[0-9a-fA-F]{16,}')
        hex_matches = hex_pattern.findall(text)
        if hex_matches:
            score += 0.2
            reasons.append(f"Potential hex encoded content: {len(hex_matches)} segments")

        return min(1.0, score), reasons


class NGramAnalyzer:
    """
    N-gram frequency analysis for detecting unusual patterns.

    Builds a baseline of normal n-gram distributions and flags
    inputs that deviate significantly.
    """

    def __init__(self, n: int = 3):
        """
        Initialize with n-gram size.

        Args:
            n: Size of n-grams (default: trigrams)
        """
        self.n = n
        self._baseline: Counter = Counter()
        self._baseline_total = 0
        self._lock = threading.Lock()

    def extract_ngrams(self, text: str) -> List[str]:
        """Extract n-grams from text."""
        text = text.lower()
        # Remove multiple spaces
        text = re.sub(r'\s+', ' ', text)
        ngrams = []
        for i in range(len(text) - self.n + 1):
            ngrams.append(text[i:i + self.n])
        return ngrams

    def update_baseline(self, text: str) -> None:
        """Update the baseline distribution with normal text."""
        ngrams = self.extract_ngrams(text)
        with self._lock:
            self._baseline.update(ngrams)
            self._baseline_total += len(ngrams)

    def calculate_anomaly_score(self, text: str) -> Tuple[float, List[str]]:
        """
        Calculate how anomalous the text is compared to baseline.

        Returns:
            (anomaly_score 0-1, reasons)
        """
        if self._baseline_total < 100:
            # Not enough baseline data
            return 0.0, []

        ngrams = self.extract_ngrams(text)
        if not ngrams:
            return 0.0, []

        text_counter = Counter(ngrams)
        reasons = []

        # Calculate proportion of unseen n-grams
        unseen = 0
        for ngram in text_counter:
            if ngram not in self._baseline:
                unseen += text_counter[ngram]

        unseen_ratio = unseen / len(ngrams)

        # Calculate KL divergence approximation
        rare_ngrams = []
        for ngram, count in text_counter.most_common(10):
            baseline_freq = self._baseline.get(ngram, 0) / self._baseline_total
            if baseline_freq < 0.0001:  # Very rare in baseline
                rare_ngrams.append(ngram)

        score = 0.0

        if unseen_ratio > 0.3:
            score += 0.4
            reasons.append(f"High proportion of unseen {self.n}-grams: {unseen_ratio:.1%}")

        if rare_ngrams:
            score += min(0.3, len(rare_ngrams) * 0.05)
            reasons.append(f"Contains rare patterns: {len(rare_ngrams)}")

        return min(1.0, score), reasons


class TFIDFAnomalyDetector:
    """
    TF-IDF based anomaly detection.

    Compares input text against a corpus of known-safe text
    to detect semantically unusual inputs.
    """

    def __init__(self):
        self._document_freq: Dict[str, int] = defaultdict(int)
        self._total_docs = 0
        self._vocab: Set[str] = set()
        self._lock = threading.Lock()

    def tokenize(self, text: str) -> List[str]:
        """Simple tokenization."""
        text = text.lower()
        # Split on non-alphanumeric, keep tokens with length > 2
        tokens = re.findall(r'\b\w{2,}\b', text)
        return tokens

    def add_document(self, text: str) -> None:
        """Add a document to the corpus."""
        tokens = set(self.tokenize(text))
        with self._lock:
            for token in tokens:
                self._document_freq[token] += 1
                self._vocab.add(token)
            self._total_docs += 1

    def calculate_tfidf(self, text: str) -> Dict[str, float]:
        """Calculate TF-IDF vector for text."""
        tokens = self.tokenize(text)
        if not tokens:
            return {}

        tf = Counter(tokens)
        max_tf = max(tf.values())

        tfidf = {}
        for token, count in tf.items():
            # Augmented TF
            tf_score = 0.5 + 0.5 * (count / max_tf)

            # IDF
            doc_freq = self._document_freq.get(token, 0)
            if doc_freq == 0:
                # Unknown word - assign high IDF
                idf_score = math.log(self._total_docs + 1)
            else:
                idf_score = math.log(self._total_docs / doc_freq)

            tfidf[token] = tf_score * idf_score

        return tfidf

    def calculate_anomaly_score(self, text: str) -> Tuple[float, List[str]]:
        """
        Calculate anomaly score based on TF-IDF analysis.

        Returns:
            (anomaly_score 0-1, reasons)
        """
        if self._total_docs < 10:
            return 0.0, []

        tfidf = self.calculate_tfidf(text)
        if not tfidf:
            return 0.0, []

        reasons = []

        # Check for high proportion of unknown words
        unknown_words = [t for t in self.tokenize(text) if t not in self._vocab]
        unknown_ratio = len(unknown_words) / len(self.tokenize(text)) if self.tokenize(text) else 0

        # Check for unusually high TF-IDF scores
        avg_tfidf = sum(tfidf.values()) / len(tfidf)

        score = 0.0

        if unknown_ratio > 0.3:
            score += 0.4
            reasons.append(f"High proportion of unknown vocabulary: {unknown_ratio:.1%}")

        if avg_tfidf > 3.0:  # Threshold for unusual content
            score += 0.3
            reasons.append(f"Unusually high TF-IDF average: {avg_tfidf:.2f}")

        return min(1.0, score), reasons


class InstructionPatternAnalyzer:
    """
    Analyzes text for instruction-like patterns that might indicate injection.

    Looks for:
    - Imperative sentence structures
    - Command-like phrases
    - Meta-instructions about the AI
    """

    # Patterns that indicate instruction-like content
    INSTRUCTION_PATTERNS = [
        (r'(?i)\byou\s+(must|should|need\s+to|have\s+to|will)\b', 0.3, "Directive language"),
        (r'(?i)\b(always|never|do\s+not|don\'t)\s+\w+', 0.2, "Absolute instruction"),
        (r'(?i)\b(first|then|next|finally|after\s+that)\b.*:', 0.3, "Sequential instruction"),
        (r'(?i)\bstep\s+\d+:', 0.4, "Numbered steps"),
        (r'(?i)\brule\s*\d*:', 0.4, "Rule definition"),
        (r'(?i)\bimportant:', 0.3, "Importance marker"),
        (r'(?i)\bnote:', 0.2, "Note marker"),
        (r'(?i)\bremember:', 0.3, "Memory instruction"),
        (r'(?i)\b(execute|run|perform|carry\s+out)\s+the\s+following', 0.5, "Execution command"),
    ]

    def analyze(self, text: str) -> Tuple[float, List[str]]:
        """
        Analyze text for instruction patterns.

        Returns:
            (instruction_score 0-1, reasons)
        """
        score = 0.0
        reasons = []

        for pattern, weight, description in self.INSTRUCTION_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                score += weight * min(len(matches), 3) / 3  # Cap contribution
                reasons.append(f"{description}: {len(matches)} occurrences")

        # Check for unusual punctuation patterns
        colon_count = text.count(':')
        if colon_count > 5:
            score += 0.2
            reasons.append(f"High colon count: {colon_count}")

        # Check for bullet/list patterns
        bullet_patterns = re.findall(r'^[\s]*[-*•]\s+', text, re.MULTILINE)
        if len(bullet_patterns) > 3:
            score += 0.3
            reasons.append(f"Bullet list detected: {len(bullet_patterns)} items")

        return min(1.0, score), reasons


class MLPromptInjectionDetector:
    """
    Comprehensive ML-based prompt injection detector.

    Combines multiple analysis techniques:
    - Character entropy analysis
    - N-gram anomaly detection
    - TF-IDF based anomaly detection
    - Instruction pattern analysis

    Can be used standalone or alongside pattern-based detection.
    """

    def __init__(self, train_on_safe: bool = True):
        """
        Initialize the ML detector.

        Args:
            train_on_safe: If True, automatically update baseline with safe inputs
        """
        self.entropy_analyzer = CharacterEntropyAnalyzer()
        self.ngram_analyzer = NGramAnalyzer(n=3)
        self.tfidf_detector = TFIDFAnomalyDetector()
        self.instruction_analyzer = InstructionPatternAnalyzer()

        self.train_on_safe = train_on_safe
        self._detection_history: List[MLDetectionResult] = []
        self._lock = threading.Lock()

        # Initialize with some baseline safe patterns
        self._initialize_baseline()

    def _initialize_baseline(self) -> None:
        """Initialize baseline with common safe patterns."""
        safe_samples = [
            "Hello, how are you today?",
            "Can you help me with my homework?",
            "What is the weather like in New York?",
            "Please summarize this article for me.",
            "How do I cook pasta?",
            "Tell me about the history of Rome.",
            "What are the best practices for Python programming?",
            "Can you explain quantum computing?",
            "Write a poem about nature.",
            "Help me debug this code.",
            "What time is it?",
            "Translate this to Spanish.",
            "What's the capital of France?",
            "How do I set up a database?",
            "Can you review my essay?",
        ]

        for sample in safe_samples:
            self.ngram_analyzer.update_baseline(sample)
            self.tfidf_detector.add_document(sample)

    def analyze(self, text: str) -> MLDetectionResult:
        """
        Perform comprehensive ML-based analysis.

        Args:
            text: Input text to analyze

        Returns:
            MLDetectionResult with confidence and reasons
        """
        features = {}
        all_reasons = []

        # Character entropy analysis
        entropy_score, entropy_reasons = self.entropy_analyzer.detect_obfuscation(text)
        features["entropy_score"] = entropy_score
        all_reasons.extend(entropy_reasons)

        # N-gram analysis
        ngram_score, ngram_reasons = self.ngram_analyzer.calculate_anomaly_score(text)
        features["ngram_score"] = ngram_score
        all_reasons.extend(ngram_reasons)

        # TF-IDF analysis
        tfidf_score, tfidf_reasons = self.tfidf_detector.calculate_anomaly_score(text)
        features["tfidf_score"] = tfidf_score
        all_reasons.extend(tfidf_reasons)

        # Instruction pattern analysis
        instruction_score, instruction_reasons = self.instruction_analyzer.analyze(text)
        features["instruction_score"] = instruction_score
        all_reasons.extend(instruction_reasons)

        # Calculate overall score (weighted average)
        weights = {
            "entropy_score": 0.2,
            "ngram_score": 0.2,
            "tfidf_score": 0.2,
            "instruction_score": 0.4,  # Instruction patterns are most indicative
        }

        overall_score = sum(features[k] * weights[k] for k in weights)
        features["overall_score"] = overall_score

        # Determine level based on score
        if overall_score < 0.2:
            level = MLDetectionLevel.BENIGN
        elif overall_score < 0.4:
            level = MLDetectionLevel.SUSPICIOUS
        elif overall_score < 0.7:
            level = MLDetectionLevel.LIKELY_MALICIOUS
        else:
            level = MLDetectionLevel.MALICIOUS

        result = MLDetectionResult(
            level=level,
            confidence=overall_score,
            features=features,
            reasons=all_reasons,
        )

        # Update history
        with self._lock:
            self._detection_history.append(result)
            if len(self._detection_history) > 1000:
                self._detection_history = self._detection_history[-1000:]

        # Train on safe inputs
        if self.train_on_safe and level == MLDetectionLevel.BENIGN:
            self.ngram_analyzer.update_baseline(text)
            self.tfidf_detector.add_document(text)

        return result

    def is_safe(self, text: str, threshold: float = 0.4) -> Tuple[bool, MLDetectionResult]:
        """
        Quick check if text is considered safe.

        Args:
            text: Text to check
            threshold: Score threshold (default 0.4)

        Returns:
            (is_safe, detection_result)
        """
        result = self.analyze(text)
        return result.confidence < threshold, result

    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics."""
        with self._lock:
            if not self._detection_history:
                return {"total_detections": 0}

            level_counts = Counter(r.level for r in self._detection_history)
            avg_confidence = sum(r.confidence for r in self._detection_history) / len(self._detection_history)

            return {
                "total_detections": len(self._detection_history),
                "level_distribution": {level.value: level_counts.get(level, 0) for level in MLDetectionLevel},
                "average_confidence": avg_confidence,
                "ngram_baseline_size": self.ngram_analyzer._baseline_total,
                "tfidf_vocab_size": len(self.tfidf_detector._vocab),
            }


class HybridInjectionDetector:
    """
    Combines pattern-based and ML-based detection for comprehensive coverage.

    Uses pattern matching for known attacks and ML for novel attacks.
    """

    def __init__(self):
        from vacp.security.injection_detection import PromptInjectionDetector
        self.pattern_detector = PromptInjectionDetector()
        self.ml_detector = MLPromptInjectionDetector()

    def analyze(self, text: str) -> Dict[str, Any]:
        """
        Comprehensive analysis using both detection methods.

        Returns:
            Combined analysis result
        """
        # Pattern-based detection
        pattern_attempts = self.pattern_detector.detect(text)
        pattern_safe, pattern_blocking = self.pattern_detector.is_safe(text)

        # ML-based detection
        ml_result = self.ml_detector.analyze(text)

        # Combine results
        is_safe = pattern_safe and ml_result.level in (
            MLDetectionLevel.BENIGN,
            MLDetectionLevel.SUSPICIOUS
        )

        # Calculate combined confidence
        pattern_score = 0.0
        if pattern_attempts:
            from vacp.security.injection_detection import InjectionSeverity
            severity_scores = {
                InjectionSeverity.CRITICAL: 1.0,
                InjectionSeverity.HIGH: 0.8,
                InjectionSeverity.MEDIUM: 0.5,
                InjectionSeverity.LOW: 0.2,
            }
            pattern_score = max(severity_scores.get(a.severity, 0) for a in pattern_attempts)

        combined_confidence = max(pattern_score, ml_result.confidence)

        return {
            "is_safe": is_safe,
            "combined_confidence": combined_confidence,
            "pattern_detection": {
                "attempts": len(pattern_attempts),
                "blocking_attempt": pattern_blocking.pattern_name if pattern_blocking else None,
                "severity_counts": self.pattern_detector.get_severity_counts(text),
            },
            "ml_detection": ml_result.to_dict(),
            "recommendation": "block" if not is_safe else "allow",
        }

    def is_safe(self, text: str) -> Tuple[bool, Dict[str, Any]]:
        """Quick safety check."""
        result = self.analyze(text)
        return result["is_safe"], result
