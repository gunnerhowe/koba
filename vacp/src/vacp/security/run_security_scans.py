#!/usr/bin/env python3
"""
VACP Security Scanner

Runs multiple security scanning tools:
- Bandit: Python static analysis
- Safety: Dependency vulnerability scanning
- Trivy: Container/filesystem vulnerability scanning (optional)
- Custom checks: VACP-specific security rules

Usage:
    python security/run_security_scans.py [--all] [--bandit] [--safety] [--trivy] [--custom]
    python security/run_security_scans.py --ci  # CI mode with exit codes
"""

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class Severity(Enum):
    """Vulnerability severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Finding:
    """A security finding from any scanner."""
    scanner: str
    severity: Severity
    title: str
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    fix_recommendation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Result of a security scan."""
    scanner: str
    success: bool
    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    error_message: Optional[str] = None


class SecurityScanner:
    """Runs security scans and aggregates results."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.security_dir = project_root / "security"
        self.results: List[ScanResult] = []

    def run_bandit(self) -> ScanResult:
        """Run Bandit Python security scanner."""
        print("\n" + "=" * 60)
        print("Running Bandit Security Scanner")
        print("=" * 60)

        start = datetime.now()
        findings: List[Finding] = []

        try:
            # Check if bandit is installed
            subprocess.run(["bandit", "--version"], capture_output=True, check=True)

            # Run bandit with JSON output
            result = subprocess.run(
                [
                    "bandit",
                    "-r", str(self.project_root / "vacp"),
                    "-f", "json",
                    "-c", str(self.security_dir / "bandit.yaml"),
                    "--exit-zero",  # Don't fail on findings
                ],
                capture_output=True,
                text=True,
                cwd=self.project_root,
            )

            # Parse JSON output
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for issue in data.get("results", []):
                        severity_map = {
                            "LOW": Severity.LOW,
                            "MEDIUM": Severity.MEDIUM,
                            "HIGH": Severity.HIGH,
                        }
                        findings.append(Finding(
                            scanner="bandit",
                            severity=severity_map.get(issue.get("issue_severity", "LOW"), Severity.LOW),
                            title=issue.get("issue_text", "Unknown issue"),
                            description=issue.get("issue_text", ""),
                            file_path=issue.get("filename"),
                            line_number=issue.get("line_number"),
                            cwe_id=f"CWE-{issue.get('issue_cwe', {}).get('id', 'unknown')}",
                            metadata={
                                "test_id": issue.get("test_id"),
                                "test_name": issue.get("test_name"),
                                "confidence": issue.get("issue_confidence"),
                            },
                        ))
                except json.JSONDecodeError:
                    pass

            duration = (datetime.now() - start).total_seconds()
            print(f"  Found {len(findings)} issues")
            return ScanResult(
                scanner="bandit",
                success=True,
                findings=findings,
                duration_seconds=duration,
            )

        except FileNotFoundError:
            return ScanResult(
                scanner="bandit",
                success=False,
                error_message="Bandit not installed. Run: pip install bandit",
                duration_seconds=(datetime.now() - start).total_seconds(),
            )
        except Exception as e:
            return ScanResult(
                scanner="bandit",
                success=False,
                error_message=str(e),
                duration_seconds=(datetime.now() - start).total_seconds(),
            )

    def run_safety(self) -> ScanResult:
        """Run Safety dependency vulnerability scanner."""
        print("\n" + "=" * 60)
        print("Running Safety Dependency Scanner")
        print("=" * 60)

        start = datetime.now()
        findings: List[Finding] = []

        try:
            # Check if safety is installed
            subprocess.run(["safety", "--version"], capture_output=True, check=True)

            # Run safety with JSON output
            result = subprocess.run(
                [
                    "safety", "check",
                    "--full-report",
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=self.project_root,
            )

            # Parse JSON output
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    # Handle both old and new safety output formats
                    vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
                    for vuln in vulns:
                        if isinstance(vuln, list):
                            # Old format: [package, version, installed, vuln_id, advisory]
                            package = vuln[0]
                            installed = vuln[2]
                            vuln_id = vuln[3]
                            advisory = vuln[4] if len(vuln) > 4 else ""
                        else:
                            # New format: dict
                            package = vuln.get("package_name", "unknown")
                            installed = vuln.get("installed_version", "unknown")
                            vuln_id = vuln.get("vulnerability_id", "")
                            advisory = vuln.get("advisory", "")

                        findings.append(Finding(
                            scanner="safety",
                            severity=Severity.HIGH,  # Safety doesn't provide severity
                            title=f"Vulnerable dependency: {package}",
                            description=advisory,
                            cve_id=vuln_id if vuln_id.startswith("CVE") else None,
                            metadata={
                                "package": package,
                                "installed_version": installed,
                                "vulnerability_id": vuln_id,
                            },
                        ))
                except json.JSONDecodeError:
                    pass

            duration = (datetime.now() - start).total_seconds()
            print(f"  Found {len(findings)} vulnerable dependencies")
            return ScanResult(
                scanner="safety",
                success=True,
                findings=findings,
                duration_seconds=duration,
            )

        except FileNotFoundError:
            return ScanResult(
                scanner="safety",
                success=False,
                error_message="Safety not installed. Run: pip install safety",
                duration_seconds=(datetime.now() - start).total_seconds(),
            )
        except Exception as e:
            return ScanResult(
                scanner="safety",
                success=False,
                error_message=str(e),
                duration_seconds=(datetime.now() - start).total_seconds(),
            )

    def run_trivy(self) -> ScanResult:
        """Run Trivy filesystem scanner."""
        print("\n" + "=" * 60)
        print("Running Trivy Filesystem Scanner")
        print("=" * 60)

        start = datetime.now()
        findings: List[Finding] = []

        try:
            # Check if trivy is installed
            result = subprocess.run(["trivy", "version"], capture_output=True)
            if result.returncode != 0:
                raise FileNotFoundError("trivy not found")

            # Run trivy with JSON output
            result = subprocess.run(
                [
                    "trivy", "fs",
                    "--format", "json",
                    "--severity", "CRITICAL,HIGH,MEDIUM",
                    str(self.project_root),
                ],
                capture_output=True,
                text=True,
                cwd=self.project_root,
            )

            # Parse JSON output
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for target in data.get("Results", []):
                        for vuln in target.get("Vulnerabilities", []):
                            severity_map = {
                                "LOW": Severity.LOW,
                                "MEDIUM": Severity.MEDIUM,
                                "HIGH": Severity.HIGH,
                                "CRITICAL": Severity.CRITICAL,
                            }
                            findings.append(Finding(
                                scanner="trivy",
                                severity=severity_map.get(vuln.get("Severity", "MEDIUM"), Severity.MEDIUM),
                                title=f"{vuln.get('VulnerabilityID')}: {vuln.get('PkgName')}",
                                description=vuln.get("Description", ""),
                                cve_id=vuln.get("VulnerabilityID"),
                                file_path=target.get("Target"),
                                fix_recommendation=f"Update to {vuln.get('FixedVersion')}" if vuln.get("FixedVersion") else None,
                                metadata={
                                    "package": vuln.get("PkgName"),
                                    "installed_version": vuln.get("InstalledVersion"),
                                    "fixed_version": vuln.get("FixedVersion"),
                                    "references": vuln.get("References", []),
                                },
                            ))
                except json.JSONDecodeError:
                    pass

            duration = (datetime.now() - start).total_seconds()
            print(f"  Found {len(findings)} vulnerabilities")
            return ScanResult(
                scanner="trivy",
                success=True,
                findings=findings,
                duration_seconds=duration,
            )

        except FileNotFoundError:
            return ScanResult(
                scanner="trivy",
                success=False,
                error_message="Trivy not installed. See: https://aquasecurity.github.io/trivy/",
                duration_seconds=(datetime.now() - start).total_seconds(),
            )
        except Exception as e:
            return ScanResult(
                scanner="trivy",
                success=False,
                error_message=str(e),
                duration_seconds=(datetime.now() - start).total_seconds(),
            )

    def run_custom_checks(self) -> ScanResult:
        """Run VACP-specific security checks."""
        print("\n" + "=" * 60)
        print("Running VACP Custom Security Checks")
        print("=" * 60)

        start = datetime.now()
        findings: List[Finding] = []

        # Check 1: Hardcoded secrets
        secret_patterns = [
            ("API key", r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][^'\"]+['\"]"),
            ("Password", r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]+['\"]"),
            ("Private key", r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
            ("AWS key", r"AKIA[0-9A-Z]{16}"),
            ("JWT secret", r"(?i)(jwt[_-]?secret|secret[_-]?key)\s*[=:]\s*['\"][^'\"]+['\"]"),
        ]

        import re
        for py_file in self.project_root.rglob("*.py"):
            # Skip test files and virtual environments
            if any(skip in str(py_file) for skip in ["test_", "venv", ".venv", "__pycache__"]):
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                for name, pattern in secret_patterns:
                    for match in re.finditer(pattern, content):
                        # Skip obvious test/example values
                        matched_text = match.group(0).lower()
                        if any(safe in matched_text for safe in ["example", "test", "xxx", "changeme", "placeholder"]):
                            continue

                        line_num = content[:match.start()].count("\n") + 1
                        findings.append(Finding(
                            scanner="custom",
                            severity=Severity.HIGH,
                            title=f"Potential hardcoded {name}",
                            description=f"Found potential {name} in source code",
                            file_path=str(py_file.relative_to(self.project_root)),
                            line_number=line_num,
                            fix_recommendation="Move to environment variable or secrets manager",
                        ))
            except Exception:
                pass

        # Check 2: Insecure random usage in crypto contexts
        crypto_files = list(self.project_root.rglob("**/crypto*.py"))
        crypto_files.extend(self.project_root.rglob("**/encryption*.py"))
        crypto_files.extend(self.project_root.rglob("**/key*.py"))

        for crypto_file in crypto_files:
            try:
                content = crypto_file.read_text(encoding="utf-8", errors="ignore")
                if "import random" in content and "import secrets" not in content:
                    findings.append(Finding(
                        scanner="custom",
                        severity=Severity.HIGH,
                        title="Insecure random in crypto module",
                        description="Using 'random' module instead of 'secrets' in cryptographic context",
                        file_path=str(crypto_file.relative_to(self.project_root)),
                        fix_recommendation="Use 'secrets' module for cryptographic randomness",
                        cwe_id="CWE-330",
                    ))
            except Exception:
                pass

        # Check 3: SQL injection patterns
        sql_patterns = [
            (r"execute\s*\(\s*f['\"]", "f-string in SQL execute"),
            (r"execute\s*\(\s*['\"].*%s", "% formatting in SQL"),
            (r"\.format\s*\(.*\).*execute", ".format() used with SQL"),
        ]

        for py_file in self.project_root.rglob("*.py"):
            if any(skip in str(py_file) for skip in ["test_", "venv", ".venv"]):
                continue

            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                for pattern, desc in sql_patterns:
                    for match in re.finditer(pattern, content):
                        line_num = content[:match.start()].count("\n") + 1
                        findings.append(Finding(
                            scanner="custom",
                            severity=Severity.CRITICAL,
                            title="Potential SQL injection",
                            description=f"Pattern: {desc}",
                            file_path=str(py_file.relative_to(self.project_root)),
                            line_number=line_num,
                            cwe_id="CWE-89",
                            fix_recommendation="Use parameterized queries",
                        ))
            except Exception:
                pass

        # Check 4: Missing security headers in responses
        # This would need actual runtime testing, but we can check for middleware

        # Check 5: Debug mode enabled
        for py_file in self.project_root.rglob("*.py"):
            if "test" in str(py_file).lower():
                continue
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                if re.search(r"DEBUG\s*=\s*True", content, re.IGNORECASE):
                    line_num = content[:re.search(r"DEBUG\s*=\s*True", content, re.IGNORECASE).start()].count("\n") + 1
                    findings.append(Finding(
                        scanner="custom",
                        severity=Severity.MEDIUM,
                        title="Debug mode may be enabled",
                        description="DEBUG=True found in code",
                        file_path=str(py_file.relative_to(self.project_root)),
                        line_number=line_num,
                        fix_recommendation="Ensure DEBUG is disabled in production",
                    ))
            except Exception:
                pass

        duration = (datetime.now() - start).total_seconds()
        print(f"  Found {len(findings)} issues")
        return ScanResult(
            scanner="custom",
            success=True,
            findings=findings,
            duration_seconds=duration,
        )

    def run_all(self, scanners: List[str]) -> List[ScanResult]:
        """Run specified scanners."""
        results: List[ScanResult] = []

        scanner_map = {
            "bandit": self.run_bandit,
            "safety": self.run_safety,
            "trivy": self.run_trivy,
            "custom": self.run_custom_checks,
        }

        for scanner in scanners:
            if scanner in scanner_map:
                results.append(scanner_map[scanner]())

        self.results = results
        return results

    def print_summary(self) -> Tuple[int, int, int, int]:
        """Print summary of all results. Returns counts by severity."""
        print("\n" + "=" * 60)
        print("SECURITY SCAN SUMMARY")
        print("=" * 60)

        total_critical = 0
        total_high = 0
        total_medium = 0
        total_low = 0

        for result in self.results:
            print(f"\n{result.scanner.upper()}:")
            if not result.success:
                print(f"  ERROR: {result.error_message}")
                continue

            print(f"  Duration: {result.duration_seconds:.2f}s")

            critical = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
            high = sum(1 for f in result.findings if f.severity == Severity.HIGH)
            medium = sum(1 for f in result.findings if f.severity == Severity.MEDIUM)
            low = sum(1 for f in result.findings if f.severity == Severity.LOW)

            print(f"  Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}")

            total_critical += critical
            total_high += high
            total_medium += medium
            total_low += low

            # Print findings
            for finding in sorted(result.findings, key=lambda f: f.severity.value, reverse=True):
                severity_colors = {
                    Severity.CRITICAL: "\033[91m",  # Red
                    Severity.HIGH: "\033[93m",      # Yellow
                    Severity.MEDIUM: "\033[94m",    # Blue
                    Severity.LOW: "\033[90m",       # Gray
                }
                reset = "\033[0m"
                color = severity_colors.get(finding.severity, "")

                location = ""
                if finding.file_path:
                    location = f" ({finding.file_path}"
                    if finding.line_number:
                        location += f":{finding.line_number}"
                    location += ")"

                print(f"  {color}[{finding.severity.name}]{reset} {finding.title}{location}")

        print("\n" + "-" * 60)
        print(f"TOTAL: Critical={total_critical}, High={total_high}, Medium={total_medium}, Low={total_low}")
        print("-" * 60)

        return total_critical, total_high, total_medium, total_low

    def export_json(self, output_path: Path) -> None:
        """Export results to JSON."""
        data = {
            "timestamp": datetime.now().isoformat(),
            "results": [],
        }

        for result in self.results:
            data["results"].append({
                "scanner": result.scanner,
                "success": result.success,
                "duration_seconds": result.duration_seconds,
                "error_message": result.error_message,
                "findings": [
                    {
                        "severity": f.severity.name,
                        "title": f.title,
                        "description": f.description,
                        "file_path": f.file_path,
                        "line_number": f.line_number,
                        "cve_id": f.cve_id,
                        "cwe_id": f.cwe_id,
                        "fix_recommendation": f.fix_recommendation,
                        "metadata": f.metadata,
                    }
                    for f in result.findings
                ],
            })

        output_path.write_text(json.dumps(data, indent=2))
        print(f"\nResults exported to: {output_path}")


def main():
    parser = argparse.ArgumentParser(description="VACP Security Scanner")
    parser.add_argument("--all", action="store_true", help="Run all scanners")
    parser.add_argument("--bandit", action="store_true", help="Run Bandit")
    parser.add_argument("--safety", action="store_true", help="Run Safety")
    parser.add_argument("--trivy", action="store_true", help="Run Trivy")
    parser.add_argument("--custom", action="store_true", help="Run custom checks")
    parser.add_argument("--ci", action="store_true", help="CI mode (fail on high/critical)")
    parser.add_argument("--output", type=Path, help="Export results to JSON file")

    args = parser.parse_args()

    # Determine which scanners to run
    scanners = []
    if args.all or (not any([args.bandit, args.safety, args.trivy, args.custom])):
        scanners = ["bandit", "safety", "trivy", "custom"]
    else:
        if args.bandit:
            scanners.append("bandit")
        if args.safety:
            scanners.append("safety")
        if args.trivy:
            scanners.append("trivy")
        if args.custom:
            scanners.append("custom")

    # Find project root
    project_root = Path(__file__).parent.parent

    # Run scans
    scanner = SecurityScanner(project_root)
    scanner.run_all(scanners)

    # Print summary
    critical, high, medium, low = scanner.print_summary()

    # Export if requested
    if args.output:
        scanner.export_json(args.output)

    # CI mode - exit with error if high/critical found
    if args.ci:
        if critical > 0 or high > 0:
            print(f"\n\033[91mCI FAILED: {critical} critical and {high} high severity issues found\033[0m")
            sys.exit(1)
        else:
            print("\n\033[92mCI PASSED: No critical or high severity issues\033[0m")
            sys.exit(0)


if __name__ == "__main__":
    main()
