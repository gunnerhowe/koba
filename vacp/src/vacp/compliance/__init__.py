"""
Compliance Reporting Module for Koba

This module generates verifiable compliance reports that auditors can use to
validate that the system's security claims are actually enforced.
"""

from .report import ComplianceReport, generate_compliance_report

__all__ = ["ComplianceReport", "generate_compliance_report"]
