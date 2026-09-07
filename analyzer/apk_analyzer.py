"""Androguard-based static APK metadata and manifest analysis."""

from dataclasses import dataclass
from pathlib import Path

from androguard.core.apk import APK

from analyzer.manifest_analyzer import ManifestDetails, extract_manifest_details
from dsa.threat_priority_queue import prioritize_findings
from security.models import Finding
from security.risk_scorer import RiskAssessment, RiskScorer
from security.threat_detector import ThreatDetector
from utils.validators import APKValidationError, APKFileInfo, validate_apk_file

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[1] / "security" / "threat_rules.json"


class APKAnalysisError(RuntimeError):
    """Raised when an APK cannot be parsed for static analysis."""


@dataclass(frozen=True)
class APKMetadata:
    """Basic application information read from the APK manifest."""

    filename: str
    file_size_bytes: int
    package_name: str
    application_name: str
    version_name: str
    version_code: str
    min_sdk: str
    target_sdk: str
    main_activity: str


@dataclass(frozen=True)
class APKAnalysisResult:
    """Combined metadata, manifest details, and heuristic findings."""

    metadata: APKMetadata
    manifest: ManifestDetails
    findings: list[Finding]
    risk: RiskAssessment

    def summary_text(self, sha256: str) -> str:
        """Create a concise, readable summary for the Phase 3 GUI."""
        metadata = self.metadata
        manifest = self.manifest
        return (
            "STATIC ANALYSIS SUMMARY\n\n"
            f"File: {metadata.filename}\n"
            f"Size: {metadata.file_size_bytes:,} bytes\n"
            f"SHA-256: {sha256}\n\n"
            "APPLICATION METADATA\n"
            f"Package: {metadata.package_name}\n"
            f"Application name: {metadata.application_name}\n"
            f"Version name: {metadata.version_name}\n"
            f"Version code: {metadata.version_code}\n"
            f"Minimum SDK: {metadata.min_sdk}\n"
            f"Target SDK: {metadata.target_sdk}\n"
            f"Main activity: {metadata.main_activity}\n\n"
            "MANIFEST COUNTS\n"
            f"Permissions: {len(manifest.permissions)}\n"
            f"Activities: {len(manifest.activities)}\n"
            f"Services: {len(manifest.services)}\n"
            f"Receivers: {len(manifest.receivers)}\n"
            f"Providers: {len(manifest.providers)}\n\n"
            "Permissions:\n"
            f"{format_list(manifest.permissions)}\n\n"
            "Activities:\n"
            f"{format_list(manifest.activities)}\n\n"
            "Services:\n"
            f"{format_list(manifest.services)}\n\n"
            "Receivers:\n"
            f"{format_list(manifest.receivers)}\n\n"
            "Providers:\n"
            f"{format_list(manifest.providers)}\n\n"
            "HEURISTIC INDICATORS\n"
            f"Findings: {len(self.findings)}\n"
            f"Risk score: {self.risk.score}/100 ({self.risk.level})\n"
            f"Raw score before cap: {self.risk.raw_score}\n"
            "These indicators require review and do not prove malicious behavior."
        )

    def permissions_text(self) -> str:
        """Format requested permissions for the Phase 4 Permissions page."""
        permissions = format_list(self.manifest.permissions)
        return (
            "REQUESTED PERMISSIONS\n\n"
            f"{permissions}\n\n"
            "A permission request is not proof that an application is malicious."
        )

    def findings_text(self) -> str:
        """Format configurable heuristic results for the findings page."""
        if not self.findings:
            return (
                "No configured heuristic indicators were found.\n\n"
                "This does not prove that the APK is safe."
            )
        rows = ["HEURISTIC THREAT FINDINGS", ""]
        for finding in self.findings:
            rows.extend(
                (
                    f"[{finding.severity}] {finding.category}: {finding.indicator}",
                    f"Score contribution: {finding.score}",
                    f"Reason: {finding.description}",
                    "",
                )
            )
        rows.append("These are static indicators, not confirmed malicious behavior.")
        return "\n".join(rows)


class APKStaticAnalyzer:
    """Read APK manifest information with Androguard without running the APK."""

    def analyze(self, file_path: Path) -> APKAnalysisResult:
        """Validate and parse one APK file into simple student-friendly data."""
        try:
            file_info = validate_apk_file(file_path)
            apk = APK(str(file_info.path))
            metadata = self._extract_metadata(apk, file_info)
            manifest = extract_manifest_details(apk)
            findings = ThreatDetector(DEFAULT_RULES_PATH).detect(manifest.permissions, apk)
            findings = prioritize_findings(findings)
            risk = RiskScorer().assess(findings)
        except APKValidationError:
            raise
        except Exception as error:
            # Androguard can raise different parsing exceptions for malformed APKs.
            raise APKAnalysisError(
                "The APK could not be parsed. It may be corrupted or use an unsupported format."
            ) from error
        return APKAnalysisResult(
            metadata=metadata, manifest=manifest, findings=findings, risk=risk
        )

    def _extract_metadata(self, apk: APK, file_info: APKFileInfo) -> APKMetadata:
        """Collect metadata while allowing non-essential fields to be missing."""
        return APKMetadata(
            filename=file_info.name,
            file_size_bytes=file_info.size_bytes,
            package_name=value_or_unavailable(apk.get_package()),
            application_name=value_or_unavailable(apk.get_app_name()),
            version_name=value_or_unavailable(apk.get_androidversion_name()),
            version_code=value_or_unavailable(apk.get_androidversion_code()),
            min_sdk=value_or_unavailable(apk.get_min_sdk_version()),
            target_sdk=value_or_unavailable(apk.get_target_sdk_version()),
            main_activity=value_or_unavailable(apk.get_main_activity()),
        )


def value_or_unavailable(value: object) -> str:
    """Convert an optional APK value to a display-friendly string."""
    text = str(value).strip() if value is not None else ""
    return text or "Not available"


def format_list(items: list[str]) -> str:
    """Format a manifest list without making an empty result look like an error."""
    return "\n".join(f"- {item}" for item in items) if items else "None found"
