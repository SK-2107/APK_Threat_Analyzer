"""Create a plain-text static security assessment report."""

from datetime import datetime
from pathlib import Path

from analyzer.apk_analyzer import APKAnalysisResult, format_list


def generate_report(result: APKAnalysisResult, sha256: str, output_folder: Path) -> Path:
    """Write a readable report and return its saved path."""
    output_folder.mkdir(parents=True, exist_ok=True)
    safe_name = result.metadata.filename.replace(".apk", "").replace(" ", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_folder / f"{safe_name}_static_report_{timestamp}.txt"
    metadata = result.metadata
    report = f"""APK THREAT ANALYZER - STATIC ASSESSMENT REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

APK INFORMATION
File: {metadata.filename}
Package: {metadata.package_name}
Application: {metadata.application_name}
Version: {metadata.version_name} ({metadata.version_code})
SHA-256: {sha256}
File size: {metadata.file_size_bytes:,} bytes
Minimum SDK: {metadata.min_sdk}
Target SDK: {metadata.target_sdk}

RISK ASSESSMENT
Risk Score: {result.risk.score}/100
Threat Level: {result.risk.level}
RISK CONTRIBUTORS
{result.risk.explanation()}

PERMISSIONS
{format_list(result.manifest.permissions)}

SUSPICIOUS INDICATORS
{result.findings_text()}

ANDROID COMPONENTS
Activities: {format_list(result.manifest.activities)}
Services: {format_list(result.manifest.services)}
Receivers: {format_list(result.manifest.receivers)}
Providers: {format_list(result.manifest.providers)}

NETWORK INDICATORS
{format_list([finding.indicator for finding in result.findings if "endpoint" in finding.category.lower() or "ip" in finding.category.lower() or "domain" in finding.category.lower()])}

LIMITATIONS
This report provides a static risk assessment and does not guarantee that an APK is malicious or safe.
Indicators are heuristic observations and should be reviewed in context. The APK was not installed or executed.
"""
    path.write_text(report, encoding="utf-8")
    return path
