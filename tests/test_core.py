"""Small safe checks for core project logic; no APK is executed."""

import tempfile
import unittest
from pathlib import Path

from analyzer.apk_analyzer import APKAnalysisResult, APKMetadata
from analyzer.manifest_analyzer import ManifestDetails
from database.database_manager import DatabaseManager
from dsa.threat_priority_queue import prioritize_findings
from security.models import Finding
from security.risk_scorer import RiskScorer
from utils.hashing import calculate_sha256
from utils.validators import APKValidationError, validate_apk_file


class CoreProjectTests(unittest.TestCase):
    """Test hashing, ranking, scoring, and local history persistence."""

    def test_hashing_and_risk_score(self) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as file_handle:
            file_handle.write(b"apk test data")
            path = Path(file_handle.name)
        try:
            self.assertEqual(len(calculate_sha256(path)), 64)
        finally:
            path.unlink()

        findings = [
            Finding("Permission", "SEND_SMS", "HIGH", 15, "SMS capability."),
            Finding("API", "DexClassLoader", "HIGH", 15, "Loads code."),
        ]
        risk = RiskScorer().assess(prioritize_findings(findings))
        self.assertEqual(risk.score, 30)
        self.assertEqual(risk.level, "MEDIUM")

    def test_database_history(self) -> None:
        findings = [Finding("Permission", "SEND_SMS", "HIGH", 15, "SMS capability.")]
        result = APKAnalysisResult(
            APKMetadata("sample.apk", 10, "com.sample", "Sample", "1.0", "1", "23", "34", "com.sample.Main"),
            ManifestDetails(["SEND_SMS"], [], [], [], []),
            findings,
            RiskScorer().assess(findings),
        )
        with tempfile.TemporaryDirectory() as folder:
            database = DatabaseManager(Path(folder) / "history.db")
            record_id = database.save_analysis(result, "a" * 64)
            self.assertEqual(database.get_history()[0]["id"], record_id)
            database.delete_analysis(record_id)
            self.assertEqual(database.get_history(), [])

    def test_risk_level_boundaries(self) -> None:
        scorer = RiskScorer()
        for score, level in ((0, "LOW"), (20, "LOW"), (21, "MEDIUM"), (40, "MEDIUM"), (41, "HIGH"), (70, "HIGH"), (71, "CRITICAL"), (120, "CRITICAL")):
            findings = [Finding("Test", "indicator", "HIGH", score, "test")]
            assessment = scorer.assess(findings)
            self.assertEqual(assessment.level, level)
            self.assertEqual(assessment.score, min(score, 100))

    def test_invalid_apk_is_rejected(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as file_handle:
            file_handle.write(b"not an apk archive")
            path = Path(file_handle.name)
        try:
            with self.assertRaises(APKValidationError):
                validate_apk_file(path)
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
