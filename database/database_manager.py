"""SQLite storage for completed static analyses."""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pandas as pd

from analyzer.apk_analyzer import APKAnalysisResult


class DatabaseManager:
    """Create, save, search, and delete local analysis history."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.create_tables()

    @contextmanager
    def _connection(self):
        """Yield a connection and always close it after commit or rollback."""
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def create_tables(self) -> None:
        """Create the small set of tables used by the project."""
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    apk_name TEXT NOT NULL,
                    package_name TEXT,
                    sha256 TEXT NOT NULL,
                    version TEXT,
                    risk_score INTEGER NOT NULL,
                    threat_level TEXT NOT NULL,
                    analysis_date TEXT DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    indicator TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    description TEXT NOT NULL,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
                );
                CREATE TABLE IF NOT EXISTS permissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    permission TEXT NOT NULL,
                    severity TEXT,
                    description TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
                );
                CREATE TABLE IF NOT EXISTS components (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    component_type TEXT NOT NULL,
                    component_name TEXT NOT NULL,
                    exported TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
                );
                CREATE TABLE IF NOT EXISTS network_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    indicator TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
                );
                """
            )

    def save_analysis(self, result: APKAnalysisResult, sha256: str) -> int:
        """Store one analysis and return its database identifier."""
        with self._connection() as connection:
            cursor = connection.execute(
                """INSERT INTO analyses
                (apk_name, package_name, sha256, version, risk_score, threat_level)
                VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    result.metadata.filename,
                    result.metadata.package_name,
                    sha256,
                    result.metadata.version_name,
                    result.risk.score,
                    result.risk.level,
                ),
            )
            analysis_id = int(cursor.lastrowid)
            connection.executemany(
                """INSERT INTO findings
                (analysis_id, category, indicator, severity, score, description)
                VALUES (?, ?, ?, ?, ?, ?)""",
                [
                    (analysis_id, f.category, f.indicator, f.severity, f.score, f.description)
                    for f in result.findings
                ],
            )
            permission_findings = {f.indicator: f for f in result.findings if f.category == "Permission"}
            connection.executemany(
                """INSERT INTO permissions (analysis_id, permission, severity, description)
                VALUES (?, ?, ?, ?)""",
                [
                    (
                        analysis_id,
                        permission,
                        permission_findings.get(permission).severity if permission in permission_findings else "INFO",
                        permission_findings.get(permission).description if permission in permission_findings else "No configured rule.",
                    )
                    for permission in result.manifest.permissions
                ],
            )
            network_findings = [f for f in result.findings if f.category in {"HTTP endpoint", "HTTPS endpoint", "Raw IP address", "Unusual domain pattern"}]
            connection.executemany(
                """INSERT INTO network_indicators
                (analysis_id, indicator, indicator_type, severity, description)
                VALUES (?, ?, ?, ?, ?)""",
                [(analysis_id, f.indicator, f.category, f.severity, f.description) for f in network_findings],
            )
            component_rows = []
            for component_type, values in (("Activity", result.manifest.activities), ("Service", result.manifest.services), ("Receiver", result.manifest.receivers), ("Provider", result.manifest.providers)):
                component_rows.extend((analysis_id, component_type, value, "Unknown") for value in values)
            connection.executemany(
                """INSERT INTO components (analysis_id, component_type, component_name, exported)
                VALUES (?, ?, ?, ?)""", component_rows,
            )
        return analysis_id

    def get_history(self, search_text: str = "") -> list[dict[str, Any]]:
        """Return recent history, optionally filtering name/package/level."""
        pattern = f"%{search_text.strip()}%"
        with self._connection() as connection:
            rows = connection.execute(
                """SELECT id, apk_name, package_name, risk_score, threat_level, analysis_date
                FROM analyses
                WHERE apk_name LIKE ? OR package_name LIKE ? OR threat_level LIKE ?
                ORDER BY id DESC""",
                (pattern, pattern, pattern),
            ).fetchall()
        return [dict(row) for row in rows]

    def history_dataframe(self) -> pd.DataFrame:
        """Provide history as a DataFrame for charting and summary statistics."""
        return pd.DataFrame(self.get_history())

    def delete_analysis(self, analysis_id: int) -> None:
        """Delete one analysis and its child records using parameterized SQL."""
        with self._connection() as connection:
            connection.execute("DELETE FROM findings WHERE analysis_id = ?", (analysis_id,))
            connection.execute("DELETE FROM permissions WHERE analysis_id = ?", (analysis_id,))
            connection.execute("DELETE FROM components WHERE analysis_id = ?", (analysis_id,))
            connection.execute("DELETE FROM network_indicators WHERE analysis_id = ?", (analysis_id,))
            connection.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
