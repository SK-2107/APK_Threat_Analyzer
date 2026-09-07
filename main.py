"""Entry point for the APK Threat Analyzer desktop application.

The completed phases provide safe file selection, static APK metadata parsing,
and configurable heuristic threat indicators.
"""

from gui.app import APKThreatAnalyzerApp
from utils.logger import get_logger


def main() -> None:
    """Start the desktop application."""
    get_logger().info("Application started")
    app = APKThreatAnalyzerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
