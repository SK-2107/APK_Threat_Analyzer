"""Shared visual tokens for the desktop interface."""

from __future__ import annotations

import customtkinter as ctk
from tkinter import font as tkfont


class Theme:
    """Centralized colors, typography, and severity presentation."""

    NAVY = "#10243F"
    NAVY_HOVER = "#1B365B"
    BLUE = "#2563EB"
    BLUE_HOVER = "#1D4ED8"
    BACKGROUND = "#F3F6FB"
    SURFACE = "#FFFFFF"
    SUBTLE = "#F8FAFC"
    TEXT = "#152238"
    MUTED = "#64748B"
    BORDER = "#E2E8F0"
    FONT = "Inter"
    FALLBACK = "Segoe UI"
    _resolved_font: str | None = None
    SEVERITY = {
        "CRITICAL": ("#FEE2E2", "#B91C1C"),
        "HIGH": ("#FFEDD5", "#C2410C"),
        "MEDIUM": ("#FEF3C7", "#A16207"),
        "LOW": ("#DBEAFE", "#1D4ED8"),
        "INFO": ("#E2E8F0", "#475569"),
    }

    @classmethod
    def font(cls, size: int, weight: str = "normal") -> ctk.CTkFont:
        """Use Inter when installed, with Windows' Segoe UI as fallback."""
        if cls._resolved_font is None:
            installed_fonts = set(tkfont.families())
            cls._resolved_font = cls.FONT if cls.FONT in installed_fonts else cls.FALLBACK
        return ctk.CTkFont(family=cls._resolved_font, size=size, weight=weight)

    @classmethod
    def severity_colors(cls, severity: str) -> tuple[str, str]:
        """Return background and foreground colors for a severity badge."""
        return cls.SEVERITY.get(severity.upper(), cls.SEVERITY["INFO"])
