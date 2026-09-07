"""Reusable CustomTkinter UI components."""

from __future__ import annotations

import customtkinter as ctk

from gui.theme import Theme


def section_card(parent: ctk.CTkBaseClass, title: str, subtitle: str = "") -> ctk.CTkFrame:
    """Create a white rounded section card with an optional explanation."""
    card = ctk.CTkFrame(parent, fg_color=Theme.SURFACE, corner_radius=14, border_width=1, border_color=Theme.BORDER)
    ctk.CTkLabel(card, text=title, text_color=Theme.TEXT, font=Theme.font(16, "bold"), anchor="w").pack(fill="x", padx=18, pady=(16, 2))
    if subtitle:
        description = ctk.CTkLabel(card, text=subtitle, text_color=Theme.MUTED, justify="left", anchor="w", font=Theme.font(12))
        description.pack(fill="x", padx=18, pady=(0, 14))

        def fit_text(event) -> None:
            """Keep explanatory text inside cards at every window width."""
            description.configure(wraplength=max(160, event.width - 36))

        card.bind("<Configure>", fit_text)
    return card


def severity_badge(parent: ctk.CTkBaseClass, severity: str) -> ctk.CTkLabel:
    """Return a consistent severity badge."""
    background, foreground = Theme.severity_colors(severity)
    return ctk.CTkLabel(parent, text=severity.upper(), fg_color=background, text_color=foreground, corner_radius=8, font=Theme.font(10, "bold"), width=70, height=25)


def stat_card(parent: ctk.CTkBaseClass, label: str, value: str, note: str, color: str = Theme.BLUE) -> ctk.CTkFrame:
    """Create a compact dashboard metric card."""
    card = ctk.CTkFrame(parent, fg_color=Theme.SURFACE, corner_radius=14, border_width=1, border_color=Theme.BORDER)
    ctk.CTkLabel(card, text=label.upper(), text_color=Theme.MUTED, font=Theme.font(10, "bold")).pack(anchor="w", padx=15, pady=(14, 3))
    ctk.CTkLabel(card, text=value, text_color=color, font=Theme.font(24, "bold")).pack(anchor="w", padx=15)
    ctk.CTkLabel(card, text=note, text_color=Theme.MUTED, wraplength=155, justify="left", font=Theme.font(10)).pack(anchor="w", padx=15, pady=(2, 14))
    return card
