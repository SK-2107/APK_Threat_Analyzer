"""Professional CustomTkinter interface for static APK assessment."""

from __future__ import annotations

from pathlib import Path
from threading import Thread
from tkinter import filedialog

import customtkinter as ctk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from analyzer.apk_analyzer import APKAnalysisError, APKAnalysisResult, APKStaticAnalyzer
from database.database_manager import DatabaseManager
from gui.components import section_card, severity_badge, stat_card
from gui.theme import Theme
from reports.docx_report_generator import generate_report
from utils.hashing import calculate_sha256
from utils.logger import get_logger
from utils.validators import APKValidationError, validate_apk_file


class APKThreatAnalyzerApp(ctk.CTk):
    """Main window. Presentation is separate from existing analysis logic."""

    PAGES = ("Dashboard", "Analyze APK", "Permissions", "Threat Findings", "History", "Reports", "About")

    def __init__(self) -> None:
        super().__init__()
        self.title("APK Threat Analyzer & Risk Assessment Platform")
        self.geometry("1240x760")
        self.minsize(1020, 650)
        ctk.set_appearance_mode("light")
        self.configure(fg_color=Theme.BACKGROUND)
        root = Path(__file__).resolve().parents[1]
        self.database = DatabaseManager(root / "data" / "analysis_history.db")
        self.report_folder = root / "reports" / "generated"
        self.logger = get_logger()
        self.selected_file: Path | None = None
        self.analysis_result: APKAnalysisResult | None = None
        self.current_hash = ""
        self.nav: dict[str, ctk.CTkButton] = {}
        self._build_shell()
        self.show_page("Dashboard")

    def _build_shell(self) -> None:
        sidebar = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=Theme.NAVY)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        ctk.CTkLabel(sidebar, text="APK THREAT\nANALYZER", text_color="white", justify="left", font=Theme.font(23, "bold")).pack(anchor="w", padx=25, pady=(34, 4))
        ctk.CTkLabel(sidebar, text="Static risk assessment", text_color="#B8C7DB", font=Theme.font(12)).pack(anchor="w", padx=25, pady=(0, 28))
        for page in self.PAGES:
            button = ctk.CTkButton(sidebar, text=page, command=lambda name=page: self.show_page(name), anchor="w", height=42, corner_radius=9, fg_color="transparent", hover_color=Theme.NAVY_HOVER, text_color="#E7EDF7", font=Theme.font(13))
            button.pack(fill="x", padx=14, pady=3)
            self.nav[page] = button
        ctk.CTkLabel(sidebar, text="OFFLINE MODE\nAPKs are never executed", text_color="#94A9C5", justify="left", font=Theme.font(10, "bold")).pack(side="bottom", anchor="w", padx=25, pady=24)

        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(side="left", fill="both", expand=True, padx=26, pady=24)
        self.title_label = ctk.CTkLabel(main, text="", text_color=Theme.TEXT, font=Theme.font(30, "bold"))
        self.title_label.pack(anchor="w")
        self.subtitle_label = ctk.CTkLabel(main, text="", text_color=Theme.MUTED, wraplength=820, justify="left", font=Theme.font(13))
        self.subtitle_label.pack(anchor="w", pady=(2, 16))
        self.page = ctk.CTkFrame(main, fg_color="transparent")
        self.page.pack(fill="both", expand=True)

    def show_page(self, name: str) -> None:
        """Switch page while retaining the latest analysis in memory."""
        for child in self.page.winfo_children():
            child.destroy()
        for page, button in self.nav.items():
            button.configure(fg_color=Theme.BLUE if page == name else "transparent")
        headings = {
            "Dashboard": ("Dashboard", "Understand the latest APK assessment at a glance."),
            "Analyze APK": ("Analyze APK", "Select an Android APK. It is read statically and never installed or executed."),
            "Permissions": ("Permissions", "Capabilities requested by the application. A permission alone is not proof of risk."),
            "Threat Findings": ("Threat Findings", "Heuristic indicators ranked by priority. They require review; they are not malware conclusions."),
            "History": ("Analysis History", "Previous analyses saved locally in SQLite."),
            "Reports": ("Reports", "Export a clear text record of the latest analysis."),
            "About": ("About the Project", "Purpose, workflow, technology stack, DSA use, and limitations."),
        }
        self.title_label.configure(text=headings[name][0])
        self.subtitle_label.configure(text=headings[name][1])
        getattr(self, f"_page_{name.lower().replace(' ', '_')}")()

    def _page_dashboard(self) -> None:
        if not self.analysis_result:
            card = section_card(self.page, "Start a safe static analysis", "Choose an APK, validate it, then review its permissions, indicators, score, and report.")
            card.pack(fill="x", pady=8)
            ctk.CTkButton(card, text="Analyze an APK", command=lambda: self.show_page("Analyze APK"), fg_color=Theme.BLUE, hover_color=Theme.BLUE_HOVER, height=38).pack(anchor="w", padx=18, pady=(0, 18))
            self._workflow_cards()
            return
        result = self.analysis_result
        badge_bg, badge_fg = Theme.severity_colors(result.risk.level)
        hero = ctk.CTkFrame(self.page, fg_color=badge_bg, corner_radius=16)
        hero.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(hero, text="LATEST ASSESSMENT", text_color=badge_fg, font=Theme.font(10, "bold")).pack(anchor="w", padx=20, pady=(17, 3))
        ctk.CTkLabel(hero, text=f"{result.risk.level} RISK  |  {result.risk.score}/100", text_color=Theme.TEXT, font=Theme.font(25, "bold")).pack(anchor="w", padx=20)
        ctk.CTkLabel(hero, text=f"{result.metadata.filename}  |  {result.metadata.package_name}", text_color=Theme.MUTED, font=Theme.font(12)).pack(anchor="w", padx=20, pady=(2, 16))
        ctk.CTkButton(hero, text="Explain Risk Score", command=self._show_score_dialog, fg_color=Theme.SURFACE, text_color=badge_fg, hover_color="#F8FAFC", height=32).pack(anchor="e", padx=20, pady=(0, 16))
        stats = ctk.CTkFrame(self.page, fg_color="transparent")
        stats.pack(fill="x", pady=(0, 12))
        network_count = sum(1 for f in result.findings if "endpoint" in f.category.lower() or "ip" in f.category.lower() or "domain" in f.category.lower())
        api_count = sum(1 for f in result.findings if f.source == "DEX string search")
        component_count = len(result.manifest.activities) + len(result.manifest.services) + len(result.manifest.receivers) + len(result.manifest.providers)
        cards = (("Risk Score", f"{result.risk.score}/100", "Heuristic score", badge_fg), ("Permissions", str(len(result.manifest.permissions)), "Requested capabilities", Theme.BLUE), ("Suspicious APIs", str(api_count), "Static API patterns", "#C2410C"), ("Network", str(network_count), "Network indicators", "#A16207"), ("Components", str(component_count), "Android components", "#475569"))
        for label, value, note, color in cards:
            stat_card(stats, label, value, note, color).pack(side="left", fill="both", expand=True, padx=3)
        self._dashboard_charts(result)

    def _workflow_cards(self) -> None:
        panel = ctk.CTkFrame(self.page, fg_color="transparent")
        panel.pack(fill="x", pady=8)
        for title, text in (("1. Select", "Choose an APK from your computer."), ("2. Analyze", "Validate it and inspect it statically."), ("3. Review", "Understand permissions, findings, score, and report.")):
            card = section_card(panel, title, text)
            card.pack(side="left", fill="both", expand=True, padx=4)

    def _dashboard_charts(self, result: APKAnalysisResult) -> None:
        row = ctk.CTkFrame(self.page, fg_color="transparent")
        row.pack(fill="both", expand=True)
        categories: dict[str, int] = {}
        severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in result.findings:
            severity[finding.severity] = severity.get(finding.severity, 0) + 1
            categories[finding.category] = categories.get(finding.category, 0) + 1
        self._chart_card(row, "Severity distribution", severity, ["#B91C1C", "#C2410C", "#A16207", "#2563EB", "#64748B"]).pack(side="left", fill="both", expand=True, padx=(0, 6))
        self._chart_card(row, "Threat category distribution", categories, ["#2563EB", "#7C3AED", "#C2410C", "#0891B2", "#A16207"]).pack(side="left", fill="both", expand=True, padx=(6, 0))

    def _chart_card(self, parent: ctk.CTkFrame, title: str, values: dict[str, int], colors: list[str]) -> ctk.CTkFrame:
        card = section_card(parent, title, "Counts from the current analysis.")
        figure = Figure(figsize=(4.4, 2.5), dpi=100, facecolor="white")
        axis = figure.add_subplot(111)
        labels = list(values.keys()) or ["None"]
        counts = list(values.values()) or [0]
        axis.bar(range(len(labels)), counts, color=colors[:len(labels)])
        axis.set_xticks(range(len(labels)), [self._shorten(label, 12) for label in labels], rotation=25, ha="right", fontsize=8)
        axis.set_ylabel("Count", fontsize=8)
        axis.spines[["top", "right"]].set_visible(False)
        figure.tight_layout()
        canvas = FigureCanvasTkAgg(figure, master=card)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=(0, 8))
        return card

    def _page_analyze_apk(self) -> None:
        steps = section_card(self.page, "Analysis workflow", "1. Select APK  2. Validate archive  3. Calculate SHA-256  4. Parse manifest  5. Detect indicators  6. Score and save")
        steps.pack(fill="x", pady=(0, 10))
        selector = section_card(self.page, "Select an APK", "Only select APK files you are authorized to inspect.")
        selector.pack(fill="x", pady=(0, 10))
        self.file_label = ctk.CTkLabel(selector, text=self._file_text(), text_color=Theme.MUTED, wraplength=760, justify="left", font=Theme.font(12))
        self.file_label.pack(anchor="w", padx=18)
        ctk.CTkButton(selector, text="Browse APK", command=self._choose_file, fg_color=Theme.BLUE, hover_color=Theme.BLUE_HOVER).pack(anchor="w", padx=18, pady=14)
        actions = ctk.CTkFrame(self.page, fg_color="transparent")
        actions.pack(fill="x", pady=(0, 10))
        ctk.CTkButton(actions, text="Validate + SHA-256", command=self._validate, fg_color="#E2E8F0", text_color=Theme.TEXT, hover_color="#CBD5E1").pack(side="left")
        ctk.CTkButton(actions, text="Run Static Analysis", command=self._start_analysis, fg_color=Theme.BLUE, hover_color=Theme.BLUE_HOVER).pack(side="left", padx=8)
        ctk.CTkButton(actions, text="Explain Risk Score", command=self._show_score_dialog, fg_color="#FFF7ED", text_color="#9A3412", hover_color="#FFEDD5").pack(side="left")
        self.status = ctk.CTkLabel(self.page, text="Ready. APKs are treated as untrusted files and are never executed.", text_color=Theme.MUTED, font=Theme.font(12))
        self.status.pack(anchor="w", pady=(0, 8))
        output = section_card(self.page, "Analysis Output", "Metadata, component counts, and the risk summary appear here after analysis.")
        output.pack(fill="both", expand=True)
        self.output = ctk.CTkTextbox(output, fg_color="#0F172A", text_color="#E2E8F0", corner_radius=10, wrap="word")
        self.output.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self._set_text(self.output, self.analysis_result.summary_text(self.current_hash) if self.analysis_result else "No analysis has been run yet.")

    def _page_permissions(self) -> None:
        self._page_findings(mode="permissions")

    def _page_threat_findings(self) -> None:
        self._page_findings(mode="findings")

    def _page_findings(self, mode: str) -> None:
        if not self.analysis_result:
            self._empty_state("No analysis data yet", "Analyze an APK first, then come back to review this information.")
            return
        toolbar = ctk.CTkFrame(self.page, fg_color="transparent")
        toolbar.pack(fill="x", pady=(0, 10))
        search = ctk.CTkEntry(toolbar, placeholder_text="Search by permission, category, API, URL, or text", height=38)
        search.pack(side="left", fill="x", expand=True)
        severity_filter = ctk.CTkOptionMenu(toolbar, values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], width=115)
        severity_filter.pack(side="left", padx=8)
        sort_option = ctk.CTkOptionMenu(toolbar, values=["Severity", "Score", "Category"], width=110)
        sort_option.pack(side="left")
        scroll = ctk.CTkScrollableFrame(self.page, fg_color=Theme.SUBTLE, corner_radius=14)
        scroll.pack(fill="both", expand=True)
        def refresh(*_args: object) -> None:
            for child in scroll.winfo_children(): child.destroy()
            items = self._permission_items() if mode == "permissions" else list(self.analysis_result.findings)
            term = search.get().lower().strip()
            chosen = severity_filter.get()
            items = [item for item in items if (chosen == "All" or item.severity == chosen) and (not term or term in f"{item.category} {item.indicator} {item.description}".lower())]
            if sort_option.get() == "Score": items.sort(key=lambda item: item.score, reverse=True)
            elif sort_option.get() == "Category": items.sort(key=lambda item: (item.category, item.indicator))
            for item in items: self._finding_row(scroll, item)
            if not items: ctk.CTkLabel(scroll, text="No matching results.", text_color=Theme.MUTED).pack(padx=18, pady=20)
        search.bind("<KeyRelease>", refresh)
        severity_filter.configure(command=lambda _value: refresh())
        sort_option.configure(command=lambda _value: refresh())
        refresh()

    def _permission_items(self):
        findings = {item.indicator: item for item in self.analysis_result.findings if item.category == "Permission"}
        return [findings.get(permission, self._info_permission(permission)) for permission in self.analysis_result.manifest.permissions]

    @staticmethod
    def _info_permission(permission: str):
        from security.models import Finding
        return Finding("Permission", permission, "INFO", 0, "No configured heuristic rule for this permission.")

    def _finding_row(self, parent: ctk.CTkScrollableFrame, finding) -> None:
        row = ctk.CTkFrame(parent, fg_color=Theme.SURFACE, corner_radius=10)
        row.pack(fill="x", padx=7, pady=5)
        badge = severity_badge(row, finding.severity); badge.pack(side="left", anchor="n", padx=(12, 10), pady=12)
        details = ctk.CTkFrame(row, fg_color="transparent"); details.pack(side="left", fill="x", expand=True, pady=10)
        ctk.CTkLabel(details, text=self._shorten(finding.indicator, 95), text_color=Theme.TEXT, anchor="w", font=Theme.font(13, "bold")).pack(fill="x")
        ctk.CTkLabel(details, text=f"{finding.category} | Score +{finding.score} | {finding.source}", text_color=Theme.MUTED, anchor="w", font=Theme.font(11)).pack(fill="x", pady=(2, 1))
        ctk.CTkLabel(details, text=finding.description, text_color="#475569", wraplength=520, justify="left", anchor="w", font=Theme.font(12)).pack(fill="x")
        ctk.CTkButton(row, text="Details", width=70, height=28, fg_color="#EEF4FF", text_color=Theme.BLUE, hover_color="#DBEAFE", command=lambda item=finding: self._finding_dialog(item)).pack(side="right", padx=12)

    def _page_history(self) -> None:
        card = section_card(self.page, "Saved Analyses", "Search by APK name, package name, or threat level. Delete removes the database record only, not the original APK.")
        card.pack(fill="x")
        search = ctk.CTkEntry(card, placeholder_text="Search history", height=38); search.pack(fill="x", padx=18, pady=(0, 10))
        table = ctk.CTkScrollableFrame(card, fg_color=Theme.SUBTLE, corner_radius=10, height=270); table.pack(fill="x", padx=18, pady=(0, 18))
        def refresh(*_args: object) -> None:
            for child in table.winfo_children(): child.destroy()
            rows = self.database.get_history(search.get())
            if not rows: ctk.CTkLabel(table, text="No analysis history available.", text_color=Theme.MUTED).pack(pady=20); return
            header = ctk.CTkFrame(table, fg_color="#EAF0F9", corner_radius=8); header.pack(fill="x", padx=4, pady=(4, 5))
            for text, width in (("ID", 45), ("APK Name", 210), ("Package", 225), ("Score", 65), ("Level", 85), ("Date", 150)):
                ctk.CTkLabel(header, text=text, width=width, anchor="w", text_color=Theme.MUTED, font=Theme.font(10, "bold")).pack(side="left", padx=4, pady=8)
            for row in rows:
                item = ctk.CTkFrame(table, fg_color=Theme.SURFACE, corner_radius=8); item.pack(fill="x", padx=4, pady=3)
                values = (str(row["id"]), self._shorten(row["apk_name"], 25), self._shorten(row["package_name"], 28), str(row["risk_score"]), row["threat_level"], str(row["analysis_date"]))
                widths = (45, 210, 225, 65, 85, 150)
                for value, width in zip(values, widths): ctk.CTkLabel(item, text=value, width=width, anchor="w", text_color=Theme.TEXT, font=Theme.font(11)).pack(side="left", padx=4, pady=8)
                ctk.CTkButton(item, text="Delete", width=62, height=26, fg_color="#FEE2E2", text_color="#B91C1C", hover_color="#FECACA", command=lambda ident=row["id"]: self._delete_history(ident, refresh)).pack(side="right", padx=7)
        search.bind("<KeyRelease>", refresh); refresh()

    def _page_reports(self) -> None:
        card = section_card(self.page, "Generate a Professional Assessment Report", "The report is a formatted Microsoft Word document (.docx) containing the latest static analysis. It does not certify an APK as safe or malicious.")
        card.pack(fill="x", pady=(0, 12))
        if self.analysis_result:
            status = f"Ready: {self.analysis_result.metadata.filename} | {self.analysis_result.risk.level} risk | {self.analysis_result.risk.score}/100"; color = "#15803D"
        else:
            status = "No completed analysis is currently available. Analyze an APK first."; color = "#B91C1C"
        message = ctk.CTkLabel(card, text=status, text_color=color, font=Theme.font(12, "bold")); message.pack(anchor="w", padx=18, pady=(0, 12))
        ctk.CTkButton(card, text="Generate Word Report (.docx)", fg_color=Theme.BLUE, hover_color=Theme.BLUE_HOVER, command=lambda: self._generate_report(message)).pack(anchor="w", padx=18, pady=(0, 18))
        details = ctk.CTkFrame(self.page, fg_color="transparent"); details.pack(fill="x")
        for title, text in (("Where is it saved?", str(self.report_folder)), ("What is included?", "Metadata, SHA-256, permissions, findings, components, network indicators, score, and limitations."), ("When to use it?", "For a record of your review, demonstration, or viva discussion.")):
            section_card(details, title, text).pack(side="left", fill="both", expand=True, padx=4)

    def _page_about(self) -> None:
        intro = section_card(self.page, "Static assessment, not a malware verdict", "The application reads an APK as an untrusted file. It never installs, launches, or executes the APK.")
        intro.pack(fill="x", pady=(0, 10))
        grid = ctk.CTkFrame(self.page, fg_color="transparent"); grid.pack(fill="both", expand=True)
        cards = (("Project Objective", "Help users inspect an APK's visible metadata, permissions, components, APIs, and network indicators."), ("Technology Stack", "Python, CustomTkinter, Androguard, SQLite, Pandas, Matplotlib, and standard libraries."), ("DSA Used", "SHA-256 hashing, dictionaries for rules, search/filtering, sorting, and a heap priority queue."), ("Risk Scoring", "Configured findings add explainable points. The final score is capped at 100 and mapped to LOW, MEDIUM, HIGH, or CRITICAL."), ("How it Works", "Select APK, validate it, inspect manifest and static strings, rank findings, calculate score, save history, and create reports."), ("Limitations", "Heuristic indicators do not prove malware or safety. Results should be reviewed in the context of the app's intended purpose."))
        for index, (title, text) in enumerate(cards):
            card = section_card(grid, title, text); card.grid(row=index // 2, column=index % 2, sticky="nsew", padx=5, pady=5)
        for index in (0, 1): grid.grid_columnconfigure(index, weight=1)
        for index in range(3): grid.grid_rowconfigure(index, weight=1)

    def _choose_file(self) -> None:
        chosen = filedialog.askopenfilename(title="Select an Android APK", filetypes=[("Android APK files", "*.apk"), ("All files", "*.*")])
        if chosen:
            self.selected_file = Path(chosen); self.file_label.configure(text=self._file_text()); self.status.configure(text="APK selected. Validate it or start static analysis.", text_color=Theme.BLUE); self.logger.info("APK selected: %s", self.selected_file.name)

    def _validate(self) -> None:
        try:
            info = validate_apk_file(self.selected_file); self.current_hash = calculate_sha256(info.path)
            self.status.configure(text=f"Validated: {info.name} | SHA-256 calculated successfully.", text_color="#15803D")
        except (APKValidationError, OSError) as error:
            self.status.configure(text=f"Validation failed: {error}", text_color="#B91C1C")

    def _start_analysis(self) -> None:
        self.status.configure(text="Analysis started. The window remains responsive while the APK is inspected.", text_color=Theme.BLUE)
        Thread(target=self._analysis_worker, daemon=True).start()

    def _analysis_worker(self) -> None:
        try:
            info = validate_apk_file(self.selected_file); file_hash = calculate_sha256(info.path)
            result = APKStaticAnalyzer().analyze(info.path); record_id = self.database.save_analysis(result, file_hash)
        except (APKValidationError, APKAnalysisError, OSError) as error:
            self.logger.exception("Analysis failed"); self.after(0, lambda: self._analysis_error(str(error))); return
        self.analysis_result, self.current_hash = result, file_hash
        self.logger.info("Analysis complete for %s", info.name); self.after(0, lambda: self._analysis_success(record_id))

    def _analysis_success(self, record_id: int) -> None:
        self.status.configure(text=f"Analysis completed and saved as record #{record_id}.", text_color="#15803D")
        self._set_text(self.output, self.analysis_result.summary_text(self.current_hash))

    def _analysis_error(self, message: str) -> None:
        self.status.configure(text=f"Unable to analyze this APK: {message}", text_color="#B91C1C")

    def _show_score_dialog(self) -> None:
        dialog = ctk.CTkToplevel(self); dialog.title("Why This Score?"); dialog.geometry("580x440"); dialog.transient(self)
        ctk.CTkLabel(dialog, text="WHY THIS APK RECEIVED THIS SCORE", text_color=Theme.TEXT, font=Theme.font(18, "bold")).pack(anchor="w", padx=22, pady=(22, 4))
        box = ctk.CTkTextbox(dialog, wrap="word"); box.pack(fill="both", expand=True, padx=22, pady=(8, 22))
        text = "Run static analysis first." if not self.analysis_result else f"Risk score: {self.analysis_result.risk.score}/100\nThreat level: {self.analysis_result.risk.level}\nRaw score: {self.analysis_result.risk.raw_score}\n\nContributors:\n{self.analysis_result.risk.explanation()}\n\nThese are heuristic indicators, not proof of malware."
        self._set_text(box, text)

    def _finding_dialog(self, finding) -> None:
        dialog = ctk.CTkToplevel(self); dialog.title("Finding Details"); dialog.geometry("570x420"); dialog.transient(self)
        card = section_card(dialog, "Finding Details", "Review this result in the context of the application's purpose."); card.pack(fill="both", expand=True, padx=18, pady=18)
        fields = (("Indicator", finding.indicator), ("Category", finding.category), ("Severity", finding.severity), ("Score", f"+{finding.score}"), ("Why it matters", finding.description), ("Recommendation", finding.recommendation), ("Source", finding.source))
        for label, value in fields:
            ctk.CTkLabel(card, text=label.upper(), text_color=Theme.MUTED, font=Theme.font(10, "bold")).pack(anchor="w", padx=18, pady=(7, 0))
            ctk.CTkLabel(card, text=value, text_color=Theme.TEXT, wraplength=480, justify="left", font=Theme.font(12)).pack(anchor="w", padx=18)

    def _generate_report(self, message: ctk.CTkLabel) -> None:
        if not self.analysis_result: message.configure(text="Run an analysis before generating a report.", text_color="#B91C1C"); return
        try:
            path = generate_report(self.analysis_result, self.current_hash, self.report_folder); message.configure(text=f"Saved: {path}", text_color="#15803D"); self.logger.info("Report generated: %s", path.name)
        except OSError:
            self.logger.exception("Report generation failed"); message.configure(text="Unable to save the report. Check the reports folder.", text_color="#B91C1C")

    def _delete_history(self, analysis_id: int, refresh) -> None:
        self.database.delete_analysis(analysis_id); self.logger.info("History record deleted: %s", analysis_id); refresh()

    def _empty_state(self, title: str, text: str) -> None:
        card = section_card(self.page, title, text); card.pack(fill="x", pady=8)
        ctk.CTkButton(card, text="Go to Analyze APK", command=lambda: self.show_page("Analyze APK"), fg_color=Theme.BLUE).pack(anchor="w", padx=18, pady=(0, 18))

    @staticmethod
    def _shorten(value: str, length: int) -> str: return value if len(value) <= length else f"{value[:length - 3]}..."
    @staticmethod
    def _set_text(box: ctk.CTkTextbox, text: str) -> None:
        box.configure(state="normal"); box.delete("1.0", "end"); box.insert("1.0", text); box.configure(state="disabled")
    def _file_text(self) -> str: return f"Selected file: {self.selected_file}" if self.selected_file else "No APK selected yet."
