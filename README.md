# APK Threat Analyzer & Risk Assessment Platform

A desktop application for **safe static analysis of Android APK files**. It helps users inspect an APK's metadata, requested permissions, Android components, suspicious APIs, and network-related indicators without installing or running the APK.

> Important: this tool produces **heuristic risk indicators**, not a malware verdict. A high score means the APK deserves closer review; it does not prove that the APK is malicious.

## What the Project Does

- Validates APK files before analysis.
- Calculates a SHA-256 file hash for integrity identification.
- Reads `AndroidManifest.xml` information through Androguard.
- Extracts app metadata, permissions, activities, services, receivers, and providers.
- Detects configured permission, API, URL/domain, and component indicators.
- Calculates an explainable risk score from 0 to 100.
- Saves completed analyses locally in an SQLite database.
- Provides searchable history, findings, permission views, charts, and a professional Word report.

The application is offline and **never installs, launches, or executes an APK**.

## Requirements

- Windows 10/11
- Python 3.10 or later
- Python installed with the **Tcl/Tk** feature enabled (required by CustomTkinter)

## Installation

Open PowerShell in the project folder and run:

```powershell
cd C:\APK_Threat_Analyzer
python -m pip install -r requirements.txt
```

## Run the Application

```powershell
cd C:\APK_Threat_Analyzer
python main.py
```

If `python main.py` reports that Tcl/Tk or `init.tcl` is missing, repair or reinstall Python and ensure **tcl/tk and IDLE** is selected in the Python installer.

## How to Use

1. Open **Analyze APK** from the sidebar.
2. Click **Browse APK** and choose an `.apk` file you are authorized to inspect.
3. Optionally select **Validate + SHA-256** to confirm the file is a valid APK archive and calculate its fingerprint.
4. Click **Run Static Analysis**.
5. Review the results in Dashboard, Permissions, and Threat Findings.
6. Open **Reports** and click **Generate Word Report (.docx)**.

Generated reports are saved in `reports/generated/`. Analysis history is stored locally in `data/analysis_history.db`.

## Understanding the Dashboard

The dashboard presents the latest completed analysis:

| Item | Meaning |
| --- | --- |
| Risk score | Combined score from configured heuristic indicators, capped at 100. |
| Threat level | LOW, MEDIUM, HIGH, or CRITICAL score band. |
| Permissions | Capabilities requested by the app in its manifest. |
| Suspicious APIs | Static DEX-string patterns that may require review. |
| Network indicators | HTTP endpoints, raw IP URLs, and unusual domain patterns found statically. |
| Components | Activities, services, receivers, and providers declared by the APK. |

### Risk Levels

| Score | Level | Suggested interpretation |
| --- | --- | --- |
| 0–20 | LOW | Few configured indicators were found. |
| 21–40 | MEDIUM | Review the findings and app purpose. |
| 41–70 | HIGH | Prioritize a closer security review. |
| 71–100 | CRITICAL | Urgent review recommended. |

## Pages in the Application

- **Dashboard** — latest risk summary, metrics, and finding charts.
- **Analyze APK** — APK selection, validation, SHA-256, and static analysis workflow.
- **Permissions** — searchable list of requested permissions with severity and explanations.
- **Threat Findings** — searchable and filterable heuristic indicators; each has a details dialog.
- **History** — locally saved analyses with search and safe record deletion.
- **Reports** — generates a formatted Microsoft Word `.docx` static assessment report.
- **About** — explains the workflow, technology used, DSA concepts, scoring, and limitations.

## Project Phases

### Phase 1 — Project Setup and GUI Shell

- Modular Python project structure.
- CustomTkinter desktop interface and sidebar navigation.
- Dashboard, analysis, permissions, findings, history, reports, and about pages.

### Phase 2 — APK Validation and SHA-256

- Checks that a file exists, has an `.apk` extension, is non-empty, and is ZIP/APK based.
- Checks for `AndroidManifest.xml`.
- Computes SHA-256 in chunks using Python's `hashlib`.

### Phase 3 — Manifest and Metadata Analysis

- Uses **Androguard** to inspect the APK without executing it.
- Extracts package name, application name, version, SDK values, main activity, permissions, and Android components.

### Phase 4 — Heuristic Threat Indicators

- Configurable rules in `security/threat_rules.json`.
- Permission-risk, suspicious API, HTTP URL, raw IP, unusual TLD, and component indicators.
- Findings explain their severity, score contribution, reason, source, and recommendation.

### Phase 5 — Data Structures and Algorithms

- Dictionary lookups for rules.
- Severity sorting and heap-based priority queues for findings.
- Optional APK-to-category-to-indicator graph.

### Phase 6 — Explainable Risk Scoring

- Score contributions are added from each configured finding.
- The raw total is capped at 100.
- The result includes a risk level and contributor explanation.

### Phase 7 — Local SQLite History

- Parameterized SQLite storage for analyses, permissions, and findings.
- Searchable history and delete support.
- Pandas-ready history summaries.

### Phase 8 — Dashboard and Charts

- Dashboard metric cards and Matplotlib severity/category charts.
- Clear guidance for users who are new to APK analysis.

### Phase 9 — Modern UI/UX

- Centralized theme and reusable UI components.
- Responsive cards, searchable views, severity badges, dialogs, and a compact History layout.

### Phase 10 — Professional Reports

- Formatted Microsoft Word reports using `python-docx`.
- Includes summary, metadata, SHA-256, risk assessment, contributors, permissions, findings, components, network indicators, and limitations.

## Key Terms

- **APK**: Android Package Kit, the file format used to distribute Android apps.
- **AndroidManifest.xml**: an APK file that declares the app's identity, permissions, components, and SDK requirements.
- **SHA-256**: a 64-character cryptographic fingerprint. If a file changes, its SHA-256 value changes.
- **Static analysis**: inspecting file contents without running the file.
- **Heuristic assessment**: rule-based estimation using observable indicators, rather than a guaranteed conclusion.
- **Androguard**: the Python library used to parse APK/DEX content safely.
- **DEX**: Android's compiled application-code format inside an APK.

## Project Structure

```text
APK_Threat_Analyzer/
├── analyzer/       # APK, manifest, permission, API, URL, and component analysis
├── database/       # SQLite history management
├── dsa/            # Priority queue, sorting, and graph concepts
├── gui/            # CustomTkinter app, theme, and reusable components
├── reports/        # Word report generators and generated reports
├── security/       # Rules, finding model, detection, and risk scoring
├── tests/          # Safe automated tests
├── utils/          # Validation, hashing, and logging helpers
├── main.py         # Application entry point
└── requirements.txt
```

## Testing

Run the safe unit tests with:

```powershell
cd C:\APK_Threat_Analyzer
python -m unittest discover -s tests -v
```

## Limitations

- Static analysis cannot observe run-time behavior.
- The rules may produce false positives or miss unknown threats.
- A permission or API use can be legitimate depending on the app's purpose.
- The tool does not replace professional malware analysis, sandboxing, or antivirus scanning.

## Safety and Ethics

Analyze only APK files you own or are authorized to inspect. Do not use this tool to target others or bypass application security.
