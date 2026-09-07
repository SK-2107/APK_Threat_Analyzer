# APK Threat Analyzer – Viva Guide

## What is an APK?

An APK is the package format used to distribute Android applications. It usually contains the Android manifest, compiled code, resources, and certificates.

## What is static analysis?

Static analysis inspects an APK file without installing or running it. This project reads metadata, the manifest, code strings, and embedded URLs only.

## Why analyze permissions?

Permissions show capabilities requested by an app, such as reading SMS messages or accessing location. A permission alone does not mean an app is malicious, but some permissions deserve closer review.

## What is SHA-256 and why is hashing used?

SHA-256 creates a fixed-length fingerprint for a file. If the APK changes, the hash changes. It helps identify the exact file that was analyzed and helps find duplicates.

## Where is DSA used?

- Hashing: SHA-256 file fingerprint.
- Dictionary/hash map: JSON permission and API rules are quickly looked up by key.
- Searching: permission, finding, and history pages support text filtering.
- Sorting: findings are ordered by severity and score.
- Priority queue: a heap prioritizes the most serious findings.
- Graph: an optional adjacency-list graph represents APK → category → indicator relationships.

## Why SQLite?

SQLite is a lightweight local database. It stores analysis history without needing a server, which suits a desktop college project.

## Why use Pandas and Matplotlib?

Pandas converts saved history into tabular data for summaries. Matplotlib creates dashboard charts such as severity distribution. They make analysis results easier to understand.

## What is an exported component?

An exported Android component can be accessed by another application. It is not automatically unsafe, but its input handling and purpose should be reviewed.

## What are network indicators?

Network indicators are URLs, domains, or IP addresses found statically in APK files. HTTP, raw IP addresses, and unusual domain patterns may need review; they do not prove a domain is malicious.

## Why CustomTkinter?

CustomTkinter provides a modern-looking desktop GUI while keeping the project based on standard Python and Tkinter concepts.

## How is the risk score calculated?

Each configurable heuristic rule has a score. Detected findings are added together and capped at 100. Levels are LOW (0–20), MEDIUM (21–40), HIGH (41–70), and CRITICAL (71–100).

## Is this a malware detector?

No. It is a static heuristic risk-assessment tool. It cannot guarantee that an APK is malicious or safe.

## Future improvements

Possible improvements include more configurable rules, richer charts, PDF reports, signing-certificate analysis, and carefully controlled dynamic analysis in a safe sandbox.
