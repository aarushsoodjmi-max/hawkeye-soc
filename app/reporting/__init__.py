"""
HawkEye SOC - Reporting & Threat Intelligence Module
=====================================================

Standalone, dependency-free module responsible for converting analyzed
security incidents into structured SOC reports, business-readable
executive summaries, and MITRE ATT&CK-style threat intelligence
mappings.

This package intentionally does NOT contain:
  - Any web framework (FastAPI, Flask, etc.)
  - Any frontend / UI code
  - Any integration with other HawkEye SOC modules

It is pure Python, uses only the standard library, and produces JSON
as its sole output format.

Modules
-------
report_generator.py   : Builds structured incident reports.
executive_summary.py  : Builds business-readable narrative summaries.
threat_intelligence.py: Maps detection techniques to ATT&CK stages.
json_export.py        : Persists report dictionaries as JSON files.
sample_reports.py      : Generates 5 realistic demo incident reports.
"""
