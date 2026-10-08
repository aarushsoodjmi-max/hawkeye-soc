"""
json_export.py
================

Simple, dependency-free JSON persistence for SOC report dictionaries.

This module performs no formatting/business logic of its own - it only
serializes whatever dict it is given (typically the output of
report_generator.generate_incident_report, optionally enriched with an
executive summary and ATT&CK chain) to a formatted JSON file on disk.
"""

import json
import os
from typing import Any, Dict


def export_report(report: Dict[str, Any], output_path: str) -> str:
    """
    Save a report dict as a formatted (indented, UTF-8) JSON file.

    Creates any missing parent directories for `output_path`.

    Args:
        report: The report dictionary to serialize (must be JSON-serializable).
        output_path: Destination file path, e.g.
            "backend/app/reporting/output/INC-1001.json".

    Returns:
        The absolute path the report was written to.

    Raises:
        TypeError: If `report` contains values that are not JSON-serializable.
        OSError: If the destination path cannot be created/written.
    """
    if report is None:
        raise ValueError("report must not be None")

    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file_handle:
        json.dump(report, file_handle, indent=2, ensure_ascii=False, sort_keys=False)
        file_handle.write("\n")

    return os.path.abspath(output_path)


def export_reports(reports: Dict[str, Dict[str, Any]], output_dir: str) -> Dict[str, str]:
    """
    Convenience helper to export multiple reports at once.

    Args:
        reports: Mapping of {incident_id: report_dict}.
        output_dir: Directory in which to write "<incident_id>.json" files.

    Returns:
        Mapping of {incident_id: absolute_written_path}.
    """
    written_paths: Dict[str, str] = {}
    for incident_id, report in (reports or {}).items():
        path = os.path.join(output_dir, f"{incident_id}.json")
        written_paths[incident_id] = export_report(report, path)
    return written_paths
