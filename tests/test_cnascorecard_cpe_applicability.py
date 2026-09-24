#!/usr/bin/env python3
"""
Test CPE applicability detection.

Tests three scenarios:
1. CVE with traditional affected[].cpes field (IBM CVE-2025-0163)
2. CVE with new cpeApplicability field (Lenovo CVE-2025-2502)
3. CVE with no CPE data (should score 0)
"""

import json
from pathlib import Path

import pytest
from cnascorecard_pipeline.scoring import score_cve_record


REPO_ROOT = Path(__file__).parent.parent
CVE_DATA_DIR = REPO_ROOT / "cve_data"


def _cve_path(relative: str) -> Path:
    return CVE_DATA_DIR / "cves" / relative


def _assert_cpe_scenario(cve_path: Path, expected_score: int, label: str) -> None:
    if not cve_path.exists():
        pytest.skip(f"Test CVE not found at {cve_path}")
    with open(cve_path) as f:
        cve = json.load(f)
    result = score_cve_record(cve)
    software_score = result["scoreBreakdown"]["softwareIdentification"]
    assert software_score == expected_score, f"{label}: expected {expected_score} points, got {software_score}"


def test_traditional_cpes():
    """CVE with traditional affected[].cpes field - IBM example."""
    _assert_cpe_scenario(
        _cve_path(Path("2025") / "0xxx" / "CVE-2025-0163.json"),
        10,
        "traditional cpes",
    )


def test_cpe_applicability():
    """CVE with cpeApplicability field - Lenovo example."""
    _assert_cpe_scenario(
        _cve_path(Path("2025") / "2xxx" / "CVE-2025-2502.json"),
        10,
        "cpeApplicability",
    )


def test_no_cpes():
    """CVE with no CPE data - should score 0."""
    cve = {
        "cveId": "CVE-TEST-0001",
        "cveMetadata": {
            "cveId": "CVE-TEST-0001",
            "assignerOrgId": "test-org",
            "state": "PUBLISHED",
            "datePublished": "2025-01-01T00:00:00.000Z",
        },
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Test CVE without CPE data"}],
                "affected": [{"vendor": "Test", "product": "Test"}],
                "references": [{"url": "http://test.com"}],
                "providerMetadata": {"orgId": "test-org", "shortName": "test"},
            }
        },
    }

    result = score_cve_record(cve)
    software_score = result["scoreBreakdown"]["softwareIdentification"]
    assert software_score == 0, f"Expected 0 points for no CPEs, got {software_score}"


def main() -> int:
    """Run the three scenarios as a standalone script and report results."""
    scenarios = {
        "Traditional cpes": _cve_path(Path("2025") / "0xxx" / "CVE-2025-0163.json"),
        "cpeApplicability": _cve_path(Path("2025") / "2xxx" / "CVE-2025-2502.json"),
    }
    passed = 0
    for label, cve_path in scenarios.items():
        if not cve_path.exists():
            print(f"SKIP: {label} ({cve_path} not found)")
            continue
        _assert_cpe_scenario(cve_path, 10, label)
        print(f"PASS: {label}")
        passed += 1

    cve = {
        "cveId": "CVE-TEST-0001",
        "cveMetadata": {
            "cveId": "CVE-TEST-0001",
            "assignerOrgId": "test-org",
            "state": "PUBLISHED",
            "datePublished": "2025-01-01T00:00:00.000Z",
        },
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Test CVE without CPE data"}],
                "affected": [{"vendor": "Test", "product": "Test"}],
                "references": [{"url": "http://test.com"}],
                "providerMetadata": {"orgId": "test-org", "shortName": "test"},
            }
        },
    }
    result = score_cve_record(cve)
    assert result["scoreBreakdown"]["softwareIdentification"] == 0
    print("PASS: No CPE data")
    passed += 1

    print(f"Results: {passed}/{len(scenarios) + 1} tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
