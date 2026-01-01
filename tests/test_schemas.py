"""
Tests for JSON schema validation of output files.

These tests validate that the generated JSON files conform to expected schemas,
ensuring data consistency and catching regressions.
"""

import json
import sys
from pathlib import Path
import pytest
from jsonschema import validate, ValidationError

# Add tests directory to path for importing conftest schemas
sys.path.insert(0, str(Path(__file__).parent))

from conftest import (
    CVE_YEAR_SCHEMA,
    CNA_ANALYSIS_SCHEMA,
    CVSS_ANALYSIS_SCHEMA,
    DATA_QUALITY_SCHEMA,
)

# Path to dist data directory
DIST_DATA_DIR = Path(__file__).parent.parent / "dist" / "data"

class TestSchemaValidation:
    """Test that generated JSON files conform to expected schemas."""
    
    @pytest.mark.skipif(
        not (DIST_DATA_DIR / "cna_analysis.json").exists(),
        reason="CNA analysis file not found - run build first"
    )
    def test_cna_analysis_schema(self):
        """Validate cna_analysis.json against schema."""
        with open(DIST_DATA_DIR / "cna_analysis.json") as f:
            data = json.load(f)
        validate(instance=data, schema=CNA_ANALYSIS_SCHEMA)
        assert data["total_cnas"] > 0, "Should have at least one CNA"
        assert len(data["cna_list"]) > 0, "CNA list should not be empty"

    @pytest.mark.skipif(
        not (DIST_DATA_DIR / "cvss_analysis.json").exists(),
        reason="CVSS analysis file not found - run build first"
    )
    def test_cvss_analysis_schema(self):
        """Validate cvss_analysis.json against schema."""
        with open(DIST_DATA_DIR / "cvss_analysis.json") as f:
            data = json.load(f)
        validate(instance=data, schema=CVSS_ANALYSIS_SCHEMA)
        assert data["total_cves_with_cvss"] > 0, "Should have scored CVEs"

    @pytest.mark.skipif(
        not (DIST_DATA_DIR / "data_quality.json").exists(),
        reason="Data quality file not found - run build first"
    )
    def test_data_quality_schema(self):
        """Validate data_quality.json against schema."""
        with open(DIST_DATA_DIR / "data_quality.json") as f:
            data = json.load(f)
        validate(instance=data, schema=DATA_QUALITY_SCHEMA)
        stats = data["stats"]
        total = stats["total_cnas_in_analysis"]
        matched = (stats["exact_matches"] + stats["case_mismatches"] + 
                   stats["org_name_matches"] + stats["normalized_matches"] + 
                   stats["partial_matches"])
        unmatched = stats["unmatched"]
        assert total == matched + unmatched

    @pytest.mark.skipif(
        not (DIST_DATA_DIR / "cve_2024.json").exists(),
        reason="Year data file not found - run build first"
    )
    def test_year_data_schema(self):
        """Validate a sample year data file against schema."""
        with open(DIST_DATA_DIR / "cve_2024.json") as f:
            data = json.load(f)
        validate(instance=data, schema=CVE_YEAR_SCHEMA)
        assert data["year"] == 2024
        assert data["total_cves"] > 0

class TestDataIntegrity:
    """Test data integrity and consistency across files."""
    
    @pytest.mark.skipif(
        not (DIST_DATA_DIR / "cna_analysis.json").exists(),
        reason="CNA analysis file not found - run build first"
    )
    def test_cna_list_has_required_fields(self):
        """Verify all CNAs have required fields populated."""
        with open(DIST_DATA_DIR / "cna_analysis.json") as f:
            data = json.load(f)
        for cna in data["cna_list"]:
            assert "name" in cna
            assert "count" in cna
            assert cna["count"] >= 0

    @pytest.mark.skipif(
        not (DIST_DATA_DIR / "yearly_summary.json").exists(),
        reason="Yearly summary file not found - run build first"
    )
    def test_yearly_summary_completeness(self):
        """Verify yearly summary contains all expected years."""
        with open(DIST_DATA_DIR / "yearly_summary.json") as f:
            data = json.load(f)
        years = data.get("years", {})
        # Check for start and end years roughly
        assert any(y in years or str(y) in years for y in range(1999, 2005))
        assert any(y in years or str(y) in years for y in range(2023, 2027))

    @pytest.mark.skipif(
        not all((DIST_DATA_DIR / f).exists() for f in ["cna_analysis.json", "cve_all.json"]),
        reason="Required files not found - run build first"
    )
    def test_cve_totals_reasonable(self):
        """Verify CVE totals are in reasonable ranges."""
        with open(DIST_DATA_DIR / "cna_analysis.json") as f:
            cna_data = json.load(f)
        with open(DIST_DATA_DIR / "cve_all.json") as f:
            all_data = json.load(f)
        
        cna_total = sum(cna["count"] for cna in cna_data["cna_list"])
        all_total = all_data.get("total_cves", 0)
        
        # Basic sanity checks
        assert cna_total > 1000
        assert all_total > 1000
        
class TestFixtureSchemas:
    """Test that fixtures conform to schemas (validates our test data)."""
    
    def test_sample_cna_analysis_valid(self, sample_cna_analysis):
        validate(instance=sample_cna_analysis, schema=CNA_ANALYSIS_SCHEMA)
    
    def test_sample_cvss_analysis_valid(self, sample_cvss_analysis):
        validate(instance=sample_cvss_analysis, schema=CVSS_ANALYSIS_SCHEMA)
    
    def test_sample_year_data_valid(self, sample_year_data):
        validate(instance=sample_year_data, schema=CVE_YEAR_SCHEMA)
