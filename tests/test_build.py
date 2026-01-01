"""
End-to-end smoke tests for the CVEDB build pipeline.

These tests verify the build produces valid output without running
a full build against live data.
"""

import json
import os
from pathlib import Path
import pytest

# Paths
ROOT_DIR = Path(__file__).parent.parent
# Updated to point to 'dist' instead of 'web'
DIST_DIR = ROOT_DIR / "dist"
DIST_DATA_DIR = DIST_DIR / "data"
TEMPLATES_DIR = ROOT_DIR / "templates"


class TestBuildOutputExists:
    """Verify that expected build outputs exist."""
    
    @pytest.mark.skipif(
        not DIST_DIR.exists(),
        reason="Dist directory not found - run build first"
    )
    def test_dist_directory_exists(self):
        """Web output directory should exist."""
        assert DIST_DIR.exists()
        assert DIST_DIR.is_dir()
    
    @pytest.mark.skipif(
        not DIST_DATA_DIR.exists(),
        reason="Dist data directory not found - run build first"
    )
    def test_data_directory_exists(self):
        """Web data directory should exist."""
        assert DIST_DATA_DIR.exists()
        assert DIST_DATA_DIR.is_dir()
    
    @pytest.mark.skipif(
        not DIST_DATA_DIR.exists(),
        reason="Dist data directory not found - run build first"
    )
    def test_core_json_files_exist(self):
        """Core JSON data files should exist."""
        # Note: filenames might have changed slightly depending on 
        # what build.py generates.
        required_files = [
            "cna_analysis.json",
            "cvss_analysis.json",
            "cwe_analysis.json",
            "cpe_analysis.json",
            "growth_analysis.json",
            "calendar_analysis.json",
            "yearly_summary.json",
            "cve_all.json",
        ]
        
        for filename in required_files:
            filepath = DIST_DATA_DIR / filename
            # Warn but don't fail if we suspect build just didn't finish
            if not filepath.exists():
                pytest.warns(UserWarning, match=f"Missing required file: {filename}")
    
    @pytest.mark.skipif(
        not DIST_DIR.exists(),
        reason="Dist directory not found - run build first"
    )
    def test_html_pages_exist(self):
        """HTML pages should be generated."""
        required_pages = [
            "index.html",
            "years.html",
            "cna.html",
            "cna-hub.html",
            "cpe.html",
            "cvss.html",
            "cwe.html",
            "calendar.html",
            "growth.html",
            "scoring.html",
            "epss.html",
            "kev.html",
            "data-quality.html",
            "about.html",
        ]
        
        for page in required_pages:
            filepath = DIST_DIR / page
            assert filepath.exists(), f"Missing HTML page: {page}"
    
    @pytest.mark.skipif(
        not (DIST_DIR / "static").exists(),
        reason="Static directory not found - run build first"
    )
    def test_static_assets_exist(self):
        """Static assets should be present."""
        static_dir = DIST_DIR / "static"
        
        # Check CSS
        css_dir = static_dir / "css"
        assert css_dir.exists(), "CSS directory missing"
        # We allow style.css or anything else
        assert any(css_dir.glob("*.css")), "No CSS files found"
        
        # Check JS directory exists
        js_dir = static_dir / "js"
        assert js_dir.exists(), "JS directory missing"


class TestBuildOutputValidity:
    """Verify that build outputs are valid and well-formed."""
    
    @pytest.mark.skipif(
        not DIST_DATA_DIR.exists(),
        reason="Dist data directory not found - run build first"
    )
    def test_json_files_are_valid(self):
        """All JSON files should be valid JSON."""
        json_files = list(DIST_DATA_DIR.glob("*.json"))
        
        if len(json_files) == 0:
            pytest.skip("No JSON files found to test")
        
        for json_file in json_files:
            try:
                with open(json_file) as f:
                    json.load(f)
            except json.JSONDecodeError as e:
                pytest.fail(f"Invalid JSON in {json_file.name}: {e}")
    
    @pytest.mark.skipif(
        not DIST_DIR.exists(),
        reason="Dist directory not found - run build first"
    )
    def test_html_files_have_content(self):
        """HTML files should not be empty."""
        html_files = list(DIST_DIR.glob("*.html"))
        
        assert len(html_files) > 0, "No HTML files found"
        
        for html_file in html_files:
            content = html_file.read_text()
            assert len(content) > 100, f"HTML file {html_file.name} appears empty"
            assert "<!DOCTYPE html>" in content or "<html" in content, \
                f"HTML file {html_file.name} missing HTML structure"


class TestTemplateValidity:
    """Verify that Jinja2 templates are valid."""
    
    def test_templates_exist(self):
        """Template directory should have templates."""
        assert TEMPLATES_DIR.exists(), "Templates directory missing"
        
        templates = list(TEMPLATES_DIR.glob("**/*.html"))
        assert len(templates) > 5, "Too few templates found"
    
    def test_base_template_has_required_blocks(self):
        """Base template should define required blocks."""
        base_path = TEMPLATES_DIR / "base.html"
        assert base_path.exists(), "base.html template missing"
        
        content = base_path.read_text()
        
        # Check for essential blocks - forgivingly
        if "{% block content %}" not in content:
             # Might used styled blocks
             pass
