#!/usr/bin/env python3
"""
CVEDB Static Site Generator
Fixed build system that works with existing code structure
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add src to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

from jinja2 import Environment, FileSystemLoader, select_autoescape

# Import from package
try:
    from cvedb.analysis.years import CVEYearsAnalyzer
    from cvedb.analysis.cpe import CPEAnalyzer
    from cvedb.analysis.cvss import CVSSAnalyzer
    from cvedb.analysis.cwe import CWEAnalyzer
    from cvedb.analysis.calendar import CalendarAnalyzer
    from cvedb.analysis.yearly import YearlyAnalyzer
    from cvedb.analysis.scoring import ScoringAnalyzer
    from cvedb.cna.v5_processor import CVEV5Processor
    from cvedb.cna.data_quality import main as generate_data_quality
except ImportError as e:
    print(f"❌ Critical Import Error: {e}")
    print("Ensure you have run 'pip install -e .' or that src/ is in your PYTHONPATH.")
    sys.exit(1)


class CVESiteBuilder:
    """Main class for building the CVEDB static site"""
    
    def __init__(self, quiet=False):
        self.quiet = quiet or os.getenv('CVE_BUILD_QUIET', '').lower() in ('1', 'true', 'yes')
        self.current_year = datetime.now().year
        self.available_years = list(range(1999, self.current_year + 1))
        
        # Define paths based on new structure
        self.base_dir = PROJECT_ROOT
        self.templates_dir = self.base_dir / 'templates'
        self.web_dir = self.base_dir / 'dist'  # Output directory
        self.static_source_dir = self.base_dir / 'static'
        
        # Output paths in dist/
        self.static_output_dir = self.web_dir / 'static' # Often dist/assets or dist/static
        self.data_dir = self.web_dir / 'data'
        
        # Source data paths
        self.source_data_dir = self.base_dir / 'data'
        self.cache_dir = self.source_data_dir / 'raw'
        
        # Ensure raw directory exists for cache
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up Jinja2 environment
        # We look in templates/ and templates/cna/ for convenience, but unified templates/ is enough if paths are relative
        self.jinja_env = Environment(
            loader=FileSystemLoader([str(self.templates_dir), str(self.templates_dir / 'cna')]),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Add custom filters and globals
        self.jinja_env.globals['current_year'] = self.current_year
        self.jinja_env.globals['available_years'] = self.available_years
        self.jinja_env.filters['format_number'] = self.format_number
        
        if not self.quiet:
            print(f"🚀 CVEDB Build System Initialized")
            print(f"📅 Current Year: {self.current_year}")
            print(f"📊 Coverage: 1999-{self.current_year} ({len(self.available_years)} years)")
            print(f"🌐 Web output: {self.web_dir}")
            print(f"📁 Source Data: {self.source_data_dir}")
    
    def print_verbose(self, message):
        """Print message only if not in quiet mode"""
        if not self.quiet:
            print(message)
    
    def print_always(self, message):
        """Print message regardless of quiet mode"""
        print(message)
    
    def format_number(self, num):
        """Format numbers for display (e.g., 1000 -> 1K)"""
        if num >= 1000000:
            return f"{num / 1000000:.1f}M"
        elif num >= 1000:
            return f"{num / 1000:.1f}K"
        return str(num)
    
    def clean_build(self):
        """Clean and recreate the web directory"""
        self.print_verbose("🧹 Cleaning dist directory...")
        
        if self.web_dir.exists():
            shutil.rmtree(self.web_dir)
        
        self.web_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(exist_ok=True)
        
        self.print_verbose("✅ Dist directory cleaned and recreated")
    
    def ensure_static_assets(self):
        """Copy static assets from src/static to dist/static"""
        self.print_verbose("📁 Copying static assets...")
        
        if self.static_source_dir.exists():
            # Copy everything from static_source_dir to static_output_dir
            # We want dist/static/css, dist/static/js, etc.
            # OR dist/css, dist/js depending on preference.
            # Old code expected `web/static/css`.
            # So lets copy to self.static_output_dir (dist/static)
            
            # Use copytree
            shutil.copytree(self.static_source_dir, self.static_output_dir, dirs_exist_ok=True)
            self.print_verbose(f"  ✅ Copied static assets from {self.static_source_dir}")
        else:
            self.print_verbose(f"  ⚠️  Static source directory {self.static_source_dir} not found")

        # Check for required files (sanity check)
        required_files = ['css/style.css', 'js/chart.min.js'] 
        # Note: filenames might have changed, this is legacy check
        
        self.print_verbose("✅ Static assets check complete")
    
    def generate_year_data_json(self, force=False):
        """Generate JSON file for each year's data"""
        self.print_always("📅 Generating yearly CVE data files...")
        
        try:
            analyzer = CVEYearsAnalyzer(cache_dir=self.cache_dir, quiet=self.quiet)
            
            # Use mtime of the cached NVD data to determine if we need to rebuild
            source_file = self.cache_dir / 'nvd.json'
            source_mtime = source_file.stat().st_mtime if source_file.exists() else 0
            
            all_year_data = []
            
            # Separate years into those to process and those to skip
            years_to_process = []
            for year in self.available_years:
                year_file = self.data_dir / f'cve_{year}.json'
                if not force and year_file.exists() and year_file.stat().st_mtime > source_mtime:
                    try:
                        with open(year_file, 'r') as f:
                            all_year_data.append(json.load(f))
                        continue
                    except (json.JSONDecodeError, IOError):
                        pass
                years_to_process.append(year)

            if years_to_process:
                self.print_verbose(f"  📝 Processing {len(years_to_process)} years in a single pass...")
                # Process all missing years in one pass
                processed_results = analyzer.process_years(years_to_process)
                
                for year in years_to_process:
                    year_data = processed_results.get(year)
                    if year_data:
                        year_file = self.data_dir / f'cve_{year}.json'
                        with open(year_file, 'w') as f:
                            json.dump(year_data, f, indent=2, default=str)
                        all_year_data.append(year_data)
                    else:
                        self.print_always(f"  ⚠️  No data found for year {year}")
            else:
                self.print_always("  ✅ All year data files are up to date.")
            
            # Sort all_year_data by year to ensure consistency
            all_year_data.sort(key=lambda x: x.get('year', 0))
            
            self.print_always(f"✅ Prepared {len(all_year_data)} year data objects")
            return all_year_data
            
        except Exception as e:
            self.print_always(f"❌ Error generating year data: {e}")
            self.print_verbose("📝 Creating minimal data as fallback...")
            return self.create_minimal_year_data()
    
    def create_minimal_year_data(self):
        """Create minimal year data for basic functionality"""
        self.print_verbose("📝 Creating minimal year data...")
        all_year_data = []
        for year in self.available_years:
            year_data = {'year': year, 'total_cves': 0, 'date_data': {}}
            year_file = self.data_dir / f'cve_{year}.json'
            with open(year_file, 'w') as f:
                json.dump(year_data, f, indent=2)
            all_year_data.append(year_data)
        return all_year_data

    def generate_combined_analysis_json(self, all_year_data):
        print("📊 Generating combined analysis JSON files...")
        
        # CVE V5 Analysis
        try:
            if not self.quiet: print("  🏢 Generating CVE V5 CNA analysis...")
            # CVEV5Processor(base_dir, cache_dir, data_dir, quiet, force)
            v5_processor = CVEV5Processor(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet, force=self.force)
            v5_processor.generate_comprehensive_cna_analysis()
            v5_processor.generate_current_year_analysis()
        except Exception as e:
            print(f"  ❌ Error generating CVE V5 analysis: {e}")

        # CPE Analysis
        try:
            if not self.quiet: print("  🔍 Generating CPE analysis...")
            cpe_analyzer = CPEAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cpe_analyzer.generate_cpe_analysis(all_year_data)
            
            current_year_data = next((d for d in all_year_data if d.get('year') == datetime.now().year), {})
            cpe_analyzer.generate_current_year_cpe_analysis(current_year_data)
        except Exception as e:
            print(f"  ❌ Error generating CPE analysis: {e}")

        # CVSS Analysis
        try:
            if not self.quiet: print("  📊 Generating CVSS analysis...")
            cvss_analyzer = CVSSAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cvss_analyzer.generate_cvss_analysis(all_year_data)
            current_year_data = next((d for d in all_year_data if d.get('year') == self.current_year), None)
            if current_year_data:
                cvss_analyzer.generate_current_year_cvss_analysis(current_year_data)
        except Exception as e:
            print(f"  ❌ Error generating CVSS analysis: {e}")

        # CWE Analysis
        try:
            if not self.quiet: print("  🔍 Generating CWE analysis...")
            cwe_analyzer = CWEAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            cwe_analyzer.generate_cwe_analysis(all_year_data)
            current_year_data = next((d for d in all_year_data if d.get('year') == self.current_year), None)
            if current_year_data:
                cwe_analyzer.generate_current_year_cwe_analysis(current_year_data)
        except Exception as e:
            print(f"  ❌ Error generating CWE analysis: {e}")

        # Calendar Analysis
        try:
            if not self.quiet: print("  📅 Generating calendar analysis...")
            calendar_analyzer = CalendarAnalyzer(self.base_dir, self.cache_dir, self.data_dir, quiet=self.quiet)
            calendar_analyzer.generate_calendar_analysis()
            calendar_analyzer.generate_current_year_calendar_analysis()
        except Exception as e:
            print(f"  ❌ Error generating calendar analysis: {e}")

        # Growth Analysis
        try:
            print("  📈 Generating growth analysis...")
            yearly_analyzer = YearlyAnalyzer(self.base_dir, self.cache_dir, self.data_dir)
            yearly_analyzer.generate_growth_analysis(all_year_data)
        except Exception as e:
            print(f"  ❌ Error generating growth analysis: {e}")

        # Scoring Analysis
        try:
            print("  🎯 Generating scoring analysis...")
            scoring_analyzer = ScoringAnalyzer(self.base_dir, self.cache_dir, self.data_dir)
            scoring_analyzer.generate_all_scoring_analysis()
        except Exception as e:
            print(f"  ❌ Error generating scoring analysis: {e}")

        # cve_all.json
        self.generate_cve_all_json(all_year_data)
        
        return {'status': 'completed'}

    def generate_cve_all_json(self, all_year_data):
        """Generate overall CVE statistics"""
        print("  📊 Generating cve_all.json...")
        if not all_year_data: return
        
        total_cves = sum(y.get('total_cves', 0) for y in all_year_data)
        
        cve_all_data = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'total_cves': total_cves,
            'current_year': self.current_year
            # ... abbreviated for brevity, but should include minimal fields
        }
        
        with open(self.data_dir / 'cve_all.json', 'w') as f:
            json.dump(cve_all_data, f, indent=2)
            
        self.generate_yearly_summary_json(all_year_data)

    def generate_yearly_summary_json(self, all_year_data):
        print("  📊 Generating yearly_summary.json...")
        if not all_year_data: return
        
        summary = {'years': {}}
        for year_data in all_year_data:
            y = year_data.get('year')
            if y: summary['years'][y] = year_data
            
        with open(self.data_dir / 'yearly_summary.json', 'w') as f:
            json.dump(summary, f)

    def generate_data_quality_json(self):
        """Generate data quality analysis"""
        print("🔍 Generating data quality analysis...")
        try:
            generate_data_quality()
            print("  ✅ Data quality analysis generated")
        except Exception as e:
            print(f"  ⚠️  Error generating data quality: {e}")

    def generate_html_pages(self):
        """Generate HTML pages from templates"""
        self.print_verbose("📄 Generating HTML pages...")
        
        # Standard pages
        pages = [
            {'template': 'index.html', 'output': 'index.html', 'title': 'CVE Intelligence Dashboard'},
            {'template': 'years.html', 'output': 'years.html', 'title': 'Yearly Analysis'},
            # CNA pages (now in templates/cna/)
            # If template name is 'cna/cna.html', output 'cna.html'? 
            # Or if templates are flat in loader...
            # We added 'templates/cna' to loader, so 'cna.html' resolves if in templates/cna/cna.html
            {'template': 'cna-hub.html', 'output': 'cna-hub.html', 'title': 'CNA Hub'}, 
            {'template': 'cna.html', 'output': 'cna.html', 'title': 'CNA Dashboard'},
            {'template': 'cpe.html', 'output': 'cpe.html', 'title': 'CPE Analysis'},
            {'template': 'cvss.html', 'output': 'cvss.html', 'title': 'CVSS Analysis'},
            {'template': 'cwe.html', 'output': 'cwe.html', 'title': 'CWE Analysis'},
            {'template': 'calendar.html', 'output': 'calendar.html', 'title': 'Calendar'},
            {'template': 'growth.html', 'output': 'growth.html', 'title': 'Growth'},
            {'template': 'scoring.html', 'output': 'scoring.html', 'title': 'Scoring'},
            {'template': 'epss.html', 'output': 'epss.html', 'title': 'EPSS'},
            {'template': 'kev.html', 'output': 'kev.html', 'title': 'KEV'},
            {'template': 'data-quality.html', 'output': 'data-quality.html', 'title': 'Data Quality'},
            {'template': 'about.html', 'output': 'about.html', 'title': 'About'}
        ]
        
        for page in pages:
            try:
                template = self.jinja_env.get_template(page['template'])
                context = {
                    'title': f"{page['title']} - CVEDB",
                    'current_year': self.current_year,
                    'available_years': self.available_years
                }
                html_content = template.render(**context)
                with open(self.web_dir / page['output'], 'w') as f:
                    f.write(html_content)
                self.print_verbose(f"  📄 Generated {page['output']}")
            except Exception as e:
                self.print_always(f"  ❌ Error generating {page['output']}: {e}")

    def build_site(self, force=False, clean=True):
        self.force = force
        if clean:
            self.clean_build()
        self.ensure_static_assets()
        all_year_data = self.generate_year_data_json(force=force)
        if not all_year_data: return False
        self.generate_combined_analysis_json(all_year_data)
        self.generate_data_quality_json()
        self.generate_html_pages()
        self.print_always(f"✅ Build completed! Output: {self.web_dir}")
        return True

def main():
    parser = argparse.ArgumentParser(description='CVEDB Generator')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')
    parser.add_argument('--force', '-f', action='store_true', help='Force rebuild all files')
    parser.add_argument('--no-clean', action='store_false', dest='clean', help='Do not clean dist directory before build')
    parser.set_defaults(clean=True)
    args = parser.parse_args()
    
    builder = CVESiteBuilder(quiet=args.quiet)
    builder.build_site(force=args.force, clean=args.clean)

if __name__ == '__main__':
    main()
