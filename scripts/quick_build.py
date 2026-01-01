#!/usr/bin/env python3
"""
CVEDB Quick Template Builder
Fast template-only rebuild for development - skips data processing
"""

import shutil
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

class CVEQuickBuilder:
    """Fast template-only builder for development"""
    
    def __init__(self):
        self.current_year = datetime.now().year
        self.available_years = list(range(1999, self.current_year + 1))
        # scripts/quick_build.py -> parent is scripts/ -> parent is project root
        self.project_root = Path(__file__).parent.parent.resolve()
        self.templates_dir = self.project_root / 'templates'
        self.web_dir = self.project_root / 'dist'
        self.static_source_dir = self.project_root / 'static'
        self.static_output_dir = self.web_dir / 'static'
        
        # Set up Jinja2 environment
        # Include templates/ and templates/cna for resolution
        self.jinja_env = Environment(
            loader=FileSystemLoader([str(self.templates_dir), str(self.templates_dir / 'cna')]),
            autoescape=select_autoescape(['html', 'xml'])
        )
        
        # Add custom filters and globals
        self.jinja_env.globals['current_year'] = self.current_year
        self.jinja_env.globals['available_years'] = self.available_years
        self.jinja_env.filters['format_number'] = self.format_number
        
        print(f"⚡ CVEDB Quick Template Builder")
        print(f"📅 Current Year: {self.current_year}")
        print(f"📂 Templates: {self.templates_dir}")
        print(f"🌐 Web output: {self.web_dir}")
    
    def format_number(self, num):
        """Format numbers with commas"""
        if isinstance(num, (int, float)):
            return f"{num:,}"
        return str(num)
    
    def copy_static_assets(self):
        """Copy static assets (CSS, JS, images) from static/ to dist/static/"""
        print("📁 Synchronizing static assets...")
        
        if self.static_source_dir.exists():
            # Ensure static output dir exists
            self.static_output_dir.mkdir(parents=True, exist_ok=True)
            # Copy everything from static_source_dir to static_output_dir
            shutil.copytree(self.static_source_dir, self.static_output_dir, dirs_exist_ok=True)
            print(f"  ✅ Static assets copied to {self.static_output_dir}")
        else:
            print(f"  ⚠️  No static source assets found at {self.static_source_dir}")
    
    def generate_html_pages(self):
        """Generate HTML pages from templates"""
        print("📄 Generating HTML pages...")
        
        # Define pages to generate
        pages = [
            ('index.html', 'CVEDB - Vulnerability Intelligence Platform'),
            ('years.html', 'Yearly Analysis - CVEDB'),
            ('cna-hub.html', 'CNA Intelligence Hub - CVEDB'),
            ('cna.html', 'CNA Analysis - CVEDB'),
            ('cpe.html', 'CPE Analysis - CVEDB'),
            ('cvss.html', 'CVSS Analysis - CVEDB'),
            ('cwe.html', 'CWE Analysis - CVEDB'),
            ('calendar.html', 'Calendar View - CVEDB'),
            ('growth.html', 'Growth Trends - CVEDB'),
            ('about.html', 'About CVEDB'),
            ('scoring.html', 'Scoring Hub - CVEDB'),
            ('epss.html', 'EPSS Analysis - CVEDB'),
            ('kev.html', 'KEV Dashboard - CVEDB'),
            ('data-quality.html', 'CNA Name Matching - CVEDB'),
        ]
        
        for template_name, title in pages:
            try:
                template = self.jinja_env.get_template(template_name)
                
                context = {
                    'title': title,
                    'current_year': self.current_year,
                    'available_years': self.available_years,
                }
                
                html_content = template.render(**context)
                
                output_path = self.web_dir / template_name
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                
                print(f"  📄 Generated {template_name}")
                
            except Exception as e:
                print(f"  ❌ Error generating {template_name}: {e}")
                continue
        
        print("✅ HTML pages generated successfully")
    
    def build(self):
        """Main build method - templates only"""
        print("\n🏗️  Starting quick template build...")
        print("=" * 50)
        
        # Ensure web directory exists
        self.web_dir.mkdir(parents=True, exist_ok=True)
        (self.web_dir / 'data').mkdir(exist_ok=True)
        
        # Copy static assets
        self.copy_static_assets()
        
        # Generate HTML pages
        self.generate_html_pages()
        
        print("\n" + "=" * 50)
        print("✅ Quick build completed!")
        print(f"📁 Site ready in: {self.web_dir}")
        print("⚡ Data files remain unchanged or missing (use full build for data)")

def main():
    """Main entry point"""
    builder = CVEQuickBuilder()
    builder.build()

if __name__ == "__main__":
    main()
