#!/usr/bin/env python3
"""
CVE V5 Processor Module
Handles CVE V5 list data processing as the single source of truth for CNA analysis
"""

import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import sys
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import cpu_count

# Add data folder to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent / 'data'))

from cvedb.ingest.download_cve_data import CVEDataDownloader


class CVEV5Processor:
    """Processes CVE V5 list data for authoritative CNA analysis"""
    
    def __init__(self, base_dir, cache_dir, data_dir, quiet=False, force=False):
        self.quiet = quiet
        self.force = force
        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.data_dir = Path(data_dir)
        self.current_year = datetime.now().year
        self.v5_cache_dir = self.cache_dir / 'cvelistV5'
        # Optional EPSS enrichment mapping, keyed by CVE ID
        self.epss_mapping = {}
        # KEV CVE set for threat intelligence tracking
        self.kev_cve_set = set()
        # Load threat intelligence data
        self._load_epss_mapping()
        self._load_kev_set()

    def get_current_commit(self):
        """Get the current commit hash of the CVE V5 repository"""
        if not self.v5_cache_dir.exists():
            return None
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                cwd=self.v5_cache_dir,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except: pass
        return None

    def _load_epss_mapping(self):
        """Load EPSS mapping from cache if available.

        Uses the same cache directory as CVEDataDownloader to avoid
        duplicate downloads. If EPSS data is unavailable or parsing
        fails, this method leaves epss_mapping empty and continues
        silently so that CNA analysis is not blocked.
        """
        try:
            downloader = CVEDataDownloader(cache_dir=self.cache_dir, quiet=True)
            epss_json_path = downloader.epss_parsed_file
            # If parsed file does not exist yet, attempt to parse from CSV
            if not epss_json_path.exists():
                epss_json_path = downloader.parse_epss_csv()

            if epss_json_path and Path(epss_json_path).exists():
                with open(epss_json_path, 'r', encoding='utf-8') as f:
                    self.epss_mapping = json.load(f)
                if not self.quiet:
                    print(f"  ✅ Loaded EPSS mapping for {len(self.epss_mapping):,} CVEs")
            else:
                if not self.quiet:
                    print("  ⚠️  EPSS mapping not available; proceeding without enrichment")
        except Exception as e:
            if not self.quiet:
                print(f"  ⚠️  Could not load EPSS mapping: {e}")
            self.epss_mapping = {}

    def _load_kev_set(self):
        """Load KEV CVE IDs into a set for fast lookup"""
        kev_file = self.cache_dir / 'known_exploited_vulnerabilities_parsed.json'
        if kev_file.exists():
            try:
                with open(kev_file, 'r') as f:
                    kev_data = json.load(f)
                self.kev_cve_set = set(kev_data.keys())
                if not self.quiet:
                    print(f"  ✅ Loaded KEV set with {len(self.kev_cve_set):,} CVEs")
            except Exception as e:
                if not self.quiet:
                    print(f"  ⚠️  Could not load KEV data: {e}")
                self.kev_cve_set = set()
        else:
            if not self.quiet:
                print("  ⚠️  KEV data not available; proceeding without KEV enrichment")

        # CNA type classification patterns
        self.cna_type_patterns = {
            'Vendor': [
                'microsoft', 'apple', 'google', 'oracle', 'cisco', 'adobe', 'ibm',
                'redhat', 'canonical', 'suse', 'debian', 'ubuntu', 'mozilla',
                'vmware', 'intel', 'amd', 'nvidia', 'qualcomm', 'samsung',
                'huawei', 'lenovo', 'hp', 'dell', 'netapp', 'citrix'
            ],
            'Security Researcher': [
                'patchstack', 'wordfence', 'vuldb', 'zerodayinitiative', 'trendmicro',
                'rapid7', 'tenable', 'qualys', 'checkmarx', 'veracode'
            ],
            'CERT': [
                'cert', 'cisa', 'ncsc', 'jpcert', 'kr-cert', 'au-cert',
                'ca-cert', 'de-cert', 'fr-cert', 'nl-cert'
            ],
            'Government': [
                'cisa', 'nist', 'dhs', 'gov', 'mil', 'defense',
                'homeland', 'treasury', 'energy', 'state'
            ],
            'Academic': [
                'edu', 'university', 'college', 'research', 'institute',
                'academic', 'school', 'campus'
            ],
            'Open Source': [
                'github', 'gitlab', 'apache', 'eclipse', 'linux', 'kernel',
                'gnu', 'fsf', 'oss', 'opensource'
            ]
        }
        
    def clone_or_update_cve_v5_repo(self):
        """Clone or update the CVE V5 repository with shallow clone"""
        print(f"  📥 Setting up CVE V5 repository...")
        
        if self.v5_cache_dir.exists():
            # Check if it's a valid git repository
            git_dir = self.v5_cache_dir / '.git'
            if not git_dir.exists():
                print(f"    ⚠️ Invalid git repository, re-cloning...")
                shutil.rmtree(self.v5_cache_dir)
                return self._clone_fresh_repo()
            
            print(f"    🔄 Updating existing CVE V5 repository...")
            try:
                # First try a simple git pull (no --depth flag for existing repos)
                result = subprocess.run(
                    ['git', 'pull', 'origin', 'main'],
                    cwd=self.v5_cache_dir,
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode == 0:
                    print(f"    ✅ Successfully updated CVE V5 repository")
                    return True
                else:
                    # Try to reset and pull if there are conflicts
                    print(f"    🔄 Pull failed, trying reset and pull...")
                    reset_result = subprocess.run(
                        ['git', 'reset', '--hard', 'origin/main'],
                        cwd=self.v5_cache_dir,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    if reset_result.returncode == 0:
                        pull_result = subprocess.run(
                            ['git', 'pull', 'origin', 'main'],
                            cwd=self.v5_cache_dir,
                            capture_output=True,
                            text=True,
                            timeout=300
                        )
                        if pull_result.returncode == 0:
                            print(f"    ✅ Successfully updated CVE V5 repository after reset")
                            return True
                    
                    # Only re-clone as last resort
                    print(f"    ⚠️ All update attempts failed, re-cloning as last resort...")
                    print(f"    📝 Git pull error: {result.stderr}")
                    shutil.rmtree(self.v5_cache_dir)
                    return self._clone_fresh_repo()
                    
            except subprocess.TimeoutExpired:
                print(f"    ⏰ Git pull timed out, repository may be up to date")
                return True  # Don't re-clone on timeout, assume it's working
            except Exception as e:
                print(f"    ⚠️ Update failed with exception: {e}")
                # Only re-clone if it's a critical error
                if "not a git repository" in str(e).lower():
                    shutil.rmtree(self.v5_cache_dir)
                    return self._clone_fresh_repo()
                else:
                    print(f"    📝 Assuming repository is usable despite error")
                    return True
        else:
            return self._clone_fresh_repo()
    
    def _clone_fresh_repo(self):
        """Clone fresh CVE V5 repository"""
        print(f"    📦 Cloning CVE V5 repository (shallow clone)...")
        try:
            # Ensure cache directory exists
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            
            # Shallow clone with depth=1 to minimize data transfer
            result = subprocess.run([
                'git', 'clone', 
                '--depth=1',
                '--single-branch',
                'https://github.com/CVEProject/cvelistV5.git',
                str(self.v5_cache_dir)
            ], capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                print(f"    ✅ Successfully cloned CVE V5 repository")
                return True
            else:
                print(f"    ❌ Failed to clone CVE V5 repository: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"    ❌ Clone operation timed out")
            return False
        except Exception as e:
            print(f"    ❌ Clone failed: {e}")
            return False
    
    def get_repo_stats(self):
        """Get basic statistics about the cloned repository"""
        if not self.v5_cache_dir.exists():
            return None
            
        cves_dir = self.v5_cache_dir / 'cves'
        if not cves_dir.exists():
            return None
            
        stats = {
            'total_years': 0,
            'total_cves': 0,
            'years_available': []
        }
        
        for year_dir in sorted(cves_dir.iterdir()):
            if year_dir.is_dir() and year_dir.name.isdigit():
                year = int(year_dir.name)
                stats['years_available'].append(year)
                stats['total_years'] += 1
                
                # Count CVE files in this year (handle nested structure)
                year_cve_count = 0
                for subdir in year_dir.iterdir():
                    if subdir.is_dir():
                        cve_files = list(subdir.glob('CVE-*.json'))
                        year_cve_count += len(cve_files)
                stats['total_cves'] += year_cve_count
        
        return stats
    
    def classify_cna_type(self, org_id, short_name):
        """Classify CNA type based on organization ID and short name"""
        # Combine org_id and short_name for pattern matching
        search_text = f"{org_id} {short_name}".lower()
        
        # Special cases first
        if 'mitre' in search_text:
            return ['Program']  # MITRE is the CVE Program
        
        # Check patterns for each type
        matched_types = []
        for cna_type, patterns in self.cna_type_patterns.items():
            for pattern in patterns:
                if pattern in search_text:
                    matched_types.append(cna_type)
                    break  # Only add each type once
        
        # If no specific type matched, use comprehensive inference patterns
        if not matched_types:
            # Academic institutions
            if any(domain in search_text for domain in ['.edu', 'university', 'college', 'institut', 'research', 'academic', 'school']):
                matched_types.append('Academic')
            # Government and military
            elif any(gov in search_text for gov in ['.gov', '.mil', 'government', 'cisa', 'nist', 'dhs', 'defense', 'homeland']):
                matched_types.append('Government')
            # CERT and security organizations
            elif any(cert in search_text for cert in ['cert', 'csirt', 'security', 'cyber']):
                matched_types.append('CERT')
            # Open source projects and repositories
            elif any(oss in search_text for oss in ['github', 'gitlab', 'apache', 'linux', 'kernel', 'gnu', 'eclipse', 'mozilla', 'debian', 'ubuntu', 'redhat', 'canonical', 'suse']):
                matched_types.append('Open Source')
            # Security researchers and vulnerability research
            elif any(sec in search_text for sec in ['vulnerability', 'exploit', 'security', 'research', 'bug', 'bounty', 'pentest', 'audit']):
                matched_types.append('Security Researcher')
            # Technology vendors (broad patterns)
            elif any(vendor in search_text for vendor in ['corp', 'inc', 'ltd', 'llc', 'gmbh', 'co', 'company', 'tech', 'software', 'systems', 'solutions', 'technologies']):
                matched_types.append('Vendor')
            # Email domain-based classification
            elif '@' in search_text:
                domain = search_text.split('@')[-1] if '@' in search_text else ''
                if '.edu' in domain or 'university' in domain:
                    matched_types.append('Academic')
                elif '.gov' in domain or '.mil' in domain:
                    matched_types.append('Government')
                elif any(tech in domain for tech in ['.com', '.org', '.net', 'tech', 'software', 'systems']):
                    matched_types.append('Vendor')
                else:
                    matched_types.append('Other')
            else:
                # Final fallback - assume most are vendors/organizations
                matched_types.append('Vendor')
        
        return matched_types if matched_types else ['Vendor']
    
    def calculate_enhanced_statistics(self, cna_list):
        """Calculate enhanced statistics for CNA analysis"""
        if not cna_list:
            return {}
        
        total_cves = sum(cna['count'] for cna in cna_list)
        total_cnas = len(cna_list)
        
        # Market concentration (top 5 CNAs)
        top_5_cves = sum(cna['count'] for cna in cna_list[:5])
        market_concentration = (top_5_cves / total_cves * 100) if total_cves > 0 else 0
        
        # High volume CNAs (1000+ CVEs)
        high_volume_cnas = len([cna for cna in cna_list if cna['count'] >= 1000])
        
        # Activity statistics
        active_cnas = len([cna for cna in cna_list if cna['activity_status'] == 'Active'])
        inactive_cnas = total_cnas - active_cnas
        
        # Years active statistics
        years_active_list = [cna['years_active'] for cna in cna_list if cna.get('years_active', 0) > 0]
        median_years_active = 0
        if years_active_list:
            years_active_list.sort()
            n = len(years_active_list)
            median_years_active = years_active_list[n // 2] if n % 2 == 1 else (years_active_list[n // 2 - 1] + years_active_list[n // 2]) / 2
        
        # Type distribution
        type_counts = defaultdict(int)
        for cna in cna_list:
            cna_types = cna.get('cna_types', ['Other'])
            for cna_type in cna_types:
                type_counts[cna_type] += 1
        
        # Convert to format expected by JavaScript
        # JavaScript expects: type_distribution.sorted_types and type_distribution.type_percentages
        sorted_types = []
        type_percentages = {}
        
        # Sort by count (descending)
        sorted_type_items = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)
        
        for cna_type, count in sorted_type_items:
            percentage = (count / total_cnas * 100) if total_cnas > 0 else 0
            sorted_types.append([cna_type, count])  # JavaScript expects [type, count] pairs
            type_percentages[cna_type] = round(percentage, 1)
        
        # Create the structure expected by JavaScript
        type_distribution = {
            'sorted_types': sorted_types,
            'type_percentages': type_percentages
        }
        
        return {
            'total_cves': total_cves,
            'total_cnas': total_cnas,
            'active_cnas': active_cnas,
            'inactive_cnas': inactive_cnas,
            'high_volume_cnas': high_volume_cnas,
            'market_concentration': round(market_concentration, 1),
            'median_years_active': round(median_years_active, 1),
            'type_distribution': type_distribution
        }
    
    def parse_cve_v5_record(self, cve_file_path):
        """Parse a single CVE V5 record and extract CNA information and metrics"""
        try:
            with open(cve_file_path, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            # Extract CVE metadata
            cve_metadata = cve_data.get('cveMetadata', {})
            cve_id = cve_metadata.get('cveId', '')
            state = cve_metadata.get('state', '')
            
            # Skip REJECTED CVEs
            if state == 'REJECTED':
                return None
            
            # Extract CNA information from V5 format
            assigner_org_id = cve_metadata.get('assignerOrgId', '')
            assigner_short_name = cve_metadata.get('assignerShortName', '')
            date_published = cve_metadata.get('datePublished', '')
            date_updated = cve_metadata.get('dateUpdated', '')
            pub_date = date_published if date_published else date_updated
            
            # Extract metrics (CVSS) and CWE from CNA container
            cna_container = cve_data.get('containers', {}).get('cna', {})
            metrics = cna_container.get('metrics', [])
            cwes = []
            for weakness in cna_container.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwes.append(desc.get('value'))
            
            record = {
                'cve_id': cve_id,
                'assigner_org_id': assigner_org_id,
                'assigner_short_name': assigner_short_name,
                'publication_date': pub_date,
                'year': int(cve_id.split('-')[1]) if cve_id.startswith('CVE-') else None,
                'metrics': metrics,
                'cwes': [c for c in cwes if c and c.startswith('CWE-')]
            }

            # EPSS enrichment
            if cve_id and self.epss_mapping:
                epss = self.epss_mapping.get(cve_id)
                if epss:
                    record['epss_score'] = epss.get('epss_score')
                    record['epss_percentile'] = epss.get('epss_percentile')

            return record
            
        except Exception as e:
            if not self.quiet:
                print(f"    ⚠️ Error parsing {cve_file_path}: {e}")
            return None
    
    def process_all_cves_single_pass(self):
        """Process ALL CVE records in a single pass using multi-processing."""
        print(f"  📊 Processing all CVE files in parallel...")
        
        cves_dir = self.v5_cache_dir / 'cves'
        all_cve_files = []
        for year_dir in sorted(cves_dir.iterdir()):
            if year_dir.is_dir() and year_dir.name.isdigit():
                for subdir in year_dir.iterdir():
                    if subdir.is_dir():
                        all_cve_files.extend([str(p) for p in subdir.glob('CVE-*.json')])
        
        total_files = len(all_cve_files)
        print(f"  📊 Found {total_files:,} total CVE files to process")
        
        # Initialize CNA stats
        all_cna_stats = defaultdict(lambda: {
            'count': 0, 'cves': [],
            'first_date': None, 'last_date': None,
            'first_year': None, 'last_year': None,
            'assigner_org_id': '', 'assigner_short_name': '',
            'cves_by_pub_year': defaultdict(int),
            'kev_count': 0, 'epss_high_count': 0, 'epss_elevated_count': 0,
            'year_stats': defaultdict(lambda: {
                'count': 0, 'kev_count': 0, 'epss_high_count': 0,
                'severity_counts': defaultdict(int), 'cwe_counts': defaultdict(int),
                'cves': []
            })
        })

        # Process in parallel using a generator to keep memory usage low
        # Note: We pass strings to avoid large pickle objects
        num_workers = max(1, cpu_count() - 1)
        print(f"    🚀 Using {num_workers} worker processes")
        
        processed = 0
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            # Map parse_cve_v5_record to all files
            # Note: We use a larger chunksize for small JSON files
            for cve_record in executor.map(self.parse_cve_v5_record, all_cve_files, chunksize=500):
                processed += 1
                if processed % 25000 == 0:
                    print(f"    📈 Parsed {processed:,}/{total_files:,} files...")
                
                if not cve_record or not cve_record.get('assigner_org_id'):
                    continue
                    
                org_id = cve_record['assigner_org_id']
                cve_id = cve_record['cve_id']
                pub_date = cve_record['publication_date']
                pub_year = None
                if pub_date:
                    try:
                        pub_year = datetime.fromisoformat(pub_date.replace('Z', '+00:00')).year
                    except: pass
                
                stats = all_cna_stats[org_id]
                stats['count'] += 1
                stats['assigner_org_id'] = org_id
                stats['assigner_short_name'] = cve_record['assigner_short_name']
                
                if pub_year:
                    stats['cves_by_pub_year'][pub_year] += 1
                    y_stats = stats['year_stats'][pub_year]
                    y_stats['count'] += 1
                    y_stats['cves'].append(cve_id)
                    
                    for metric in cve_record.get('metrics', []):
                        cvss = metric.get('cvssData', {})
                        severity = cvss.get('baseSeverity') or cvss.get('severity')
                        if severity:
                            y_stats['severity_counts'][severity.upper()] += 1
                    
                    for cwe in cve_record.get('cwes', []):
                        y_stats['cwe_counts'][cwe] += 1
                
                if pub_date:
                    if not stats['first_date'] or pub_date < stats['first_date']:
                        stats['first_date'] = pub_date
                        stats['first_year'] = pub_year
                    if not stats['last_date'] or pub_date > stats['last_date']:
                        stats['last_date'] = pub_date
                        stats['last_year'] = pub_year
                
                if cve_id in self.kev_cve_set:
                    stats['kev_count'] += 1
                    if pub_year: stats['year_stats'][pub_year]['kev_count'] += 1
                
                epss_score = cve_record.get('epss_score', 0)
                if epss_score > 0.5:
                    stats['epss_high_count'] += 1
                    if pub_year: stats['year_stats'][pub_year]['epss_high_count'] += 1
                if epss_score > 0.1:
                    stats['epss_elevated_count'] += 1

        print(f"  ✅ Processed {processed:,}({total_files:,}) files, found {len(all_cna_stats):,} unique CNAs")
        return dict(all_cna_stats)

    def process_year_data(self, year):
        """Process all CVE records for a specific year"""
        print(f"    📅 Processing CVE data for year {year}...")
        
        year_dir = self.v5_cache_dir / 'cves' / str(year)
        if not year_dir.exists():
            print(f"    ⚠️ No data found for year {year}")
            return {}
        
        cna_stats = defaultdict(lambda: {
            'count': 0,
            'cves': [],
            'first_date': None,
            'last_date': None,
            'assigner_org_id': '',
            'assigner_short_name': ''
        })
        
        # CVE V5 has nested directory structure (0xxx, 1xxx, etc.)
        cve_files = []
        for subdir in year_dir.iterdir():
            if subdir.is_dir():
                cve_files.extend(subdir.glob('CVE-*.json'))
        
        total_files = len(cve_files)
        processed = 0
        
        if not self.quiet:
            print(f"    📊 Found {total_files} CVE files for {year}")
        
        for cve_file in cve_files:
            cve_record = self.parse_cve_v5_record(cve_file)
            if cve_record and cve_record['assigner_org_id']:
                org_id = cve_record['assigner_org_id']
                
                # Update CNA statistics
                cna_stats[org_id]['count'] += 1
                cna_stats[org_id]['cves'].append(cve_record['cve_id'])
                cna_stats[org_id]['assigner_org_id'] = org_id
                cna_stats[org_id]['assigner_short_name'] = cve_record['assigner_short_name']
                
                # Track date ranges
                pub_date = cve_record['publication_date']
                if pub_date:
                    if not cna_stats[org_id]['first_date'] or pub_date < cna_stats[org_id]['first_date']:
                        cna_stats[org_id]['first_date'] = pub_date
                    if not cna_stats[org_id]['last_date'] or pub_date > cna_stats[org_id]['last_date']:
                        cna_stats[org_id]['last_date'] = pub_date
            
            processed += 1
            if processed % 1000 == 0 and not self.quiet:
                print(f"    📈 Processed {processed}/{total_files} files...")
        
        if not self.quiet:
            print(f"    ✅ Processed {processed} CVE files, found {len(cna_stats)} CNAs for {year}")
        return dict(cna_stats)
    
    def generate_comprehensive_cna_analysis(self):
        """Generate comprehensive and current year CNA analysis in a single pass"""
        print(f"  🏢 Starting single-pass CNA analysis...")
        
        if not self.clone_or_update_cve_v5_repo():
            return None
        
        # Check if we need to rebuild
        commit_file = self.cache_dir / 'cvelistV5_commit.txt'
        current_commit = self.get_current_commit()
        output_file = self.data_dir / 'cna_analysis.json'
        stats_cache = self.cache_dir / 'cna_stats_cache.pkl'
        
        if not self.force and current_commit and commit_file.exists() and output_file.exists():
            with open(commit_file, 'r') as f:
                last_commit = f.read().strip()
            if last_commit == current_commit:
                print(f"  ✅ CNA analysis is up to date (commit {current_commit[:8]})")
                if stats_cache.exists():
                    try:
                        import pickle
                        with open(stats_cache, 'rb') as f:
                            self.all_cna_stats = pickle.load(f)
                    except: pass
                
                with open(output_file, 'r') as f:
                    return json.load(f)

        repo_stats = self.get_repo_stats()
        if not repo_stats: return None
            
        all_cna_stats = self.process_all_cves_single_pass()
        self.all_cna_stats = all_cna_stats  # Store for use by current year generator
        
        # Cache the stats for incremental runs
        try:
            import pickle
            with open(stats_cache, 'wb') as f:
                pickle.dump(dict(all_cna_stats), f)
        except: pass

        cna_list = []
        for org_id, stats in all_cna_stats.items():
            first_year = stats['first_year']
            last_year = stats['last_year']
            years_active = max(1, (last_year - first_year + 1)) if first_year and last_year else 1
            
            days_since_last = 365
            if stats['last_date']:
                try:
                    last_date = datetime.fromisoformat(stats['last_date'].replace('Z', '+00:00'))
                    days_since_last = (datetime.now(last_date.tzinfo) - last_date).days
                except: pass

            cna_list.append({
                'name': stats['assigner_short_name'] or org_id,
                'assigner_org_id': org_id,
                'count': stats['count'],
                'years_active': years_active,
                'first_cve_year': first_year,
                'last_cve_year': last_year,
                'first_cve_date': stats['first_date'],
                'last_cve_date': stats['last_date'],
                'days_since_last_cve': days_since_last,
                'activity_status': 'Active' if days_since_last < 365 else 'Inactive',
                'is_official': True,
                'cna_types': self.classify_cna_type(org_id, stats['assigner_short_name']),
                'cves_by_year': dict(stats['cves_by_pub_year']),
                'kev_count': stats['kev_count'],
                'epss_high_count': stats['epss_high_count'],
                'epss_elevated_count': stats['epss_elevated_count'],
                'severity_distribution': {}, 'top_cwe_types': {}, 'top_cwes': []
            })
        
        cna_list.sort(key=lambda x: x['count'], reverse=True)
        for i, cna in enumerate(cna_list): cna['rank'] = i + 1
        
        enhanced_stats = self.calculate_enhanced_statistics(cna_list)
        repo_stats['total_cves'] = sum(cna['count'] for cna in cna_list)
        
        comprehensive_data = {
            'generated_at': datetime.now().isoformat(),
            'source': 'CVE V5 List (Authoritative)',
            'repository_stats': repo_stats,
            'total_cnas': len(cna_list),
            'active_cnas': enhanced_stats.get('active_cnas', 0),
            'inactive_cnas': enhanced_stats.get('inactive_cnas', 0),
            'official_cnas': len(cna_list),
            'unofficial_cnas': 0,
            'high_volume_cnas': enhanced_stats.get('high_volume_cnas', 0),
            'market_concentration': enhanced_stats.get('market_concentration', 0),
            'median_years_active': enhanced_stats.get('median_years_active', 0),
            'type_distribution': enhanced_stats.get('type_distribution', []),
            'cna_list': cna_list,
            'cna_assigners': cna_list
        }
        
        output_file = self.data_dir / 'cna_analysis.json'
        with open(output_file, 'w') as f:
            json.dump(comprehensive_data, f, indent=2)
        
        # Update commit hash after success
        if current_commit:
            commit_file = self.cache_dir / 'cvelistV5_commit.txt'
            with open(commit_file, 'w') as f:
                f.write(current_commit)
        
        print(f"  📄 Generated comprehensive CNA analysis with {len(cna_list)} CNAs")
        return comprehensive_data
    
    def process_current_year_by_publication_date(self):
        """Process CVEs from ALL years, filtering by current year publication date"""
        print(f"    🔍 Scanning all CVE years for {self.current_year} publications...")
        
        cves_dir = self.v5_cache_dir / 'cves'
        if not cves_dir.exists():
            print(f"    ❌ CVEs directory not found")
            return {}
        
        cna_stats = defaultdict(lambda: {
            'count': 0,
            'cves': [],
            'first_date': None,
            'last_date': None,
            'assigner_org_id': '',
            'assigner_short_name': ''
        })
        
        total_processed = 0
        current_year_cves = 0
        
        # Scan all year directories
        for year_dir in sorted(cves_dir.iterdir()):
            if not year_dir.is_dir() or not year_dir.name.isdigit():
                continue
                
            year = int(year_dir.name)
            if not self.quiet:
                print(f"    📂 Scanning CVE-{year}-* files for {self.current_year} publications...")
            
            # Get all CVE files in this year directory (handle nested structure)
            cve_files = []
            for subdir in year_dir.iterdir():
                if subdir.is_dir():
                    cve_files.extend(subdir.glob('CVE-*.json'))
            
            year_current_cves = 0
            for cve_file in cve_files:
                cve_record = self.parse_cve_v5_record(cve_file)
                if cve_record and cve_record['assigner_org_id']:
                    # Check if this CVE was published in the current year
                    pub_date = cve_record['publication_date']
                    if pub_date:
                        try:
                            pub_year = datetime.fromisoformat(pub_date.replace('Z', '+00:00')).year
                            if pub_year == self.current_year:
                                # This CVE was published in current year
                                org_id = cve_record['assigner_org_id']
                                
                                # Update CNA statistics
                                cna_stats[org_id]['count'] += 1
                                cna_stats[org_id]['cves'].append(cve_record['cve_id'])
                                cna_stats[org_id]['assigner_org_id'] = org_id
                                cna_stats[org_id]['assigner_short_name'] = cve_record['assigner_short_name']
                                
                                # Track date ranges
                                if not cna_stats[org_id]['first_date'] or pub_date < cna_stats[org_id]['first_date']:
                                    cna_stats[org_id]['first_date'] = pub_date
                                if not cna_stats[org_id]['last_date'] or pub_date > cna_stats[org_id]['last_date']:
                                    cna_stats[org_id]['last_date'] = pub_date
                                
                                year_current_cves += 1
                                current_year_cves += 1
                        except Exception:
                            # Skip CVEs with invalid dates
                            pass
                
                total_processed += 1
                if total_processed % 5000 == 0 and not self.quiet:
                    print(f"    📈 Processed {total_processed} files, found {current_year_cves} {self.current_year} publications...")
            
            if year_current_cves > 0 and not self.quiet:
                print(f"    ✅ Found {year_current_cves} CVEs published in {self.current_year} from CVE-{year}-* files")
        
        if not self.quiet:
            print(f"    🎯 Total: {current_year_cves} CVEs published in {self.current_year}, from {len(cna_stats)} CNAs")
        return dict(cna_stats)
    
    def generate_current_year_analysis(self):
        """Generate current year CNA analysis from already processed single-pass data"""
        print(f"  📅 Generating {self.current_year} CNA analysis from single-pass data...")
        
        if not hasattr(self, 'all_cna_stats'):
            print("  ⚠️ No processed data found; performing full analysis...")
            self.generate_comprehensive_cna_analysis()
            
        current_year_cnas = []
        for org_id, stats in self.all_cna_stats.items():
            y_stats = stats['year_stats'].get(self.current_year)
            if not y_stats or y_stats['count'] == 0:
                continue
                
            y_cna = {
                'name': stats['assigner_short_name'] or org_id,
                'assigner_org_id': org_id,
                'count': y_stats['count'],
                'years_active': max(1, (stats['last_year'] - stats['first_year'] + 1)) if stats['first_year'] else 1,
                'kev_count': y_stats['kev_count'],
                'epss_high_count': y_stats['epss_high_count'],
                'severity_distribution': dict(y_stats['severity_counts']),
                'top_cwe_types': dict(sorted(y_stats['cwe_counts'].items(), key=lambda x: x[1], reverse=True)[:10]),
                'top_cwes': sorted(y_stats['cwe_counts'].items(), key=lambda x: x[1], reverse=True)[:5],
                'cna_types': self.classify_cna_type(org_id, stats['assigner_short_name']),
                'first_cve_year': stats['first_year'],
                'last_cve_year': stats['last_year']
            }
            current_year_cnas.append(y_cna)
            
        current_year_cnas.sort(key=lambda x: x['count'], reverse=True)
        for i, cna in enumerate(current_year_cnas): cna['rank'] = i + 1
        
        current_year_data = {
            'generated_at': datetime.now().isoformat(),
            'year': self.current_year,
            'total_cnas': len(current_year_cnas),
            'total_cves': sum(cna['count'] for cna in current_year_cnas),
            'cna_list': current_year_cnas,
            'cna_assigners': current_year_cnas
        }
        
        output_file = self.data_dir / f'cna_analysis_{self.current_year}.json'
        with open(output_file, 'w') as f:
            json.dump(current_year_data, f, indent=2)
            
        print(f"  📄 Generated {self.current_year} CNA analysis with {len(current_year_cnas)} CNAs")
        return current_year_data
