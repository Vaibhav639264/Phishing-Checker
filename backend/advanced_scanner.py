import hashlib
import re
import asyncio
import logging
from typing import Dict, List, Any, Optional
import base64
import dns.resolver
import socket
from urllib.parse import urlparse
import ssl
import subprocess
import os
import tempfile
from datetime import datetime

logger = logging.getLogger(__name__)

class AdvancedSecurityScanner:
    def __init__(self):
        # Threat intelligence databases
        self.malicious_domains = self._load_malicious_domains()
        self.virus_total_api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        self.suspicious_file_hashes = set()
        
        # Common phishing indicators
        self.phishing_keywords = [
            'verify account', 'suspended', 'click here', 'update payment',
            'confirm identity', 'security alert', 'unusual activity',
            'temporary suspension', 'immediate action', 'expire today'
        ]
        
        # Suspicious TLDs often used in phishing
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc']
        
    def _load_malicious_domains(self) -> set:
        """Load known malicious domains (in production, use threat intel feeds)"""
        return {
            'phishing-site.com', 'malware-host.net', 'fake-bank.org',
            'suspicious-link.tk', 'evil-domain.ml', 'scam-site.ga'
        }

    async def analyze_urls_advanced(self, urls: List[str]) -> Dict[str, Any]:
        """Advanced URL analysis with multiple security checks"""
        findings = []
        
        for url in urls:
            url_analysis = await self._analyze_single_url(url)
            if url_analysis['risk_level'] != 'LOW':
                findings.append(url_analysis)
        
        return {
            'advanced_url_analysis': findings,
            'total_urls_scanned': len(urls),
            'suspicious_urls_found': len(findings)
        }

    async def _analyze_single_url(self, url: str) -> Dict[str, Any]:
        """Comprehensive analysis of a single URL"""
        analysis = {
            'url': url,
            'risk_level': 'LOW',
            'threats_detected': [],
            'technical_details': {}
        }
        
        try:
            # Parse URL
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # 1. Domain reputation check
            domain_check = await self._check_domain_reputation(domain)
            if domain_check['is_malicious']:
                analysis['risk_level'] = 'CRITICAL'
                analysis['threats_detected'].append({
                    'type': 'malicious_domain',
                    'details': 'Domain found in threat intelligence database'
                })
            
            # 2. URL shortener detection
            if self._is_url_shortener(domain):
                analysis['threats_detected'].append({
                    'type': 'url_shortener',
                    'details': 'URL shortener detected - could hide malicious destination'
                })
                if analysis['risk_level'] == 'LOW':
                    analysis['risk_level'] = 'MEDIUM'
            
            # 3. Suspicious TLD check
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                analysis['threats_detected'].append({
                    'type': 'suspicious_tld',
                    'details': f'Domain uses suspicious TLD: {domain}'
                })
                if analysis['risk_level'] == 'LOW':
                    analysis['risk_level'] = 'MEDIUM'
            
            # 4. Homograph attack detection
            if self._detect_homograph_attack(domain):
                analysis['risk_level'] = 'HIGH'
                analysis['threats_detected'].append({
                    'type': 'homograph_attack',
                    'details': 'Domain uses lookalike characters to mimic legitimate site'
                })
            
            # 5. SSL certificate check
            ssl_check = await self._check_ssl_certificate(domain)
            analysis['technical_details']['ssl'] = ssl_check
            
            # 6. DNS analysis
            dns_check = await self._analyze_dns(domain)
            analysis['technical_details']['dns'] = dns_check
            
            # 7. Check against VirusTotal (if API key available)
            if self.virus_total_api_key:
                vt_check = await self._check_virustotal_url(url)
                if vt_check['malicious_votes'] > 0:
                    analysis['risk_level'] = 'CRITICAL'
                    analysis['threats_detected'].append({
                        'type': 'virustotal_detection',
                        'details': f'Flagged by {vt_check["malicious_votes"]} security vendors'
                    })
            
        except Exception as e:
            logger.error(f"Error analyzing URL {url}: {str(e)}")
            analysis['error'] = str(e)
        
        return analysis

    async def analyze_attachments_advanced(self, email_msg) -> Dict[str, Any]:
        """Advanced attachment analysis with content scanning"""
        findings = []
        total_attachments = 0
        
        for part in email_msg.walk():
            if part.get_content_disposition() == 'attachment':
                total_attachments += 1
                filename = part.get_filename()
                
                if filename:
                    attachment_analysis = await self._analyze_attachment(part, filename)
                    if attachment_analysis['risk_level'] != 'LOW':
                        findings.append(attachment_analysis)
        
        return {
            'advanced_attachment_analysis': findings,
            'total_attachments': total_attachments,
            'suspicious_attachments_found': len(findings)
        }

    async def _analyze_attachment(self, attachment_part, filename: str) -> Dict[str, Any]:
        """Deep analysis of email attachment"""
        analysis = {
            'filename': filename,
            'risk_level': 'LOW',
            'threats_detected': [],
            'file_details': {}
        }
        
        try:
            # Get attachment content
            content = attachment_part.get_payload(decode=True)
            if not content:
                return analysis
            
            # 1. File signature analysis
            file_type = self._detect_file_type(content)
            analysis['file_details']['detected_type'] = file_type
            analysis['file_details']['size'] = len(content)
            
            # 2. Extension vs content mismatch
            extension = filename.split('.')[-1].lower() if '.' in filename else ''
            if self._check_extension_mismatch(extension, file_type):
                analysis['risk_level'] = 'HIGH'
                analysis['threats_detected'].append({
                    'type': 'extension_mismatch',
                    'details': f'File claims to be .{extension} but is actually {file_type}'
                })
            
            # 3. Hash analysis
            file_hash = hashlib.sha256(content).hexdigest()
            analysis['file_details']['sha256'] = file_hash
            
            # Check against known malicious hashes
            if file_hash in self.suspicious_file_hashes:
                analysis['risk_level'] = 'CRITICAL'
                analysis['threats_detected'].append({
                    'type': 'known_malware',
                    'details': 'File hash matches known malware signature'
                })
            
            # 4. Executable file detection
            if self._is_executable_file(content, filename):
                analysis['risk_level'] = 'HIGH'
                analysis['threats_detected'].append({
                    'type': 'executable_file',
                    'details': 'Attachment contains executable code'
                })
            
            # 5. Macro detection in Office files
            if extension in ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']:
                if self._contains_macros(content):
                    analysis['risk_level'] = 'MEDIUM'
                    analysis['threats_detected'].append({
                        'type': 'office_macros',
                        'details': 'Office document contains macros'
                    })
            
            # 6. PDF analysis
            if extension == 'pdf':
                pdf_analysis = self._analyze_pdf(content)
                if pdf_analysis['suspicious']:
                    analysis['risk_level'] = 'MEDIUM'
                    analysis['threats_detected'].append({
                        'type': 'suspicious_pdf',
                        'details': pdf_analysis['reason']
                    })
            
            # 7. Archive analysis
            if extension in ['zip', 'rar', '7z', 'tar', 'gz']:
                archive_analysis = await self._analyze_archive(content, extension)
                if archive_analysis['suspicious']:
                    analysis['risk_level'] = 'HIGH'
                    analysis['threats_detected'].extend(archive_analysis['threats'])
            
            # 8. VirusTotal scan (if API available)
            if self.virus_total_api_key:
                vt_result = await self._scan_file_virustotal(content)
                if vt_result['malicious_count'] > 0:
                    analysis['risk_level'] = 'CRITICAL'
                    analysis['threats_detected'].append({
                        'type': 'antivirus_detection',
                        'details': f'Detected as malware by {vt_result["malicious_count"]} antivirus engines'
                    })
            
        except Exception as e:
            logger.error(f"Error analyzing attachment {filename}: {str(e)}")
            analysis['error'] = str(e)
        
        return analysis

    def _detect_file_type(self, content: bytes) -> str:
        """Detect actual file type from content"""
        try:
            # Check magic bytes (file signatures)
            if content.startswith(b'\x4D\x5A'):  # PE executable
                return 'executable'
            elif content.startswith(b'\x50\x4B'):  # ZIP/Office
                return 'archive_or_office'
            elif content.startswith(b'%PDF'):
                return 'pdf'
            elif content.startswith(b'\xFF\xD8\xFF'):
                return 'jpeg'
            elif content.startswith(b'\x89PNG'):
                return 'png'
            else:
                return 'unknown'
        except:
            return 'unknown'

    def _is_executable_file(self, content: bytes, filename: str) -> bool:
        """Check if file is executable"""
        exe_signatures = [
            b'\x4D\x5A',  # PE (Windows executable)
            b'\x7FELF',    # ELF (Linux executable)
            b'\xFE\xED\xFA\xCE',  # Mach-O (macOS executable)
        ]
        
        return any(content.startswith(sig) for sig in exe_signatures)

    def _contains_macros(self, content: bytes) -> bool:
        """Check if Office document contains macros"""
        macro_indicators = [
            b'macros', b'VBA', b'Microsoft Office Macro',
            b'vbaProject.bin', b'_VBA_PROJECT'
        ]
        
        return any(indicator in content for indicator in macro_indicators)

    def _analyze_pdf(self, content: bytes) -> Dict[str, Any]:
        """Analyze PDF for suspicious content"""
        try:
            content_str = content.decode('latin-1', errors='ignore')
            
            # Check for JavaScript
            if '/JS' in content_str or 'JavaScript' in content_str:
                return {'suspicious': True, 'reason': 'PDF contains JavaScript'}
            
            # Check for suspicious actions
            suspicious_actions = ['/Launch', '/ImportData', '/SubmitForm']
            for action in suspicious_actions:
                if action in content_str:
                    return {'suspicious': True, 'reason': f'PDF contains {action} action'}
            
            return {'suspicious': False, 'reason': 'PDF appears safe'}
            
        except Exception:
            return {'suspicious': True, 'reason': 'Unable to analyze PDF'}

    async def _analyze_archive(self, content: bytes, extension: str) -> Dict[str, Any]:
        """Analyze compressed archives for threats"""
        threats = []
        
        try:
            # Save to temporary file for analysis
            with tempfile.NamedTemporaryFile(suffix=f'.{extension}', delete=False) as tmp_file:
                tmp_file.write(content)
                tmp_file_path = tmp_file.name
            
            try:
                # List archive contents without extracting
                if extension == 'zip':
                    result = subprocess.run(['unzip', '-l', tmp_file_path], 
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        # Check for suspicious files in archive
                        for line in result.stdout.split('\n'):
                            if any(ext in line.lower() for ext in ['.exe', '.bat', '.scr', '.vbs']):
                                threats.append({
                                    'type': 'executable_in_archive',
                                    'details': f'Archive contains executable: {line.strip()}'
                                })
            finally:
                os.unlink(tmp_file_path)
                
        except Exception as e:
            logger.error(f"Error analyzing archive: {str(e)}")
        
        return {
            'suspicious': len(threats) > 0,
            'threats': threats
        }

    async def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain against threat intelligence"""
        return {
            'is_malicious': domain in self.malicious_domains,
            'reputation_score': 0 if domain in self.malicious_domains else 100
        }

    def _is_url_shortener(self, domain: str) -> bool:
        """Check if domain is a URL shortener"""
        shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'is.gd', 'buff.ly', 'rebrand.ly', 'short.link'
        ]
        return domain in shorteners

    def _detect_homograph_attack(self, domain: str) -> bool:
        """Detect homograph/IDN attacks"""
        # Check for mixed scripts or suspicious Unicode characters
        suspicious_chars = ['а', 'о', 'р', 'е', 'х', 'с']  # Cyrillic lookalikes
        return any(char in domain for char in suspicious_chars)

    def _check_extension_mismatch(self, extension: str, detected_type: str) -> bool:
        """Check if file extension matches actual content"""
        type_mappings = {
            'pdf': 'pdf',
            'jpg': 'jpeg', 'jpeg': 'jpeg',
            'png': 'png',
            'exe': 'executable',
            'zip': 'archive_or_office'
        }
        
        expected_type = type_mappings.get(extension, 'unknown')
        return expected_type != 'unknown' and expected_type != detected_type

    async def _check_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Check SSL certificate validity"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
            return {
                'valid': True,
                'issuer': dict(x[0] for x in cert['issuer']),
                'expires': cert['notAfter']
            }
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }

    async def _analyze_dns(self, domain: str) -> Dict[str, Any]:
        """Analyze DNS records for suspicious patterns"""
        try:
            # Get A records
            a_records = dns.resolver.resolve(domain, 'A')
            ips = [str(record) for record in a_records]
            
            # Check for suspicious IP ranges (this is simplified)
            suspicious_ranges = ['10.', '192.168.', '127.']
            suspicious_ips = [ip for ip in ips if any(ip.startswith(range_) for range_ in suspicious_ranges)]
            
            return {
                'ips': ips,
                'suspicious_ips': suspicious_ips,
                'has_suspicious_ips': len(suspicious_ips) > 0
            }
        except Exception as e:
            return {
                'error': str(e)
            }

    async def _check_virustotal_url(self, url: str) -> Dict[str, Any]:
        """Check URL against VirusTotal API"""
        # Placeholder - implement actual VirusTotal API call
        return {
            'malicious_votes': 0,
            'total_scans': 0,
            'scan_date': datetime.now().isoformat()
        }

    async def _scan_file_virustotal(self, content: bytes) -> Dict[str, Any]:
        """Scan file hash against VirusTotal"""
        # Placeholder - implement actual VirusTotal API call
        return {
            'malicious_count': 0,
            'total_engines': 0,
            'scan_date': datetime.now().isoformat()
        }

    def calculate_overall_risk_score(self, url_analysis: Dict, attachment_analysis: Dict) -> Dict[str, Any]:
        """Calculate overall security risk score"""
        risk_scores = {
            'LOW': 1,
            'MEDIUM': 3,
            'HIGH': 7,
            'CRITICAL': 10
        }
        
        total_score = 0
        max_score = 0
        
        # Factor in URL risks
        for finding in url_analysis.get('advanced_url_analysis', []):
            score = risk_scores.get(finding['risk_level'], 0)
            total_score += score
            max_score = max(max_score, score)
        
        # Factor in attachment risks
        for finding in attachment_analysis.get('advanced_attachment_analysis', []):
            score = risk_scores.get(finding['risk_level'], 0)
            total_score += score
            max_score = max(max_score, score)
        
        # Determine overall risk level
        if max_score >= 10:
            overall_risk = 'CRITICAL'
        elif max_score >= 7:
            overall_risk = 'HIGH'
        elif max_score >= 3:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'
        
        return {
            'overall_risk_level': overall_risk,
            'risk_score': total_score,
            'max_individual_score': max_score,
            'recommendation': self._get_security_recommendation(overall_risk)
        }

    def _get_security_recommendation(self, risk_level: str) -> str:
        """Get security recommendation based on risk level"""
        recommendations = {
            'LOW': 'Email appears safe. Continue with normal processing.',
            'MEDIUM': 'Exercise caution. Verify sender and content before taking action.',
            'HIGH': 'High risk detected. Do not interact with links or attachments.',
            'CRITICAL': 'CRITICAL THREAT: Block immediately. Report to security team.'
        }
        
        return recommendations.get(risk_level, 'Unknown risk level')