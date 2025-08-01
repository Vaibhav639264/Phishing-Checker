import re
import logging
import os
from typing import Dict, List, Any, Optional
import urllib.parse
import base64
from datetime import datetime
import hashlib
import google.generativeai as genai

class LlmChat:
    def __init__(self, api_key, session_id, system_message):
        self.api_key = api_key
        self.system_message = system_message
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')
    
    def with_model(self, provider, model_name):
        return self
    
    async def chat(self, message):
        try:
            prompt = f"{self.system_message}\n\nUser: {message.text}"
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            return f"Analysis error: {str(e)}"

class UserMessage:
    def __init__(self, text):
        self.text = text

logger = logging.getLogger(__name__)

class EnhancedPhishingDetector:
    def __init__(self):
        self.gemini_api_key = os.environ.get('GEMINI_API_KEY')
        
        # Enhanced phishing patterns (covering the Office-365 example)
        self.critical_phishing_patterns = [
            # Office 365 / Microsoft phishing
            r'office[-\s]*365',
            r'microsoft.*account.*suspend',
            r'microsoft.*login.*expire',
            r'outlook.*verification',
            r'onedrive.*access.*suspend',
            r'teams.*account.*block',
            
            # Generic credential harvesting (made more specific)
            r'verify.*account.*immediate.*or.*suspend',
            r'verify.*account.*within.*24.*hours?',
            r'account.*suspend.*24.*hour.*unless',
            r'password.*expire.*today.*click',
            r'click.*here.*verify.*account.*now',
            r'keep.*active.*password',
            r'update.*payment.*info.*immediately',
            r'confirm.*identity.*now.*or.*lose',
            
            # Urgency indicators (made more specific)
            r'immediate.*action.*required.*or.*account',
            r'expires?.*today.*click.*here',
            r'within.*24.*hours?.*or.*lose.*access',
            r'urgent.*response.*needed.*verify',
            r'act.*now.*or.*lose.*access.*permanently'
        ]
        
        # Suspicious domains and patterns
        self.suspicious_domain_patterns = [
            r'.*compress.*save.*org',  # From the example
            r'.*microsoft.*[^\.]+\.(?!com)',  # Fake Microsoft domains
            r'.*office.*365.*[^\.]+\.(?!com)',
            r'.*outlook.*[^\.]+\.(?!com)',
            r'.*paypal.*[^\.]+\.(?!com)',
            r'.*amazon.*[^\.]+\.(?!co\.)',
            r'.*apple.*[^\.]+\.(?!com)',
            r'.*google.*[^\.]+\.(?!com)',
        ]
        
        # Suspicious TLDs often used in phishing
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc',
            '.org', '.info', '.biz', '.name', '.mobi'
        ]
        
        # Brand impersonation keywords
        self.brand_keywords = {
            'microsoft': ['office', 'outlook', 'onedrive', 'teams', 'azure', 'windows'],
            'google': ['gmail', 'drive', 'docs', 'chrome', 'youtube'],
            'amazon': ['aws', 'prime', 'kindle', 'alexa'],
            'apple': ['icloud', 'itunes', 'app store', 'iphone'],
            'paypal': ['payment', 'transaction', 'billing'],
            'banking': ['account', 'statement', 'transaction', 'funds']
        }
        
        # Whitelist of legitimate financial/service domains to never flag
        self.legitimate_service_domains = [
            'stripe.com', 'paypal.com', 'razorpay.com', 'payu.in', 'phonepe.com',
            'hdfcbank.net', 'hdfcbank.com', 'icicibank.com', 'sbi.co.in',
            'axisbank.com', 'kotak.com', 'citibank.co.in', 'standardchartered.co.in',
            'amazon.com', 'amazon.in', 'amazon.co.uk', 'ses.amazonaws.com',
            'google.com', 'gmail.com', 'accounts.google.com', 'security.google.com',
            'microsoft.com', 'outlook.com', 'live.com', 'hotmail.com',
            'apple.com', 'icloud.com', 'me.com',
            'linkedin.com', 'twitter.com', 'facebook.com', 'instagram.com',
            'github.com', 'stackoverflow.com', 'medium.com',
            'perplexity.ai', 'openai.com', 'anthropic.com', 'emergent.ai'
        ]
        
    async def analyze_email_comprehensive(self, email_content: str, email_data: Dict[str, Any], filename: str) -> Dict[str, Any]:
        """Comprehensive email analysis with enhanced detection"""
        try:
            logger.info(f"🔍 Starting comprehensive analysis of: {email_data.get('subject', 'No subject')}")
            
            # Check if email is from trusted domain first
            sender = email_data.get('from', '').lower()
            sender_domain = ''
            if '@' in sender:
                sender_domain = sender.split('@')[-1].split('>')[0].strip()
            
            is_trusted_domain = False
            for domain in self.legitimate_service_domains:
                if sender_domain.endswith(domain) or sender_domain == domain:
                    is_trusted_domain = True
                    break
            
            results = {
                'filename': filename,
                'email_info': {
                    'subject': email_data.get('subject', ''),
                    'from': email_data.get('from', ''),
                    'to': email_data.get('to', ''),
                    'date': email_data.get('date', ''),
                    'reply_to': email_data.get('reply_to', ''),
                    'body_length': len(email_data.get('body', '')),
                    'has_html': bool(email_data.get('html_body', '')),
                    'attachment_count': len(email_data.get('attachments', [])),
                    'trusted_domain': is_trusted_domain,
                    'sender_domain': sender_domain
                },
                'threat_indicators': [],
                'url_analysis': [],
                'sender_analysis': [],
                'content_analysis': [],
                'brand_impersonation': [],
                'threat_level': 'LOW',
                'confidence_score': 0,
                'detection_reasons': []
            }
            
            # If from trusted domain, apply conservative analysis
            if is_trusted_domain:
                logger.info(f"📧 Email from trusted domain {sender_domain} - applying conservative analysis")
                # Only check for critical patterns, skip other checks
                critical_score = self._detect_critical_patterns(email_data, results)
                total_score = critical_score * 0.3  # Reduce score significantly for trusted domains
                
                # Very conservative threat level for trusted domains
                if total_score >= 60:  # Much higher threshold
                    results['threat_level'] = 'MEDIUM'
                elif total_score >= 30:
                    results['threat_level'] = 'LOW'
                else:
                    results['threat_level'] = 'LOW'
                
                results['confidence_score'] = min(total_score, 100)
                
            else:
                # Full analysis for untrusted domains
                # 1. Critical Pattern Detection (catches Office-365 type phishing)
                critical_score = self._detect_critical_patterns(email_data, results)
                
                # 2. URL Analysis
                url_score = self._analyze_urls_comprehensive(email_data, results)
                
                # 3. Sender Analysis
                sender_score = self._analyze_sender_comprehensive(email_data, results)
                
                # 4. Content Analysis
                content_score = self._analyze_content_comprehensive(email_data, results)
                
                # 5. Brand Impersonation Detection
                brand_score = self._detect_brand_impersonation(email_data, results)
                
                # 6. Attachment Analysis
                attachment_score = self._analyze_attachments_comprehensive(email_data, results)
                
                # Calculate overall score
                total_score = critical_score + url_score + sender_score + content_score + brand_score + attachment_score
                results['confidence_score'] = min(total_score, 100)
                
                # Determine threat level
                if total_score >= 80 or critical_score >= 50:
                    results['threat_level'] = 'CRITICAL'
                elif total_score >= 60:
                    results['threat_level'] = 'HIGH'
                elif total_score >= 30:
                    results['threat_level'] = 'MEDIUM'
                else:
                    results['threat_level'] = 'LOW'
            
            # Enhanced LLM Analysis (more conservative)
            if self.gemini_api_key:
                llm_analysis = await self._enhanced_llm_analysis(email_data, results)
                results['llm_analysis'] = llm_analysis
                
                # More sophisticated LLM escalation logic
                if llm_analysis:
                    llm_lower = llm_analysis.lower()
                    # Only escalate if LLM clearly identifies it as phishing AND provides specific reasons
                    if ('phishing: yes' in llm_lower or 'is this a phishing email? yes' in llm_lower) and not is_trusted_domain:
                        if results['threat_level'] in ['LOW', 'MEDIUM']:
                            results['threat_level'] = 'HIGH'
                            results['detection_reasons'].append('AI analysis identified critical threats')
                    # For trusted domains, be even more conservative
                    elif is_trusted_domain and 'block' in llm_lower and 'definite phishing' in llm_lower:
                        if results['threat_level'] == 'LOW':
                            results['threat_level'] = 'MEDIUM'
                            results['detection_reasons'].append('AI analysis identified potential concerns')
            
            logger.info(f"🎯 Analysis complete: {results['threat_level']} threat (score: {results['confidence_score']}) - Trusted: {is_trusted_domain}")
            
            return results
            
        except Exception as e:
            logger.error(f"❌ Comprehensive analysis failed: {str(e)}")
            return {
                'error': f'Analysis failed: {str(e)}',
                'threat_level': 'UNKNOWN',
                'confidence_score': 0
            }
    
    def _detect_critical_patterns(self, email_data: Dict[str, Any], results: Dict[str, Any]) -> int:
        """Detect critical phishing patterns (high-confidence detection)"""
        score = 0
        content = (email_data.get('body', '') + ' ' + email_data.get('subject', '')).lower()
        
        for pattern in self.critical_phishing_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                threat_score = 30 if 'office' in pattern or 'microsoft' in pattern else 20
                score += threat_score
                
                results['threat_indicators'].append({
                    'type': 'critical_pattern',
                    'pattern': pattern,
                    'matches': matches,
                    'severity': 'CRITICAL',
                    'score': threat_score
                })
                
                results['detection_reasons'].append(f"Critical phishing pattern detected: {pattern}")
        
        # Special check for the exact phishing example patterns
        office_365_indicators = [
            'office-365',
            'keep active password',
            'password.*due.*update',
            'user confidential'
        ]
        
        for indicator in office_365_indicators:
            if re.search(indicator, content, re.IGNORECASE):
                score += 40
                results['threat_indicators'].append({
                    'type': 'office_365_phishing',
                    'indicator': indicator,
                    'severity': 'CRITICAL',
                    'score': 40
                })
                results['detection_reasons'].append(f"Office-365 phishing indicator: {indicator}")
        
        return min(score, 100)
    
    def _analyze_urls_comprehensive(self, email_data: Dict[str, Any], results: Dict[str, Any]) -> int:
        """Comprehensive URL analysis with redirection checking"""
        score = 0
        content = email_data.get('body', '') + ' ' + email_data.get('html_body', '')
        
        # Extract all URLs
        url_patterns = [
            r'https?://[^\s<>"\'()]+',
            r'www\.[^\s<>"\'()]+',
            r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\'()]*)?'
        ]
        
        all_urls = []
        for pattern in url_patterns:
            urls = re.findall(pattern, content, re.IGNORECASE)
            all_urls.extend(urls)
        
        def check_url_redirections(url, max_redirects=5):
            """Follow URL redirections and analyze each step"""
            redirects = []
            current_url = url
            
            try:
                import requests
                for i in range(max_redirects):
                    try:
                        response = requests.head(current_url, allow_redirects=False, timeout=5)
                        
                        if response.status_code in [301, 302, 303, 307, 308]:
                            redirect_url = response.headers.get('Location', '')
                            if redirect_url:
                                redirects.append({
                                    'from': current_url,
                                    'to': redirect_url,
                                    'status_code': response.status_code,
                                    'step': i + 1
                                })
                                current_url = redirect_url
                            else:
                                break
                        else:
                            break
                    except:
                        break
                        
            except Exception as e:
                logger.warning(f"URL redirection check failed for {url}: {str(e)}")
            
            return redirects, current_url
        
        for url in set(all_urls):  # Remove duplicates
            url_score = 0
            url_analysis = {
                'original_url': url,
                'issues': [],
                'risk_level': 'LOW',
                'redirections': [],
                'final_url': url
            }
            
            # Check URL redirections
            redirections, final_url = check_url_redirections(url)
            if redirections:
                url_analysis['redirections'] = redirections
                url_analysis['final_url'] = final_url
                
                # Analyze redirection chain for suspicious patterns
                for redirect in redirections:
                    if redirect['to'].lower() != redirect['from'].lower():
                        # Check if redirection goes to suspicious domain
                        for pattern in self.suspicious_domain_patterns:
                            if re.search(pattern, redirect['to'], re.IGNORECASE):
                                url_score += 25
                                url_analysis['issues'].append(f'Redirects to suspicious domain: {redirect["to"]}')
                                url_analysis['risk_level'] = 'HIGH'
                        
                        # Check for domain switching (potential hiding)
                        from_domain = redirect['from'].split('/')[2] if '//' in redirect['from'] else redirect['from'].split('/')[0]
                        to_domain = redirect['to'].split('/')[2] if '//' in redirect['to'] else redirect['to'].split('/')[0]
                        
                        if from_domain.lower() != to_domain.lower():
                            url_score += 15
                            url_analysis['issues'].append(f'Domain change in redirection: {from_domain} → {to_domain}')
                
                if len(redirections) > 3:
                    url_score += 20
                    url_analysis['issues'].append(f'Excessive redirections: {len(redirections)} steps')
                    url_analysis['risk_level'] = 'HIGH'
            
            # Check against suspicious domain patterns (both original and final URL)
            urls_to_check = [url, final_url] if final_url != url else [url]
            
            for check_url in urls_to_check:
                for pattern in self.suspicious_domain_patterns:
                    if re.search(pattern, check_url, re.IGNORECASE):
                        url_score += 35
                        url_analysis['issues'].append(f'Matches suspicious pattern: {pattern}')
                        url_analysis['risk_level'] = 'CRITICAL'
            
            # Check TLD
            for tld in self.suspicious_tlds:
                if tld in url.lower():
                    url_score += 15
                    url_analysis['issues'].append(f'Suspicious TLD: {tld}')
                    if url_analysis['risk_level'] == 'LOW':
                        url_analysis['risk_level'] = 'MEDIUM'
            
            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly']
            for shortener in shorteners:
                if shortener in url:
                    url_score += 20
                    url_analysis['issues'].append(f'URL shortener detected: {shortener}')
                    url_analysis['risk_level'] = 'HIGH'
            
            # Check for suspicious keywords in URL
            suspicious_url_keywords = ['verify', 'confirm', 'suspend', 'expire', 'login', 'account']
            for keyword in suspicious_url_keywords:
                if keyword in url.lower():
                    url_score += 10
                    url_analysis['issues'].append(f'Suspicious keyword in URL: {keyword}')
            
            if url_score > 0:
                results['url_analysis'].append(url_analysis)
                score += url_score
        
        return min(score, 80)
    
    def _analyze_sender_comprehensive(self, email_data: Dict[str, Any], results: Dict[str, Any]) -> int:
        """Comprehensive sender analysis"""
        score = 0
        sender = email_data.get('from', '').lower()
        reply_to = email_data.get('reply_to', '').lower()
        
        # Extract domain from sender
        sender_domain = ''
        if '@' in sender:
            sender_domain = sender.split('@')[-1].split('>')[0].strip()
        
        # Skip analysis if from whitelisted legitimate service domains
        for domain in self.legitimate_service_domains:
            if sender_domain.endswith(domain) or sender_domain == domain:
                return 0  # No impersonation score for whitelisted domains

        sender_analysis = {
            'sender': sender,
            'domain': sender_domain,
            'issues': [],
            'risk_level': 'LOW'
        }
        
        # Check for brand impersonation in sender
        for brand, keywords in self.brand_keywords.items():
            if brand in sender or any(keyword in sender for keyword in keywords):
                # Check if domain matches the brand
                legitimate_domains = {
                    'microsoft': ['microsoft.com', 'outlook.com', 'hotmail.com', 'live.com', 'office.com'],
                    'google': ['google.com', 'gmail.com', 'accounts.google.com', 'mail.google.com', 'security.google.com'],
                    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.in', 'ses.amazonaws.com'],
                    'apple': ['apple.com', 'icloud.com', 'me.com'],
                    'paypal': ['paypal.com', 'paypal.co.uk']
                }
                
                if brand in legitimate_domains:
                    is_legitimate = False
                    
                    # Check if it's exactly a legitimate domain
                    if sender_domain in legitimate_domains[brand]:
                        is_legitimate = True
                    else:
                        # Check if it's a subdomain of a legitimate domain
                        for legit_domain in legitimate_domains[brand]:
                            if sender_domain.endswith('.' + legit_domain) or sender_domain == legit_domain:
                                is_legitimate = True
                                break
                    
                    # Only flag if NOT from legitimate domain
                    if not is_legitimate:
                        score += 40
                        sender_analysis['issues'].append(f'Brand impersonation: {brand} from non-legitimate domain {sender_domain}')
                        sender_analysis['risk_level'] = 'CRITICAL'
                        results['detection_reasons'].append(f'{brand.title()} impersonation detected from {sender_domain}')
        
        # Check for suspicious sender patterns
        suspicious_sender_patterns = [
            r'helpdesk.*message',  # From the example
            r'security.*team',
            r'account.*support',
            r'no.*reply',
            r'automated.*message'
        ]
        
        for pattern in suspicious_sender_patterns:
            if re.search(pattern, sender, re.IGNORECASE):
                score += 25
                sender_analysis['issues'].append(f'Suspicious sender pattern: {pattern}')
                sender_analysis['risk_level'] = 'HIGH'
        
        # Reply-To analysis
        if reply_to and reply_to != sender:
            score += 15
            sender_analysis['issues'].append('Reply-To differs from sender')
            sender_analysis['risk_level'] = 'MEDIUM'
        
        if sender_analysis['issues']:
            results['sender_analysis'].append(sender_analysis)
        
        return min(score, 60)
    
    def _analyze_content_comprehensive(self, email_data: Dict[str, Any], results: Dict[str, Any]) -> int:
        """Comprehensive content analysis"""
        score = 0
        subject = email_data.get('subject', '').lower()
        body = email_data.get('body', '').lower()
        content = subject + ' ' + body
        
        content_analysis = {
            'urgency_indicators': [],
            'social_engineering': [],
            'suspicious_elements': [],
            'risk_level': 'LOW'
        }
        
        # Urgency indicators
        urgency_patterns = [
            r'immediate.*action',
            r'urgent.*response',
            r'expires?.*today',
            r'within.*24.*hours?',
            r'act.*now',
            r'time.*sensitive',
            r'due.*today',
            r'suspend.*account'
        ]
        
        urgency_score = 0
        for pattern in urgency_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                urgency_score += 10
                content_analysis['urgency_indicators'].append({
                    'pattern': pattern,
                    'matches': matches
                })
        
        score += urgency_score
        
        # Social engineering tactics
        social_patterns = [
            r'verify.*account.*or.*suspend',
            r'click.*here.*to.*continue',
            r'update.*payment.*information',
            r'confirm.*identity.*immediately',
            r'unusual.*activity.*detected',
            r'security.*breach.*detected'
        ]
        
        social_score = 0
        for pattern in social_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                social_score += 15
                content_analysis['social_engineering'].append({
                    'pattern': pattern,
                    'matches': matches
                })
        
        score += social_score
        
        # Generic greetings (impersonal)
        generic_greetings = ['dear user', 'dear customer', 'dear member', 'dear sir/madam']
        for greeting in generic_greetings:
            if greeting in content:
                score += 10
                content_analysis['suspicious_elements'].append(f'Generic greeting: {greeting}')
        
        # Determine risk level
        if score >= 40:
            content_analysis['risk_level'] = 'HIGH'
        elif score >= 20:
            content_analysis['risk_level'] = 'MEDIUM'
        
        if content_analysis['urgency_indicators'] or content_analysis['social_engineering'] or content_analysis['suspicious_elements']:
            results['content_analysis'].append(content_analysis)
        
        return min(score, 70)
    
    def _detect_brand_impersonation(self, email_data: Dict[str, Any], results: Dict[str, Any]) -> int:
        """Detect brand impersonation"""
        score = 0
        content = (email_data.get('subject', '') + ' ' + email_data.get('body', '')).lower()
        sender = email_data.get('from', '').lower()
        
        # Extract sender domain
        sender_domain = ''
        if '@' in sender:
            sender_domain = sender.split('@')[-1].split('>')[0].strip()
        
        # Skip analysis if from whitelisted legitimate service domains
        for domain in self.legitimate_service_domains:
            if sender_domain.endswith(domain) or sender_domain == domain:
                return 0  # No impersonation score for whitelisted domains
        
        for brand, keywords in self.brand_keywords.items():
            brand_mentions = 0
            
            # Check for brand mentions in content
            if brand in content:
                brand_mentions += 1
            
            for keyword in keywords:
                if keyword in content:
                    brand_mentions += 1
            
            if brand_mentions >= 2:  # Multiple mentions suggest impersonation
                # Check if sender domain is legitimate for this brand
                legitimate_domains = {
                    'microsoft': ['microsoft.com', 'outlook.com', 'office.com', 'live.com', 'hotmail.com'],
                    'google': ['google.com', 'gmail.com', 'accounts.google.com', 'mail.google.com', 'security.google.com'],
                    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.in', 'ses.amazonaws.com'],
                    'apple': ['apple.com', 'icloud.com', 'me.com'],
                    'paypal': ['paypal.com', 'paypal.co.uk']
                }
                
                # More sophisticated domain matching
                if brand in legitimate_domains:
                    is_legitimate = False
                    
                    # Check if it's exactly a legitimate domain
                    if sender_domain in legitimate_domains[brand]:
                        is_legitimate = True
                    else:
                        # Check if it's a subdomain of a legitimate domain
                        for legit_domain in legitimate_domains[brand]:
                            if sender_domain.endswith('.' + legit_domain) or sender_domain == legit_domain:
                                is_legitimate = True
                                break
                    
                    # Only flag as impersonation if NOT from a legitimate domain
                    if not is_legitimate:
                        impersonation_score = 50  # High score for clear impersonation
                        score += impersonation_score
                        
                        results['brand_impersonation'].append({
                            'brand': brand,
                            'mentions': brand_mentions,
                            'sender_domain': sender_domain,
                            'legitimate_domains': legitimate_domains[brand],
                            'severity': 'CRITICAL',
                            'score': impersonation_score
                        })
                        
                        results['detection_reasons'].append(f'Brand impersonation detected: {brand.title()} from non-legitimate domain {sender_domain}')
        
        return min(score, 80)
    
    def _analyze_attachments_comprehensive(self, email_data: Dict[str, Any], results: Dict[str, Any]) -> int:
        """Comprehensive attachment analysis"""
        score = 0
        attachments = email_data.get('attachments', [])
        
        if not attachments:
            return 0
        
        attachment_analysis = {
            'total_attachments': len(attachments),
            'suspicious_attachments': [],
            'risk_level': 'LOW'
        }
        
        # Dangerous file extensions
        dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.vbe',
            '.js', '.jse', '.wsf', '.wsh', '.msi', '.dll', '.jar'
        ]
        
        # Suspicious extensions
        suspicious_extensions = [
            '.zip', '.rar', '.7z', '.tar.gz', '.docm', '.xlsm', '.pptm'
        ]
        
        for attachment in attachments:
            filename = attachment.get('filename', '').lower()
            
            # Check for dangerous extensions
            for ext in dangerous_extensions:
                if filename.endswith(ext):
                    score += 50
                    attachment_analysis['suspicious_attachments'].append({
                        'filename': filename,
                        'issue': f'Dangerous executable: {ext}',
                        'severity': 'CRITICAL'
                    })
                    attachment_analysis['risk_level'] = 'CRITICAL'
            
            # Check for suspicious extensions
            for ext in suspicious_extensions:
                if filename.endswith(ext):
                    score += 20
                    attachment_analysis['suspicious_attachments'].append({
                        'filename': filename,
                        'issue': f'Suspicious file type: {ext}',
                        'severity': 'HIGH'
                    })
                    if attachment_analysis['risk_level'] == 'LOW':
                        attachment_analysis['risk_level'] = 'HIGH'
            
            # Check for double extensions
            if filename.count('.') >= 2:
                score += 30
                attachment_analysis['suspicious_attachments'].append({
                    'filename': filename,
                    'issue': 'Double file extension detected',
                    'severity': 'HIGH'
                })
                attachment_analysis['risk_level'] = 'HIGH'
        
        if attachment_analysis['suspicious_attachments']:
            results['attachment_analysis'] = attachment_analysis
        
        return min(score, 70)
    
    async def _enhanced_llm_analysis(self, email_data: Dict[str, Any], results: Dict[str, Any]) -> str:
        """Enhanced LLM analysis with specific context"""
        try:
            # Extract sender domain for context
            sender = email_data.get('from', '').lower()
            sender_domain = ''
            if '@' in sender:
                sender_domain = sender.split('@')[-1].split('>')[0].strip()
            
            # Check if from trusted domain
            is_trusted_domain = False
            for domain in self.legitimate_service_domains:
                if sender_domain.endswith(domain) or sender_domain == domain:
                    is_trusted_domain = True
                    break
            
            chat = LlmChat(
                api_key=self.gemini_api_key,
                session_id=f"phishing_analysis_{datetime.now().timestamp()}",
                system_message="""You are an expert cybersecurity analyst specializing in phishing detection with a focus on ACCURACY and minimizing false positives.

CRITICAL GUIDELINES:
- Emails from legitimate domains (google.com, microsoft.com, stripe.com, banks, etc.) are usually legitimate
- Only flag as phishing if there are CLEAR indicators of deception or malicious intent
- Transaction confirmations, security alerts from legitimate services are usually legitimate
- Be conservative - when in doubt, classify as legitimate rather than phishing

Analyze for GENUINE phishing indicators:
1. Obvious brand impersonation from suspicious domains
2. Credential harvesting attempts with suspicious links
3. Clear social engineering tactics with urgency + suspicious requests
4. Suspicious URLs or attachments
5. Grammar/spelling errors in official communications

Provide balanced, accurate assessment."""
            ).with_model("gemini", "gemini-2.0-flash")
            
            # Prepare comprehensive analysis prompt
            domain_status = "TRUSTED" if is_trusted_domain else "UNKNOWN"
            analysis_prompt = f"""
ANALYZE THIS EMAIL FOR PHISHING (Focus on accuracy, avoid false positives):

SENDER DOMAIN: {sender_domain} ({domain_status})
SUBJECT: {email_data.get('subject', 'N/A')}
FROM: {email_data.get('from', 'N/A')}
BODY: {email_data.get('body', 'N/A')[:1000]}

CURRENT DETECTION RESULTS:
- Threat Level: {results.get('threat_level', 'UNKNOWN')}
- Confidence Score: {results.get('confidence_score', 0)}%
- Critical Patterns: {len(results.get('threat_indicators', []))}
- URL Issues: {len(results.get('url_analysis', []))}
- Brand Impersonation: {len(results.get('brand_impersonation', []))}

IMPORTANT: If this is from a trusted domain ({domain_status}), be extra conservative. Only classify as phishing if there are CLEAR malicious indicators.

Please provide:
1. Is this a phishing email? (YES/NO with confidence %)
2. What type of email is this? (legitimate service email, potential phishing, etc.)
3. Key reasons for your assessment
4. Recommended action (BLOCK/ALLOW/REVIEW)
"""
            
            user_message = UserMessage(text=analysis_prompt)
            response = await chat.send_message(user_message)
            
            return response
            
        except Exception as e:
            logger.error(f"❌ LLM analysis failed: {str(e)}")
            return "LLM analysis unavailable - relying on pattern-based detection"

