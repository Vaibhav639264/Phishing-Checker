import re
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import email
import hashlib

logger = logging.getLogger(__name__)

class EmailThreadAnalyzer:
    def __init__(self):
        self.thread_cache = {}  # message_id -> thread_data
        
    async def analyze_email_thread(self, email_content: str, detector) -> Dict[str, Any]:
        """Analyze entire email thread for malicious content"""
        try:
            logger.info("🧵 Starting email thread analysis")
            
            # Parse the email
            email_msg = email.message_from_string(email_content)
            
            # Extract thread information
            thread_info = self._extract_thread_info(email_msg, email_content)
            
            # Analyze each email in the thread
            thread_analysis = {
                'thread_id': thread_info['thread_id'],
                'total_emails_in_thread': len(thread_info['emails']),
                'malicious_emails_found': 0,
                'thread_threat_level': 'LOW',
                'email_analyses': [],
                'thread_patterns': {
                    'escalating_urgency': False,
                    'sender_spoofing_progression': False,
                    'attachment_delivery_chain': False,
                    'url_progression': False
                },
                'thread_summary': {}
            }
            
            all_senders = []
            all_urls = []
            all_subjects = []
            threat_levels = []
            
            # Analyze each email in the thread
            for i, email_in_thread in enumerate(thread_info['emails']):
                try:
                    logger.info(f"📧 Analyzing email {i+1}/{len(thread_info['emails'])} in thread")
                    
                    # Analyze individual email
                    individual_analysis = await detector.analyze_email(
                        email_in_thread['content'],
                        f"thread_email_{i}_{thread_info['thread_id']}.eml"
                    )
                    
                    # Enhanced analysis with thread context
                    enhanced_analysis = await self._analyze_with_thread_context(
                        email_in_thread, individual_analysis, all_senders, all_urls, all_subjects
                    )
                    
                    thread_analysis['email_analyses'].append({
                        'position_in_thread': i + 1,
                        'analysis': enhanced_analysis,
                        'email_info': {
                            'from': email_in_thread.get('from', ''),
                            'subject': email_in_thread.get('subject', ''),
                            'date': email_in_thread.get('date', ''),
                            'has_attachments': len(email_in_thread.get('attachments', [])) > 0
                        }
                    })
                    
                    # Collect data for thread pattern analysis
                    all_senders.append(email_in_thread.get('from', ''))
                    all_subjects.append(email_in_thread.get('subject', ''))
                    
                    # Extract URLs from this email
                    url_pattern = r'https?://[^\s<>"\'()]+'
                    urls_in_email = re.findall(url_pattern, email_in_thread['content'])
                    all_urls.extend(urls_in_email)
                    
                    threat_level = enhanced_analysis.get('threat_level', 'LOW')
                    threat_levels.append(threat_level)
                    
                    if threat_level in ['HIGH', 'CRITICAL', 'MEDIUM']:
                        thread_analysis['malicious_emails_found'] += 1
                        
                except Exception as e:
                    logger.error(f"❌ Error analyzing email {i} in thread: {str(e)}")
                    continue
            
            # Analyze thread-wide patterns
            thread_analysis['thread_patterns'] = await self._analyze_thread_patterns(
                all_senders, all_urls, all_subjects, threat_levels, thread_info
            )
            
            # Calculate overall thread threat level
            thread_analysis['thread_threat_level'] = self._calculate_thread_threat_level(
                threat_levels, thread_analysis['thread_patterns']
            )
            
            # Generate thread summary
            thread_analysis['thread_summary'] = self._generate_thread_summary(
                thread_analysis, all_senders, all_subjects
            )
            
            logger.info(f"✅ Thread analysis completed: {thread_analysis['malicious_emails_found']}/{thread_analysis['total_emails_in_thread']} malicious emails")
            
            return thread_analysis
            
        except Exception as e:
            logger.error(f"❌ Thread analysis failed: {str(e)}")
            return {
                'error': f'Thread analysis failed: {str(e)}',
                'thread_threat_level': 'UNKNOWN'
            }
    
    def _extract_thread_info(self, email_msg, email_content: str) -> Dict[str, Any]:
        """Extract thread information from email headers and content"""
        try:
            # Get thread identifiers
            message_id = email_msg.get('Message-ID', '')
            in_reply_to = email_msg.get('In-Reply-To', '')
            references = email_msg.get('References', '')
            subject = email_msg.get('Subject', '')
            
            # Clean subject for thread identification
            clean_subject = re.sub(r'^(Re:|Fwd?:|RE:|FWD?:)\s*', '', subject, flags=re.IGNORECASE).strip()
            
            # Generate thread ID
            thread_id = hashlib.md5(clean_subject.encode()).hexdigest()[:12]
            
            # Extract embedded emails (forwarded/replied content)
            embedded_emails = self._extract_embedded_emails(email_content)
            
            # Create thread structure
            thread_info = {
                'thread_id': thread_id,
                'message_id': message_id,
                'in_reply_to': in_reply_to,
                'references': references,
                'subject': subject,
                'clean_subject': clean_subject,
                'emails': [
                    # Current email
                    {
                        'content': email_content,
                        'from': email_msg.get('From', ''),
                        'to': email_msg.get('To', ''),
                        'subject': subject,
                        'date': email_msg.get('Date', ''),
                        'attachments': self._get_attachments_info(email_msg),
                        'position': 'current'
                    }
                ]
            }
            
            # Add embedded emails
            thread_info['emails'].extend(embedded_emails)
            
            return thread_info
            
        except Exception as e:
            logger.error(f"Error extracting thread info: {str(e)}")
            return {
                'thread_id': 'unknown',
                'emails': [{'content': email_content}]
            }
    
    def _extract_embedded_emails(self, email_content: str) -> List[Dict[str, Any]]:
        """Extract forwarded/replied emails from content"""
        embedded_emails = []
        
        try:
            # Common forwarded email patterns
            forward_patterns = [
                r'-----Original Message-----.*?From:.*?To:.*?Subject:.*?Date:.*?\n\n(.*?)(?=-----Original Message-----|$)',
                r'From:.*?To:.*?Cc:.*?Subject:.*?Date:.*?\n\n(.*?)(?=From:.*?To:.*?|$)',
                r'Begin forwarded message:.*?From:.*?Subject:.*?Date:.*?To:.*?\n\n(.*?)(?=Begin forwarded message:|$)',
                r'---------- Forwarded message ----------.*?From:.*?Date:.*?Subject:.*?To:.*?\n\n(.*?)(?=---------- Forwarded message ----------|$)'
            ]
            
            for pattern in forward_patterns:
                matches = re.finditer(pattern, email_content, re.DOTALL | re.IGNORECASE)
                
                for match in matches:
                    try:
                        # Extract email metadata
                        email_header = match.group(0)
                        email_body = match.group(1) if len(match.groups()) > 0 else ''
                        
                        # Parse embedded email info
                        from_match = re.search(r'From:\s*([^\n\r]+)', email_header)
                        to_match = re.search(r'To:\s*([^\n\r]+)', email_header)
                        subject_match = re.search(r'Subject:\s*([^\n\r]+)', email_header)
                        date_match = re.search(r'Date:\s*([^\n\r]+)', email_header)
                        
                        embedded_email = {
                            'content': email_header + '\n\n' + email_body,
                            'from': from_match.group(1).strip() if from_match else 'Unknown',
                            'to': to_match.group(1).strip() if to_match else 'Unknown',
                            'subject': subject_match.group(1).strip() if subject_match else 'Unknown',
                            'date': date_match.group(1).strip() if date_match else 'Unknown',
                            'attachments': [],
                            'position': f'embedded_{len(embedded_emails)}'
                        }
                        
                        embedded_emails.append(embedded_email)
                        
                    except Exception as e:
                        logger.debug(f"Error parsing embedded email: {str(e)}")
                        continue
            
            logger.info(f"📧 Found {len(embedded_emails)} embedded emails in thread")
            return embedded_emails
            
        except Exception as e:
            logger.error(f"Error extracting embedded emails: {str(e)}")
            return []
    
    def _get_attachments_info(self, email_msg) -> List[Dict[str, str]]:
        """Get attachment information from email"""
        attachments = []
        
        try:
            for part in email_msg.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': filename,
                            'content_type': part.get_content_type(),
                            'size': len(part.get_payload()) if part.get_payload() else 0
                        })
        except Exception as e:
            logger.debug(f"Error getting attachments: {str(e)}")
        
        return attachments
    
    async def _analyze_with_thread_context(self, email_data: Dict, individual_analysis: Dict, 
                                         all_senders: List[str], all_urls: List[str], 
                                         all_subjects: List[str]) -> Dict[str, Any]:
        """Enhance individual analysis with thread context"""
        
        enhanced_analysis = individual_analysis.copy()
        thread_context = {
            'sender_consistency': True,
            'subject_manipulation': False,
            'url_evolution': False,
            'escalation_detected': False
        }
        
        current_sender = email_data.get('from', '')
        current_subject = email_data.get('subject', '')
        
        # Check sender consistency in thread
        if all_senders:
            unique_domains = set()
            for sender in all_senders + [current_sender]:
                if '@' in sender:
                    domain = sender.split('@')[-1].split('>')[0].strip()
                    unique_domains.add(domain.lower())
            
            if len(unique_domains) > 2:  # Multiple domains in thread
                thread_context['sender_consistency'] = False
                enhanced_analysis['thread_warnings'] = enhanced_analysis.get('thread_warnings', [])
                enhanced_analysis['thread_warnings'].append({
                    'type': 'sender_inconsistency',
                    'details': f'Multiple domains in thread: {list(unique_domains)}',
                    'risk': 'MEDIUM'
                })
        
        # Check subject evolution for manipulation
        if all_subjects:
            for prev_subject in all_subjects:
                if self._is_subject_manipulation(prev_subject, current_subject):
                    thread_context['subject_manipulation'] = True
                    enhanced_analysis['thread_warnings'] = enhanced_analysis.get('thread_warnings', [])
                    enhanced_analysis['thread_warnings'].append({
                        'type': 'subject_manipulation',
                        'details': f'Subject changed from "{prev_subject}" to "{current_subject}"',
                        'risk': 'HIGH'
                    })
        
        # Check URL evolution in thread
        current_urls = re.findall(r'https?://[^\s<>"\'()]+', email_data['content'])
        if all_urls and current_urls:
            if self._detect_url_evolution(all_urls, current_urls):
                thread_context['url_evolution'] = True
                enhanced_analysis['thread_warnings'] = enhanced_analysis.get('thread_warnings', [])
                enhanced_analysis['thread_warnings'].append({
                    'type': 'url_evolution',
                    'details': 'URLs becoming progressively more suspicious in thread',
                    'risk': 'HIGH'
                })
        
        enhanced_analysis['thread_context'] = thread_context
        return enhanced_analysis
    
    def _is_subject_manipulation(self, prev_subject: str, current_subject: str) -> bool:
        """Check if subject shows signs of manipulation"""
        # Remove common prefixes
        clean_prev = re.sub(r'^(Re:|Fwd?:|RE:|FWD?:)\s*', '', prev_subject, flags=re.IGNORECASE).strip()
        clean_current = re.sub(r'^(Re:|Fwd?:|RE:|FWD?:)\s*', '', current_subject, flags=re.IGNORECASE).strip()
        
        # Look for suspicious changes
        suspicious_additions = ['urgent', 'immediate', 'suspended', 'verify', 'confirm', 'action required']
        
        for addition in suspicious_additions:
            if addition.lower() not in clean_prev.lower() and addition.lower() in clean_current.lower():
                return True
        
        return False
    
    def _detect_url_evolution(self, previous_urls: List[str], current_urls: List[str]) -> bool:
        """Detect if URLs are becoming more suspicious"""
        try:
            suspicious_patterns = ['.tk', '.ml', '.ga', 'bit.ly', 'tinyurl', 'redirect', 'verify', 'suspend']
            
            prev_suspicious_count = sum(
                1 for url in previous_urls 
                for pattern in suspicious_patterns 
                if pattern in url.lower()
            )
            
            current_suspicious_count = sum(
                1 for url in current_urls 
                for pattern in suspicious_patterns 
                if pattern in url.lower()
            )
            
            # If current email has more suspicious URLs than previous ones
            return current_suspicious_count > prev_suspicious_count
            
        except Exception as e:
            logger.debug(f"Error detecting URL evolution: {str(e)}")
            return False
    
    async def _analyze_thread_patterns(self, all_senders: List[str], all_urls: List[str], 
                                     all_subjects: List[str], threat_levels: List[str],
                                     thread_info: Dict) -> Dict[str, Any]:
        """Analyze patterns across the entire thread"""
        patterns = {
            'escalating_urgency': False,
            'sender_spoofing_progression': False,
            'attachment_delivery_chain': False,
            'url_progression': False,
            'social_engineering_buildup': False
        }
        
        try:
            # Check for escalating urgency in subjects
            urgency_words = ['urgent', 'immediate', 'asap', 'emergency', 'critical', 'expires', 'suspend']
            urgency_scores = []
            
            for subject in all_subjects:
                score = sum(1 for word in urgency_words if word.lower() in subject.lower())
                urgency_scores.append(score)
            
            if len(urgency_scores) > 1 and urgency_scores[-1] > urgency_scores[0]:
                patterns['escalating_urgency'] = True
            
            # Check for sender progression (legitimate -> suspicious)
            if len(all_senders) > 1:
                first_sender_domain = all_senders[0].split('@')[-1].lower() if '@' in all_senders[0] else ''
                last_sender_domain = all_senders[-1].split('@')[-1].lower() if '@' in all_senders[-1] else ''
                
                # If thread starts with legitimate domain and moves to suspicious
                legitimate_domains = ['gmail.com', 'outlook.com', 'yahoo.com', 'company.com']
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
                
                if (any(domain in first_sender_domain for domain in legitimate_domains) and
                    any(tld in last_sender_domain for tld in suspicious_tlds)):
                    patterns['sender_spoofing_progression'] = True
            
            # Check threat level progression
            if len(threat_levels) > 1:
                threat_scores = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
                if (threat_scores.get(threat_levels[-1], 0) > 
                    threat_scores.get(threat_levels[0], 0)):
                    patterns['social_engineering_buildup'] = True
            
            return patterns
            
        except Exception as e:
            logger.error(f"Error analyzing thread patterns: {str(e)}")
            return patterns
    
    def _calculate_thread_threat_level(self, threat_levels: List[str], patterns: Dict[str, bool]) -> str:
        """Calculate overall threat level for the entire thread"""
        try:
            # Get highest individual threat level
            threat_scores = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4, 'UNKNOWN': 0}
            max_individual_score = max([threat_scores.get(level, 0) for level in threat_levels] or [0])
            
            # Pattern-based escalation
            pattern_escalation = 0
            if patterns.get('escalating_urgency'):
                pattern_escalation += 1
            if patterns.get('sender_spoofing_progression'):
                pattern_escalation += 2
            if patterns.get('social_engineering_buildup'):
                pattern_escalation += 1
            
            # Calculate final score
            final_score = max_individual_score + pattern_escalation
            
            if final_score >= 5:
                return 'CRITICAL'
            elif final_score >= 4:
                return 'HIGH'
            elif final_score >= 2:
                return 'MEDIUM'
            else:
                return 'LOW'
                
        except Exception as e:
            logger.error(f"Error calculating thread threat level: {str(e)}")
            return 'UNKNOWN'
    
    def _generate_thread_summary(self, thread_analysis: Dict, all_senders: List[str], 
                                all_subjects: List[str]) -> Dict[str, Any]:
        """Generate summary of thread analysis"""
        return {
            'unique_senders': len(set(all_senders)),
            'subject_changes': len(set(all_subjects)),
            'malicious_percentage': round(
                (thread_analysis['malicious_emails_found'] / 
                 max(thread_analysis['total_emails_in_thread'], 1)) * 100, 1
            ),
            'patterns_detected': sum(1 for pattern in thread_analysis['thread_patterns'].values() if pattern),
            'risk_assessment': self._get_thread_risk_assessment(thread_analysis)
        }
    
    def _get_thread_risk_assessment(self, thread_analysis: Dict) -> str:
        """Get risk assessment for the thread"""
        threat_level = thread_analysis['thread_threat_level']
        malicious_count = thread_analysis['malicious_emails_found']
        patterns_count = sum(1 for pattern in thread_analysis['thread_patterns'].values() if pattern)
        
        if threat_level == 'CRITICAL' or malicious_count > 0:
            return "HIGH RISK: Thread contains malicious content and should be quarantined immediately."
        elif patterns_count > 2:
            return "MEDIUM RISK: Multiple suspicious patterns detected in thread progression."
        elif patterns_count > 0:
            return "LOW RISK: Some suspicious patterns detected, monitor closely."
        else:
            return "MINIMAL RISK: Thread appears legitimate with no concerning patterns."

# Global instance
thread_analyzer = EmailThreadAnalyzer()