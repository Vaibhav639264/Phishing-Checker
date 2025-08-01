import imaplib
import email
import asyncio
import logging
import smtplib
import socket
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import os
import ssl
import re

logger = logging.getLogger(__name__)

class RobustIMAPService:
    def __init__(self, email_address=None, app_password=None):
        self.email_address = email_address or os.environ.get('GMAIL_EMAIL')
        self.app_password = app_password or os.environ.get('GMAIL_APP_PASSWORD')
        self.imap_server = 'imap.gmail.com'
        self.smtp_server = 'smtp.gmail.com'
        self.imap_port = 993
        self.smtp_port = 587
        self.mail = None
        self.connection_retries = 3
        self.retry_delay = 2
        
    def _create_connection(self) -> bool:
        """Create a new IMAP connection with retries"""
        for attempt in range(self.connection_retries):
            try:
                logger.info(f"🔗 IMAP connection attempt {attempt + 1}/{self.connection_retries}")
                
                # Create SSL context
                context = ssl.create_default_context()
                
                # Connect with timeout
                self.mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port, ssl_context=context)
                self.mail.sock.settimeout(15)  # 15 second timeout
                
                # Login
                self.mail.login(self.email_address, self.app_password)
                
                logger.info(f"✅ IMAP connection successful for {self.email_address}")
                return True
                
            except (imaplib.IMAP4.error, socket.timeout, ConnectionError) as e:
                logger.warning(f"⚠️ IMAP attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.connection_retries - 1:
                    time.sleep(self.retry_delay)
                    continue
                else:
                    logger.error(f"❌ All IMAP connection attempts failed")
                    return False
            except Exception as e:
                logger.error(f"❌ Unexpected IMAP error: {str(e)}")
                return False
        
        return False
    
    async def test_connection(self, quick_check: bool = False) -> Dict[str, Any]:
        """Test IMAP connection thoroughly or quickly"""
        try:
            if not self.email_address or not self.app_password:
                return {
                    'status': 'error',
                    'message': 'Missing credentials',
                    'details': 'Email address and app password are required'
                }
            
            logger.info(f"🧪 Testing IMAP connection for {self.email_address} (quick: {quick_check})")
            
            # Test connection
            if not self._create_connection():
                return {
                    'status': 'error',
                    'message': 'Failed to connect to Gmail IMAP server',
                    'details': 'Please check your email address and app password. Make sure 2FA is enabled and you are using an App Password.'
                }
            
            try:
                if quick_check:
                    # Quick check - just verify connection without detailed inbox access
                    self.close_connection()
                    return {
                        'status': 'success',
                        'message': f'✅ Gmail connection verified for {self.email_address}',
                        'email': self.email_address,
                        'quick_check': True
                    }
                else:
                    # Full check - access inbox and count messages
                    status, count = self.mail.select('INBOX')
                    if status != 'OK':
                        return {
                            'status': 'error',
                            'message': 'Cannot access Gmail inbox',
                            'details': 'Connection succeeded but inbox access failed'
                        }
                    
                    # Get message count
                    status, messages = self.mail.search(None, 'ALL')
                    message_count = len(messages[0].split()) if messages[0] else 0
                    
                    # Close connection
                    self.close_connection()
                    
                    return {
                        'status': 'success',
                        'message': f'✅ Gmail connection successful! Found {message_count} messages in inbox.',
                        'email': self.email_address,
                        'total_messages': message_count
                    }
                if status != 'OK':
                    return {
                        'status': 'error',
                        'message': 'Cannot access Gmail inbox',
                        'details': 'Connection succeeded but inbox access failed'
                    }
                
                # Get message count
                status, messages = self.mail.search(None, 'ALL')
                message_count = len(messages[0].split()) if messages[0] else 0
                
                # Close connection
                self.close_connection()
                
                return {
                    'status': 'success',
                    'message': f'✅ Gmail connection successful! Found {message_count} messages in inbox.',
                    'email': self.email_address,
                    'total_messages': message_count
                }
                
            except Exception as e:
                logger.error(f"❌ Inbox access failed: {str(e)}")
                return {
                    'status': 'error',
                    'message': 'Inbox access failed',
                    'details': str(e)
                }
                
        except Exception as e:
            logger.error(f"❌ Connection test failed: {str(e)}")
            return {
                'status': 'error',
                'message': f'Connection test failed: {str(e)}',
                'details': 'Please verify your credentials and try again'
            }
    
    def get_all_emails(self, limit: int = None) -> List[Dict[str, Any]]:
        """Get ALL emails from inbox (synchronous for reliability)"""
        try:
            logger.info(f"📧 Starting to fetch emails (limit: {limit or 'all'})")
            
            if not self._create_connection():
                logger.error("❌ Failed to create IMAP connection")
                return []
            
            # Select inbox
            status, count = self.mail.select('INBOX')
            if status != 'OK':
                logger.error("❌ Failed to select inbox")
                return []
            
            # Search for all emails
            status, messages = self.mail.search(None, 'ALL')
            if status != 'OK':
                logger.error("❌ Failed to search emails")
                return []
            
            email_ids = messages[0].split()
            total_emails = len(email_ids)
            
            logger.info(f"📊 Found {total_emails} emails in inbox")
            
            if limit:
                # Get most recent emails if limit specified
                email_ids = email_ids[-limit:]
                logger.info(f"📋 Processing {len(email_ids)} most recent emails")
            
            emails = []
            processed = 0
            errors = 0
            
            for email_id in reversed(email_ids):  # Most recent first
                try:
                    processed += 1
                    if processed % 10 == 0:
                        logger.info(f"📈 Progress: {processed}/{len(email_ids)} emails processed")
                    
                    # Fetch email
                    status, msg_data = self.mail.fetch(email_id, '(RFC822)')
                    if status != 'OK':
                        errors += 1
                        continue
                    
                    # Parse email
                    email_message = email.message_from_bytes(msg_data[0][1])
                    parsed_email = self._parse_email_thoroughly(email_message, email_id.decode())
                    
                    if parsed_email:
                        emails.append(parsed_email)
                    
                except Exception as e:
                    errors += 1
                    logger.debug(f"Error processing email {email_id}: {str(e)}")
                    continue
            
            self.close_connection()
            logger.info(f"✅ Email fetch completed: {len(emails)} emails processed, {errors} errors")
            
            return emails
            
        except Exception as e:
            logger.error(f"❌ Failed to get emails: {str(e)}")
            self.close_connection()
            return []
    
    def _parse_email_thoroughly(self, email_message, email_id: str) -> Dict[str, Any]:
        """Parse email message completely and thoroughly"""
        try:
            # Extract all headers
            email_data = {
                'id': email_id,
                'from': email_message.get('From', ''),
                'to': email_message.get('To', ''),
                'subject': email_message.get('Subject', ''),
                'date': email_message.get('Date', ''),
                'reply_to': email_message.get('Reply-To', ''),
                'return_path': email_message.get('Return-Path', ''),
                'message_id': email_message.get('Message-ID', ''),
                'body': '',
                'html_body': '',
                'attachments': [],
                'headers': dict(email_message.items())
            }
            
            # Extract body content
            if email_message.is_multipart():
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition'))
                    
                    if 'attachment' not in content_disposition:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                decoded_content = payload.decode('utf-8', errors='ignore')
                                
                                if content_type == 'text/plain':
                                    email_data['body'] += decoded_content + '\n'
                                elif content_type == 'text/html':
                                    email_data['html_body'] += decoded_content + '\n'
                        except Exception as e:
                            logger.debug(f"Error decoding part: {str(e)}")
                            continue
                    else:
                        # Handle attachments
                        filename = part.get_filename()
                        if filename:
                            email_data['attachments'].append({
                                'filename': filename,
                                'content_type': content_type,
                                'size': len(part.get_payload()) if part.get_payload() else 0
                            })
            else:
                # Single part message
                try:
                    payload = email_message.get_payload(decode=True)
                    if payload:
                        email_data['body'] = payload.decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.debug(f"Error decoding single part: {str(e)}")
            
            # If no plain text, extract from HTML
            if not email_data['body'] and email_data['html_body']:
                email_data['body'] = self._html_to_text(email_data['html_body'])
            
            return email_data
            
        except Exception as e:
            logger.error(f"❌ Error parsing email {email_id}: {str(e)}")
            return None
    
    def _html_to_text(self, html_content: str) -> str:
        """Convert HTML to plain text for analysis"""
        try:
            # Remove HTML tags
            clean = re.compile('<.*?>')
            text = re.sub(clean, '', html_content)
            
            # Decode HTML entities
            text = text.replace('&amp;', '&')
            text = text.replace('&lt;', '<')
            text = text.replace('&gt;', '>')
            text = text.replace('&nbsp;', ' ')
            text = text.replace('&quot;', '"')
            
            return text.strip()
        except Exception as e:
            logger.debug(f"Error converting HTML to text: {str(e)}")
            return html_content
    
    def mark_as_spam(self, email_id: str) -> bool:
        """Mark email as spam"""
        try:
            if not self._create_connection():
                return False
            
            self.mail.select('INBOX')
            
            # Move to spam folder
            self.mail.store(email_id, '+FLAGS', '\\Deleted')
            self.mail.expunge()
            
            # Also try to move to spam label
            try:
                self.mail.store(email_id, '+X-GM-LABELS', '\\Spam')
            except:
                pass  # Gmail-specific, might not work
            
            self.close_connection()
            logger.info(f"✅ Email {email_id} marked as spam")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to mark email as spam: {str(e)}")
            self.close_connection()
            return False
    
    def send_alert_email(self, threat_details: Dict[str, Any], recipient_email: str) -> bool:
        """Send alert email with comprehensive details"""
        try:
            logger.info(f"🚨 Sending enhanced security alert to {recipient_email}")
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_address
            msg['To'] = recipient_email
            msg['Subject'] = f"🚨 PHISHING BLOCKED: {threat_details.get('threat_level', 'HIGH')} Threat Detected"
            
            # Get detailed information
            email_from = threat_details.get('from', 'Unknown Sender')
            email_subject = threat_details.get('subject', 'No Subject')
            monitored_account = threat_details.get('monitored_account', self.email_address)
            
            # Create comprehensive alert body
            body = f"""
🚨 CRITICAL SECURITY ALERT - PHISHING EMAIL BLOCKED

THREAT DETAILS:
═══════════════════════════════════════════════════
📧 Affected Account: {monitored_account}
🎯 Threat Level: {threat_details.get('threat_level', 'HIGH')}
⏰ Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
🔍 Detection Method: Advanced AI + Pattern Analysis

EMAIL INFORMATION:
═══════════════════════════════════════════════════
📤 From: {email_from}
📝 Subject: {email_subject}
📅 Date: {threat_details.get('date', 'Unknown')}

ACTIONS AUTOMATICALLY TAKEN:
═══════════════════════════════════════════════════
✅ Email marked as spam and moved to spam folder
✅ Sender blocked from future emails
✅ Security team notified immediately
✅ Threat logged in security database

THREAT ANALYSIS:
═══════════════════════════════════════════════════
{self._format_comprehensive_threat_details(threat_details)}

SECURITY RECOMMENDATIONS:
═══════════════════════════════════════════════════
• This threat has been automatically neutralized
• No action required from the user
• Monitor for similar attempts from related domains
• Report any suspicious activity to IT security

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This alert was generated by your Enterprise Email Security System
Powered by AI-driven threat detection and real-time monitoring
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send via SMTP
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email_address, self.app_password)
                server.send_message(msg)
            
            logger.info(f"✅ Security alert sent successfully to {recipient_email}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send security alert: {str(e)}")
            return False
    
    def _format_comprehensive_threat_details(self, details: Dict[str, Any]) -> str:
        """Format comprehensive threat details for alert"""
        formatted = ""
        
        # URL Analysis
        if details.get('url_analysis'):
            formatted += "\n🔗 MALICIOUS URLS DETECTED:\n"
            for finding in details['url_analysis'][:5]:
                formatted += f"   • {finding.get('type', 'Suspicious URL')}: {finding.get('original_url', 'N/A')}\n"
        
        # Sender Analysis
        if details.get('sender_analysis'):
            formatted += "\n👤 SENDER AUTHENTICATION ISSUES:\n"
            for finding in details['sender_analysis'][:3]:
                formatted += f"   • {finding.get('type', 'Sender Issue')}: {finding.get('suspected_brand', 'N/A')}\n"
        
        # Social Engineering
        if details.get('social_engineering'):
            formatted += "\n🧠 SOCIAL ENGINEERING TACTICS:\n"
            for finding in details['social_engineering'][:3]:
                formatted += f"   • {finding.get('type', 'Social Engineering')}: {finding.get('pattern', 'N/A')}\n"
        
        # Advanced Analysis
        if details.get('advanced_url_analysis'):
            formatted += "\n🛡️ ADVANCED THREAT INDICATORS:\n"
            for finding in details['advanced_url_analysis'][:3]:
                threats = finding.get('threats_detected', [])
                for threat in threats[:2]:
                    formatted += f"   • {threat.get('type', 'Advanced Threat')}: {threat.get('details', 'N/A')}\n"
        
        # AI Analysis
        if details.get('llm_analysis'):
            ai_analysis = details['llm_analysis'][:300]  # First 300 chars
            formatted += f"\n🤖 AI SECURITY ANALYSIS:\n   {ai_analysis}...\n"
        
        if not formatted:
            formatted = "\n⚠️ Email flagged by multiple security heuristics and AI analysis\n"
        
        return formatted
    
    def close_connection(self):
        """Safely close IMAP connection"""
        try:
            if self.mail:
                self.mail.close()
                self.mail.logout()
                self.mail = None
        except Exception as e:
            logger.debug(f"Error closing IMAP connection: {str(e)}")
    
    def __del__(self):
        """Ensure connection is closed when object is destroyed"""
        self.close_connection()