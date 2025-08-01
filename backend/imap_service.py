import imaplib
import email
import asyncio
import logging
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import os
import ssl

logger = logging.getLogger(__name__)

class IMAPService:
    def __init__(self, email_address=None, app_password=None):
        # Allow credentials to be passed directly or from environment
        self.email_address = email_address or os.environ.get('GMAIL_EMAIL')
        self.app_password = app_password or os.environ.get('GMAIL_APP_PASSWORD')
        self.imap_server = 'imap.gmail.com'
        self.smtp_server = 'smtp.gmail.com'
        self.imap_port = 993
        self.smtp_port = 587
        self.mail = None
        
    async def initialize(self) -> bool:
        """Initialize IMAP connection with timeout"""
        try:
            if not self.email_address or not self.app_password:
                logger.error(f"Gmail credentials missing - Email: {bool(self.email_address)}, Password: {bool(self.app_password)}")
                return False
                
            logger.info(f"Attempting IMAP connection for {self.email_address}")
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect to IMAP server with timeout
            self.mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port, ssl_context=context)
            self.mail.sock.settimeout(30)  # 30 second timeout
            
            # Login with timeout handling
            try:
                self.mail.login(self.email_address, self.app_password)
            except socket.timeout:
                logger.error("IMAP login timeout - connection took too long")
                return False
            
            logger.info(f"✅ IMAP connection established for {self.email_address}")
            return True
            
        except imaplib.IMAP4.error as e:
            logger.error(f"❌ IMAP authentication failed: {str(e)}")
            return False
        except socket.timeout:
            logger.error("❌ IMAP connection timeout")
            return False
        except Exception as e:
            logger.error(f"❌ Failed to initialize IMAP connection: {str(e)}")
            return False

    async def get_recent_emails(self, max_results: int = 10) -> List[Dict[str, Any]]:
        """Get recent emails from Gmail via IMAP"""
        try:
            if not self.mail:
                success = await self.initialize()
                if not success:
                    return []
            
            # Select inbox
            self.mail.select('INBOX')
            
            # Search for recent emails
            today = datetime.now()
            since_date = (today - timedelta(days=1)).strftime('%d-%b-%Y')
            
            status, messages = self.mail.search(None, f'(SINCE "{since_date}")')
            
            if status != 'OK':
                logger.error("Failed to search emails")
                return []
            
            email_ids = messages[0].split()
            
            # Get the most recent emails
            recent_ids = email_ids[-max_results:] if len(email_ids) > max_results else email_ids
            emails = []
            
            for email_id in reversed(recent_ids):  # Most recent first
                try:
                    status, msg_data = self.mail.fetch(email_id, '(RFC822)')
                    
                    if status == 'OK':
                        email_message = email.message_from_bytes(msg_data[0][1])
                        parsed_email = self._parse_email(email_message, email_id.decode())
                        emails.append(parsed_email)
                        
                except Exception as e:
                    logger.error(f"Error parsing email {email_id}: {str(e)}")
                    continue
            
            return emails
            
        except Exception as e:
            logger.error(f"Failed to get recent emails: {str(e)}")
            return []

    def _parse_email(self, email_message, email_id: str) -> Dict[str, Any]:
        """Parse email message into structured format"""
        try:
            # Extract basic info
            email_data = {
                'id': email_id,
                'from': email_message.get('From', ''),
                'to': email_message.get('To', ''),
                'subject': email_message.get('Subject', ''),
                'date': email_message.get('Date', ''),
                'body': '',
                'attachments': []
            }
            
            # Extract body
            if email_message.is_multipart():
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition'))
                    
                    # Skip attachments
                    if 'attachment' not in content_disposition:
                        if content_type == 'text/plain':
                            body = part.get_payload(decode=True)
                            if body:
                                email_data['body'] += body.decode('utf-8', errors='ignore')
                        elif content_type == 'text/html' and not email_data['body']:
                            body = part.get_payload(decode=True)
                            if body:
                                email_data['body'] = body.decode('utf-8', errors='ignore')
                    else:
                        # Track attachments
                        filename = part.get_filename()
                        if filename:
                            email_data['attachments'].append({
                                'filename': filename,
                                'content_type': content_type,
                                'size': len(part.get_payload())
                            })
            else:
                # Single part message
                body = email_message.get_payload(decode=True)
                if body:
                    email_data['body'] = body.decode('utf-8', errors='ignore')
            
            return email_data
            
        except Exception as e:
            logger.error(f"Error parsing email: {str(e)}")
            return {}

    async def mark_as_spam(self, email_id: str) -> bool:
        """Mark email as spam by moving to spam folder"""
        try:
            if not self.mail:
                await self.initialize()
            
            # Select inbox
            self.mail.select('INBOX')
            
            # Move to spam folder
            self.mail.move(email_id, '[Gmail]/Spam')
            
            logger.info(f"Email {email_id} marked as spam")
            return True
            
        except Exception as e:
            logger.error(f"Failed to mark email as spam: {str(e)}")
            return False

    async def send_alert_email(self, threat_details: Dict[str, Any], recipient_email: str) -> bool:
        """Send alert email via SMTP"""
        try:
            logger.info(f"🚨 Sending security alert to {recipient_email}")
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_address
            msg['To'] = recipient_email
            msg['Subject'] = f"🚨 PHISHING ALERT: {threat_details.get('threat_level', 'HIGH')} Threat Detected"
            
            # Get account info
            monitored_account = threat_details.get('monitored_account', 'Unknown Account')
            employee_name = threat_details.get('account_config', {}).get('employee_name', 'Unknown Employee')
            
            # Email body
            body = f"""
🚨 PHISHING EMAIL DETECTED AND BLOCKED

AFFECTED ACCOUNT: {employee_name} ({monitored_account})
Threat Level: {threat_details.get('threat_level', 'Unknown')}
From: {threat_details.get('from', 'Unknown')}
Subject: {threat_details.get('subject', 'Unknown')}
Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

ACTIONS TAKEN:
✅ Email marked as spam
✅ Email moved to spam folder
✅ Alert sent to security team

DETECTION DETAILS:
{self._format_threat_details(threat_details)}

EMPLOYEE INFORMATION:
👤 Name: {employee_name}
📧 Email: {monitored_account}
🏢 Department: {threat_details.get('account_config', {}).get('department', 'Not specified')}

This email has been automatically processed by your Email Phishing Detector.
No action required from the employee.

For questions, contact your IT Security team.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to SMTP server
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_address, self.app_password)
            
            # Send email
            text = msg.as_string()
            server.sendmail(self.email_address, recipient_email, text)
            server.quit()
            
            logger.info(f"✅ Alert email sent successfully to {recipient_email}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send alert email: {str(e)}")
            return False

    def _format_threat_details(self, details: Dict[str, Any]) -> str:
        """Format threat details for alert email"""
        formatted = ""
        
        if 'url_analysis' in details and details['url_analysis']:
            formatted += "\n🔗 SUSPICIOUS URLS DETECTED:\n"
            for finding in details['url_analysis'][:3]:
                formatted += f"  • {finding.get('type', 'Unknown')}: {finding.get('original_url', 'N/A')}\n"
        
        if 'sender_analysis' in details and details['sender_analysis']:
            formatted += "\n👤 SENDER ISSUES:\n"
            for finding in details['sender_analysis'][:3]:
                formatted += f"  • {finding.get('type', 'Unknown')}: {finding.get('suspected_brand', 'N/A')}\n"
        
        if 'social_engineering' in details and details['social_engineering']:
            formatted += "\n🧠 SOCIAL ENGINEERING DETECTED:\n"
            for finding in details['social_engineering'][:3]:
                formatted += f"  • {finding.get('type', 'Unknown')}\n"
        
        return formatted

    async def monitor_new_emails(self, callback_func, check_interval: int = 60):
        """Monitor for new emails using IMAP IDLE or polling"""
        logger.info(f"Starting IMAP email monitoring (checking every {check_interval} seconds)")
        
        last_check_count = 0
        
        while True:
            try:
                if not self.mail:
                    await self.initialize()
                
                # Select inbox
                self.mail.select('INBOX')
                
                # Get current message count
                status, messages = self.mail.search(None, 'ALL')
                current_count = len(messages[0].split()) if messages[0] else 0
                
                # Check for new emails
                if current_count > last_check_count:
                    new_count = current_count - last_check_count
                    logger.info(f"Found {new_count} new emails")
                    
                    # Get recent emails
                    recent_emails = await self.get_recent_emails(new_count)
                    
                    # Process each new email
                    for email_data in recent_emails:
                        await callback_func(email_data)
                
                last_check_count = current_count
                await asyncio.sleep(check_interval)
                
            except Exception as e:
                logger.error(f"Error in email monitoring: {str(e)}")
                # Reconnect on error
                self.mail = None
                await asyncio.sleep(check_interval)

    async def test_connection(self) -> Dict[str, Any]:
        """Test IMAP connection with timeout"""
        try:
            logger.info(f"🔍 Testing IMAP connection for {self.email_address}")
            
            success = await self.initialize()
            
            if success:
                # Get inbox info with timeout
                try:
                    self.mail.select('INBOX')
                    status, messages = self.mail.search(None, 'ALL')
                    message_count = len(messages[0].split()) if messages[0] else 0
                    
                    # Close connection after test
                    self.close_connection()
                    
                    logger.info(f"✅ IMAP test successful: {message_count} messages found")
                    
                    return {
                        'status': 'success',
                        'message': f'IMAP connection successful! Found {message_count} messages in inbox.',
                        'email': self.email_address,
                        'total_messages': message_count
                    }
                except socket.timeout:
                    logger.error("❌ IMAP inbox access timeout")
                    return {
                        'status': 'error',
                        'message': 'Connection timeout while accessing inbox',
                        'details': 'The Gmail server took too long to respond. Please check your internet connection and try again.'
                    }
            else:
                return {
                    'status': 'error',
                    'message': 'Authentication failed. Please check your email and app password.',
                    'details': 'Make sure you have enabled 2-Factor Authentication and generated an App Password from Google Account settings.'
                }
                
        except imaplib.IMAP4.error as e:
            error_msg = str(e)
            logger.error(f"❌ IMAP test failed: {error_msg}")
            
            if 'AUTHENTICATIONFAILED' in error_msg:
                return {
                    'status': 'error',
                    'message': 'Invalid Gmail credentials',
                    'details': 'Please verify your email address and app password. Make sure 2FA is enabled and you are using an App Password, not your regular Gmail password.'
                }
            else:
                return {
                    'status': 'error',
                    'message': f'IMAP error: {error_msg}',
                    'details': 'Please check your Gmail settings and try again.'
                }
        except socket.timeout:
            logger.error("❌ IMAP connection timeout during test")
            return {
                'status': 'error',
                'message': 'Connection timeout',
                'details': 'Gmail server took too long to respond. Please check your internet connection and try again in a few minutes.'
            }
        except Exception as e:
            logger.error(f"❌ IMAP test exception: {str(e)}")
            return {
                'status': 'error',
                'message': f'Connection failed: {str(e)}',
                'details': 'Please check your internet connection and Gmail settings.'
            }

    def close_connection(self):
        """Close IMAP connection"""
        try:
            if self.mail:
                self.mail.close()
                self.mail.logout()
                logger.info("IMAP connection closed")
        except Exception as e:
            logger.error(f"Error closing connection: {str(e)}")