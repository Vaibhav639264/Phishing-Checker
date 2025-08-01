import os
import json
import base64
import email
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

class GmailService:
    def __init__(self):
        self.client_id = os.environ.get('GMAIL_CLIENT_ID')
        self.client_secret = os.environ.get('GMAIL_CLIENT_SECRET') 
        self.refresh_token = os.environ.get('GMAIL_REFRESH_TOKEN')
        self.credentials = None
        self.service = None
        self.scopes = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.send'
        ]
        
    async def initialize(self):
        """Initialize Gmail service with credentials"""
        try:
            if self.client_id and self.client_secret and self.refresh_token:
                # Use refresh token
                creds_info = {
                    'client_id': self.client_id,
                    'client_secret': self.client_secret,
                    'refresh_token': self.refresh_token,
                    'token_uri': 'https://oauth2.googleapis.com/token'
                }
                self.credentials = Credentials.from_authorized_user_info(creds_info, self.scopes)
                
                # Refresh if expired
                if self.credentials.expired:
                    self.credentials.refresh(Request())
                    
                self.service = build('gmail', 'v1', credentials=self.credentials)
                logger.info("Gmail service initialized successfully")
                return True
            else:
                logger.error("Gmail credentials not found in environment")
                return False
                
        except Exception as e:
            logger.error(f"Failed to initialize Gmail service: {str(e)}")
            return False

    def generate_auth_url(self) -> str:
        """Generate OAuth authorization URL for getting refresh token"""
        try:
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": ["http://localhost:8080/callback"]
                    }
                },
                scopes=self.scopes
            )
            flow.redirect_uri = "http://localhost:8080/callback"
            
            auth_url, _ = flow.authorization_url(prompt='consent')
            return auth_url
        except Exception as e:
            logger.error(f"Failed to generate auth URL: {str(e)}")
            return ""

    async def get_recent_emails(self, max_results: int = 10) -> List[Dict[str, Any]]:
        """Get recent emails from Gmail"""
        try:
            if not self.service:
                await self.initialize()
                
            # Get message list
            results = self.service.users().messages().list(
                userId='me',
                maxResults=max_results,
                q='in:inbox'  # Only inbox emails
            ).execute()
            
            messages = results.get('messages', [])
            emails = []
            
            for message in messages:
                msg_detail = self.service.users().messages().get(
                    userId='me', 
                    id=message['id'],
                    format='full'
                ).execute()
                
                # Parse email content
                email_data = self._parse_email_message(msg_detail)
                emails.append(email_data)
                
            return emails
            
        except HttpError as e:
            logger.error(f"Gmail API error: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Failed to get emails: {str(e)}")
            return []

    def _parse_email_message(self, message: Dict) -> Dict[str, Any]:
        """Parse Gmail message into structured format"""
        try:
            payload = message['payload']
            headers = payload.get('headers', [])
            
            # Extract headers
            email_data = {
                'id': message['id'],
                'thread_id': message['threadId'],
                'from': '',
                'to': '',
                'subject': '',
                'date': '',
                'body': '',
                'attachments': []
            }
            
            for header in headers:
                name = header['name'].lower()
                if name == 'from':
                    email_data['from'] = header['value']
                elif name == 'to':
                    email_data['to'] = header['value']
                elif name == 'subject':
                    email_data['subject'] = header['value']
                elif name == 'date':
                    email_data['date'] = header['value']
            
            # Extract body
            email_data['body'] = self._extract_body(payload)
            
            # Extract attachments info
            email_data['attachments'] = self._extract_attachments(payload)
            
            return email_data
            
        except Exception as e:
            logger.error(f"Failed to parse email: {str(e)}")
            return {}

    def _extract_body(self, payload: Dict) -> str:
        """Extract email body from payload"""
        try:
            body = ""
            
            if 'parts' in payload:
                # Multipart message
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain':
                        data = part['body'].get('data', '')
                        if data:
                            body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                    elif part['mimeType'] == 'text/html':
                        data = part['body'].get('data', '')
                        if data and not body:  # Use HTML if no plain text
                            body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            else:
                # Single part message
                if payload['mimeType'] in ['text/plain', 'text/html']:
                    data = payload['body'].get('data', '')
                    if data:
                        body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            
            return body
            
        except Exception as e:
            logger.error(f"Failed to extract body: {str(e)}")
            return ""

    def _extract_attachments(self, payload: Dict) -> List[Dict[str, str]]:
        """Extract attachment information"""
        try:
            attachments = []
            
            if 'parts' in payload:
                for part in payload['parts']:
                    if part.get('filename'):
                        attachments.append({
                            'filename': part['filename'],
                            'mime_type': part['mimeType'],
                            'size': part['body'].get('size', 0)
                        })
            
            return attachments
            
        except Exception as e:
            logger.error(f"Failed to extract attachments: {str(e)}")
            return []

    async def mark_as_spam(self, message_id: str) -> bool:
        """Mark email as spam"""
        try:
            if not self.service:
                await self.initialize()
                
            self.service.users().messages().modify(
                userId='me',
                id=message_id,
                body={'addLabelIds': ['SPAM']}
            ).execute()
            
            logger.info(f"Email {message_id} marked as spam")
            return True
            
        except Exception as e:
            logger.error(f"Failed to mark as spam: {str(e)}")
            return False

    async def block_sender(self, sender_email: str) -> bool:
        """Create filter to block sender"""
        try:
            if not self.service:
                await self.initialize()
                
            # Extract email from "Name <email>" format
            if '<' in sender_email and '>' in sender_email:
                sender_email = sender_email.split('<')[1].split('>')[0]
            
            filter_criteria = {
                'criteria': {
                    'from': sender_email
                },
                'action': {
                    'addLabelIds': ['SPAM'],
                    'removeLabelIds': ['INBOX']
                }
            }
            
            self.service.users().settings().filters().create(
                userId='me',
                body=filter_criteria
            ).execute()
            
            logger.info(f"Sender {sender_email} blocked")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block sender: {str(e)}")
            return False

    async def send_alert_notification(self, threat_details: Dict[str, Any], recipient_email: str) -> bool:
        """Send alert notification email"""
        try:
            if not self.service:
                await self.initialize()
                
            # Create alert message
            subject = f"🚨 PHISHING ALERT: {threat_details.get('threat_level', 'HIGH')} Threat Detected"
            
            body = f"""
PHISHING EMAIL DETECTED AND BLOCKED

Threat Level: {threat_details.get('threat_level', 'Unknown')}
From: {threat_details.get('from', 'Unknown')}
Subject: {threat_details.get('subject', 'Unknown')}
Detection Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

ACTIONS TAKEN:
✅ Email marked as spam
✅ Sender blocked automatically
✅ Email moved to spam folder

DETECTION DETAILS:
{self._format_threat_details(threat_details)}

This email has been automatically processed by your Email Phishing Detector.
"""
            
            message = MIMEText(body)
            message['to'] = recipient_email
            message['subject'] = subject
            
            # Send via Gmail API
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
            
            self.service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
            
            logger.info(f"Alert notification sent to {recipient_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send alert: {str(e)}")
            return False

    def _format_threat_details(self, details: Dict[str, Any]) -> str:
        """Format threat details for alert email"""
        formatted = ""
        
        if 'url_analysis' in details and details['url_analysis']:
            formatted += "\n🔗 SUSPICIOUS URLS DETECTED:\n"
            for finding in details['url_analysis'][:3]:  # Show top 3
                formatted += f"  • {finding.get('type', 'Unknown')}: {finding.get('original_url', 'N/A')}\n"
        
        if 'sender_analysis' in details and details['sender_analysis']:
            formatted += "\n👤 SENDER ISSUES:\n"
            for finding in details['sender_analysis'][:3]:
                formatted += f"  • {finding.get('type', 'Unknown')}: {finding.get('suspected_brand', 'N/A')}\n"
        
        if 'social_engineering' in details and details['social_engineering']:
            formatted += "\n🧠 SOCIAL ENGINEERING DETECTED:\n"
            for finding in details['social_engineering'][:3]:
                formatted += f"  • {finding.get('type', 'Unknown')}\n"
        
        if 'llm_analysis' in details and details['llm_analysis']:
            formatted += f"\n🤖 AI ANALYSIS:\n{details['llm_analysis'][:200]}...\n"
        
        return formatted

    async def monitor_new_emails(self, callback_func, check_interval: int = 60):
        """Monitor for new emails and process them"""
        logger.info(f"Starting email monitoring (checking every {check_interval} seconds)")
        last_check = datetime.now() - timedelta(minutes=5)  # Start 5 minutes ago
        
        while True:
            try:
                if not self.service:
                    await self.initialize()
                
                # Get emails since last check
                query = f'in:inbox after:{int(last_check.timestamp())}'
                results = self.service.users().messages().list(
                    userId='me',
                    q=query
                ).execute()
                
                messages = results.get('messages', [])
                
                for message in messages:
                    msg_detail = self.service.users().messages().get(
                        userId='me', 
                        id=message['id'],
                        format='full'
                    ).execute()
                    
                    email_data = self._parse_email_message(msg_detail)
                    
                    # Process with callback (phishing detection)
                    await callback_func(email_data)
                
                last_check = datetime.now()
                await asyncio.sleep(check_interval)
                
            except Exception as e:
                logger.error(f"Error in email monitoring: {str(e)}")
                await asyncio.sleep(check_interval)

    async def test_connection(self) -> Dict[str, Any]:
        """Test Gmail API connection"""
        try:
            if not self.service:
                success = await self.initialize()
                if not success:
                    return {'status': 'error', 'message': 'Failed to initialize service'}
            
            # Test with a simple API call
            profile = self.service.users().getProfile(userId='me').execute()
            
            return {
                'status': 'success',
                'message': 'Gmail connection successful',
                'email': profile.get('emailAddress', 'Unknown'),
                'total_messages': profile.get('messagesTotal', 0)
            }
            
        except Exception as e:
            return {
                'status': 'error', 
                'message': f'Connection failed: {str(e)}'
            }