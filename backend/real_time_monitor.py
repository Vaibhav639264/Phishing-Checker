import asyncio
import logging
from datetime import datetime
from typing import Dict, Any
from gmail_service import GmailService
from server import PhishingDetector, db, EmailAnalysisResult

logger = logging.getLogger(__name__)

class RealTimeEmailMonitor:
    def __init__(self):
        self.gmail_service = GmailService()
        self.detector = PhishingDetector()
        self.monitoring = False
        self.alert_email = None  # Set this to user's email for alerts
        
    async def start_monitoring(self, alert_email: str = None, check_interval: int = 60):
        """Start real-time email monitoring"""
        self.alert_email = alert_email
        self.monitoring = True
        
        logger.info("Starting real-time email monitoring...")
        
        # Initialize Gmail service
        success = await self.gmail_service.initialize()
        if not success:
            logger.error("Failed to initialize Gmail service")
            return False
        
        # Start monitoring loop
        await self.gmail_service.monitor_new_emails(
            callback_func=self.process_new_email,
            check_interval=check_interval
        )
        
        return True
    
    async def stop_monitoring(self):
        """Stop email monitoring"""
        self.monitoring = False
        logger.info("Email monitoring stopped")
    
    async def process_new_email(self, email_data: Dict[str, Any]):
        """Process new email for phishing detection"""
        try:
            logger.info(f"Processing new email from: {email_data.get('from', 'Unknown')}")
            
            # Convert email data to email format for analysis
            email_content = self._convert_to_email_format(email_data)
            
            # Analyze with existing phishing detector
            analysis_result = await self.detector.analyze_email(
                email_content, 
                f"gmail_{email_data.get('id', 'unknown')}.eml"
            )
            
            # Check threat level
            threat_level = analysis_result.get('threat_level', 'LOW')
            
            if threat_level in ['HIGH', 'CRITICAL']:
                logger.warning(f"PHISHING DETECTED! Threat level: {threat_level}")
                
                # Take automated actions
                await self._take_automated_actions(email_data, analysis_result)
                
                # Store analysis result
                await self._store_analysis_result(email_data, analysis_result)
                
            elif threat_level == 'MEDIUM':
                logger.info(f"Suspicious email detected (MEDIUM threat)")
                
                # Send alert but don't block automatically
                if self.alert_email:
                    await self.gmail_service.send_alert_notification(
                        {**analysis_result, **email_data}, 
                        self.alert_email
                    )
                
                await self._store_analysis_result(email_data, analysis_result)
            
            else:
                logger.debug(f"Email appears legitimate (threat level: {threat_level})")
                
        except Exception as e:
            logger.error(f"Error processing email: {str(e)}")
    
    async def _take_automated_actions(self, email_data: Dict[str, Any], analysis_result: Dict[str, Any]):
        """Take automated actions for high-threat emails"""
        try:
            message_id = email_data.get('id')
            sender = email_data.get('from', '')
            
            # 1. Mark as spam
            spam_success = await self.gmail_service.mark_as_spam(message_id)
            logger.info(f"Mark as spam: {'✅' if spam_success else '❌'}")
            
            # 2. Block sender
            if sender:
                block_success = await self.gmail_service.block_sender(sender)
                logger.info(f"Block sender {sender}: {'✅' if block_success else '❌'}")
            
            # 3. Send alert notification
            if self.alert_email:
                alert_success = await self.gmail_service.send_alert_notification(
                    {**analysis_result, **email_data},
                    self.alert_email
                )
                logger.info(f"Send alert: {'✅' if alert_success else '❌'}")
            
            logger.info(f"Automated actions completed for email {message_id}")
            
        except Exception as e:
            logger.error(f"Error taking automated actions: {str(e)}")
    
    async def _store_analysis_result(self, email_data: Dict[str, Any], analysis_result: Dict[str, Any]):
        """Store analysis result in database"""
        try:
            email_analysis = EmailAnalysisResult(
                filename=f"gmail_{email_data.get('id', 'unknown')}.eml",
                analysis_result={
                    **analysis_result,
                    'gmail_data': email_data,
                    'monitoring_source': 'real_time'
                },
                threat_level=analysis_result.get('threat_level', 'UNKNOWN')
            )
            
            await db.email_analyses.insert_one(email_analysis.dict())
            logger.info("Analysis result stored in database")
            
        except Exception as e:
            logger.error(f"Error storing analysis result: {str(e)}")
    
    def _convert_to_email_format(self, email_data: Dict[str, Any]) -> str:
        """Convert Gmail data to standard email format"""
        try:
            email_content = f"""From: {email_data.get('from', '')}
To: {email_data.get('to', '')}
Subject: {email_data.get('subject', '')}
Date: {email_data.get('date', '')}

{email_data.get('body', '')}
"""
            return email_content
            
        except Exception as e:
            logger.error(f"Error converting email format: {str(e)}")
            return ""
    
    async def manual_scan_recent(self, max_emails: int = 50) -> Dict[str, Any]:
        """Manually scan recent emails"""
        try:
            logger.info(f"Starting manual scan of {max_emails} recent emails")
            
            # Get recent emails
            emails = await self.gmail_service.get_recent_emails(max_emails)
            
            results = {
                'total_scanned': len(emails),
                'threats_found': 0,
                'actions_taken': 0,
                'findings': []
            }
            
            for email_data in emails:
                email_content = self._convert_to_email_format(email_data)
                analysis_result = await self.detector.analyze_email(
                    email_content, 
                    f"manual_scan_{email_data.get('id', 'unknown')}.eml"
                )
                
                threat_level = analysis_result.get('threat_level', 'LOW')
                
                if threat_level in ['HIGH', 'CRITICAL', 'MEDIUM']:
                    results['threats_found'] += 1
                    
                    findings = {
                        'email_id': email_data.get('id'),
                        'from': email_data.get('from'),
                        'subject': email_data.get('subject'),
                        'threat_level': threat_level,
                        'analysis': analysis_result
                    }
                    
                    if threat_level in ['HIGH', 'CRITICAL']:
                        await self._take_automated_actions(email_data, analysis_result)
                        results['actions_taken'] += 1
                        findings['actions_taken'] = True
                    
                    results['findings'].append(findings)
                    await self._store_analysis_result(email_data, analysis_result)
            
            logger.info(f"Manual scan completed: {results['threats_found']} threats found")
            return results
            
        except Exception as e:
            logger.error(f"Error in manual scan: {str(e)}")
            return {'error': str(e)}

# Global monitor instance
email_monitor = RealTimeEmailMonitor()