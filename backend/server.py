from fastapi import FastAPI, APIRouter, File, UploadFile, HTTPException, BackgroundTasks
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime
import asyncio
import email
from robust_imap_service import RobustIMAPService
from enhanced_phishing_detector import EnhancedPhishingDetector

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Global services
robust_imap = None
phishing_detector = EnhancedPhishingDetector()
monitoring_active = False
monitoring_task = None

# Models
class EmailAnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    analysis_result: Dict[str, Any]
    threat_level: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class IMAPSetupRequest(BaseModel):
    email: str
    app_password: str

class MonitoringRequest(BaseModel):
    alert_email: str
    check_interval: Optional[int] = 60

class ManualScanRequest(BaseModel):
    max_emails: Optional[int] = 50

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def extract_email_data(email_message):
    """Extract basic email data from email message"""
    return {
        'id': email_message.get('Message-ID', str(uuid.uuid4())),
        'from': email_message.get('From', ''),
        'to': email_message.get('To', ''),
        'subject': email_message.get('Subject', ''),
        'date': email_message.get('Date', ''),
        'reply_to': email_message.get('Reply-To', ''),
        'return_path': email_message.get('Return-Path', ''),
        'message_id': email_message.get('Message-ID', ''),
        'body': email_message.get_payload() if not email_message.is_multipart() else '',
        'headers': dict(email_message.items())
    }

@api_router.get("/")
async def root():
    return {"message": "Enhanced Email Phishing Detection API"}

@api_router.post("/analyze-email")
async def analyze_uploaded_email(file: UploadFile = File(...)):
    """Analyze uploaded email file"""
    try:
        logger.info(f"📧 Analyzing uploaded email: {file.filename}")
        
        # Read file content
        content = await file.read()
        email_content = content.decode('utf-8', errors='ignore')
        
        # Parse email
        email_msg = email.message_from_string(email_content)
        email_data = extract_email_data(email_msg)
        
        logger.info(f"📋 Email parsed - Subject: {email_data.get('subject', 'N/A')}")
        
        # Analyze with enhanced detector
        analysis_result = await phishing_detector.analyze_email_comprehensive(
            email_content, email_data, file.filename
        )
        
        # Store in database
        analysis_result['id'] = str(uuid.uuid4())
        analysis_result['timestamp'] = datetime.utcnow().isoformat()
        
        await db.email_analyses.insert_one(analysis_result)
        
        logger.info(f"✅ Analysis complete: {analysis_result['threat_level']} threat level")
        
        return EmailAnalysisResult(**analysis_result)
        
    except Exception as e:
        logger.error(f"❌ Email analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@api_router.post("/imap/test-connection")
async def test_imap_connection(request: IMAPSetupRequest):
    """Test IMAP connection without saving"""
    try:
        logger.info(f"🧪 Testing IMAP connection for {request.email}")
        
        test_service = RobustIMAPService(request.email, request.app_password)
        result = await test_service.test_connection()
        
        logger.info(f"📊 Test result: {result['status']}")
        return result
        
    except Exception as e:
        logger.error(f"❌ Connection test failed: {str(e)}")
        return {
            'status': 'error',
            'message': f'Test failed: {str(e)}',
            'details': 'Please check your credentials and try again.'
        }

@api_router.post("/imap/setup")
async def setup_imap(request: IMAPSetupRequest):
    """Setup and save IMAP credentials"""
    global robust_imap
    
    try:
        logger.info(f"⚙️ Setting up IMAP for {request.email}")
        
        # Test connection first
        test_service = RobustIMAPService(request.email, request.app_password)
        test_result = await test_service.test_connection()
        
        if test_result['status'] != 'success':
            return {
                'success': False,
                'message': 'IMAP setup failed - connection test failed',
                'connection_test': test_result
            }
        
        # Save credentials to environment and .env file
        os.environ['GMAIL_EMAIL'] = request.email
        os.environ['GMAIL_APP_PASSWORD'] = request.app_password
        
        # Update .env file for persistence
        env_file_path = ROOT_DIR / '.env'
        env_lines = []
        
        # Read existing .env file
        if env_file_path.exists():
            with open(env_file_path, 'r') as f:
                env_lines = f.readlines()
        
        # Update or add credentials
        gmail_email_found = False
        gmail_password_found = False
        
        for i, line in enumerate(env_lines):
            if line.startswith('GMAIL_EMAIL='):
                env_lines[i] = f'GMAIL_EMAIL="{request.email}"\n'
                gmail_email_found = True
            elif line.startswith('GMAIL_APP_PASSWORD='):
                env_lines[i] = f'GMAIL_APP_PASSWORD="{request.app_password}"\n'
                gmail_password_found = True
        
        if not gmail_email_found:
            env_lines.append(f'GMAIL_EMAIL="{request.email}"\n')
        if not gmail_password_found:
            env_lines.append(f'GMAIL_APP_PASSWORD="{request.app_password}"\n')
        
        # Write back to .env file
        with open(env_file_path, 'w') as f:
            f.writelines(env_lines)
        
        # Update global service
        robust_imap = RobustIMAPService(request.email, request.app_password)
        
        logger.info(f"✅ IMAP setup successful for {request.email}")
        
        return {
            'success': True,
            'message': 'IMAP connection configured and saved successfully',
            'connection_test': test_result
        }
        
    except Exception as e:
        logger.error(f"❌ IMAP setup failed: {str(e)}")
        return {
            'success': False,
            'message': f'IMAP setup failed: {str(e)}',
            'connection_test': {'status': 'error', 'message': str(e)}
        }

@api_router.get("/imap/status")
async def get_imap_status():
    """Get IMAP connection status with quick check"""
    try:
        email = os.environ.get('GMAIL_EMAIL')
        password = os.environ.get('GMAIL_APP_PASSWORD')
        
        if not email or not password:
            return {
                'configured': False,
                'monitoring_active': False,
                'status': 'error',
                'message': 'IMAP credentials not configured'
            }
        
        # Quick connection test for faster response
        if robust_imap:
            test_result = await robust_imap.test_connection(quick_check=True)
            
            return {
                'configured': test_result['status'] == 'success',
                'monitoring_active': monitoring_active,
                'email': email,
                'status': test_result['status'],
                'message': test_result['message']
            }
        else:
            return {
                'configured': False,
                'monitoring_active': False,
                'status': 'error',
                'message': 'IMAP service not initialized'
            }
            
    except Exception as e:
        logger.error(f"❌ Status check failed: {str(e)}")
        return {
            'configured': False,
            'monitoring_active': False,
            'status': 'error',
            'message': str(e)
        }

@api_router.post("/imap/manual-scan")
async def manual_scan(request: ManualScanRequest):
    """Manual scan of Gmail inbox"""
    global robust_imap
    
    if not robust_imap:
        raise HTTPException(status_code=400, detail="IMAP not configured. Please setup IMAP connection first.")
    
    try:
        logger.info(f"🔍 Starting manual scan for up to {request.max_emails} emails")
        
        # Get emails from Gmail
        emails = robust_imap.get_all_emails(request.max_emails)
        
        if not emails:
            return {
                'success': True,
                'message': 'No emails found or unable to access Gmail',
                'results': {
                    'total_scanned': 0,
                    'threats_found': 0,
                    'actions_taken': 0,
                    'findings': []
                }
            }
        
        logger.info(f"📧 Retrieved {len(emails)} emails for analysis")
        
        results = {
            'total_scanned': len(emails),
            'threats_found': 0,
            'actions_taken': 0,
            'findings': []
        }
        
        # Analyze each email
        for i, email_data in enumerate(emails):
            try:
                logger.info(f"🔍 Analyzing email {i+1}/{len(emails)}: {email_data.get('subject', 'No subject')[:50]}")
                
                # Convert to email content format
                email_content = f"""From: {email_data.get('from', '')}
To: {email_data.get('to', '')}
Subject: {email_data.get('subject', '')}
Date: {email_data.get('date', '')}

{email_data.get('body', '')}
"""
                
                # Analyze with enhanced detector
                analysis_result = await phishing_detector.analyze_email_comprehensive(
                    email_content, 
                    email_data,
                    f"manual_scan_{email_data.get('id', 'unknown')}.eml"
                )
                
                threat_level = analysis_result.get('threat_level', 'LOW')
                confidence_score = analysis_result.get('confidence_score', 0)
                
                logger.info(f"📊 Analysis result: {threat_level} threat (confidence: {confidence_score}%)")
                
                if threat_level in ['HIGH', 'CRITICAL', 'MEDIUM']:
                    results['threats_found'] += 1
                    
                    finding = {
                        'email_id': email_data.get('id'),
                        'from': email_data.get('from'),
                        'subject': email_data.get('subject'),
                        'threat_level': threat_level,
                        'confidence_score': confidence_score,
                        'detection_reasons': analysis_result.get('detection_reasons', []),
                        'actions_taken': False
                    }
                    
                    # Take action for HIGH/CRITICAL threats
                    if threat_level in ['HIGH', 'CRITICAL']:
                        logger.warning(f"🚨 {threat_level} threat detected! Taking action...")
                        
                        # Mark as spam
                        spam_success = robust_imap.mark_as_spam(email_data.get('id'))
                        if spam_success:
                            results['actions_taken'] += 1
                            finding['actions_taken'] = True
                            logger.info(f"✅ Email marked as spam: {email_data.get('subject')}")
                    
                    results['findings'].append(finding)
                    
                    # Store in database
                    email_analysis = EmailAnalysisResult(
                        filename=f"manual_scan_{email_data.get('id', 'unknown')}.eml",
                        analysis_result={
                            **analysis_result,
                            'email_data': email_data,
                            'scan_type': 'manual'
                        },
                        threat_level=threat_level
                    )
                    
                    await db.email_analyses.insert_one(email_analysis.dict())
                
            except Exception as e:
                logger.error(f"❌ Error analyzing email {i+1}: {str(e)}")
                continue
        
        logger.info(f"✅ Manual scan completed: {results['threats_found']} threats found, {results['actions_taken']} actions taken")
        
        return {
            'success': True,
            'message': f'Scanned {results["total_scanned"]} emails. Found {results["threats_found"]} threats, took {results["actions_taken"]} actions.',
            'results': results
        }
        
    except Exception as e:
        logger.error(f"❌ Manual scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Manual scan failed: {str(e)}")

@api_router.post("/imap/start-monitoring")
async def start_monitoring(request: MonitoringRequest, background_tasks: BackgroundTasks):
    """Start real-time monitoring"""
    global monitoring_active, monitoring_task
    
    if not robust_imap:
        raise HTTPException(status_code=400, detail="IMAP not configured. Please setup IMAP connection first.")
    
    if monitoring_active:
        return {
            'success': False,
            'message': 'Monitoring is already active'
        }
    
    try:
        logger.info(f"🚀 Starting real-time monitoring with alert email: {request.alert_email}")
        
        # Start monitoring task
        monitoring_task = asyncio.create_task(
            monitoring_loop(request.alert_email, request.check_interval)
        )
        
        monitoring_active = True
        
        return {
            'success': True,
            'message': f'Real-time monitoring started (checking every {request.check_interval} seconds)',
            'alert_email': request.alert_email,
            'monitoring_active': True
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to start monitoring: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start monitoring: {str(e)}")

@api_router.post("/imap/stop-monitoring")
async def stop_monitoring():
    """Stop real-time monitoring"""
    global monitoring_active, monitoring_task
    
    try:
        if not monitoring_active:
            return {
                'success': False,
                'message': 'Monitoring is not active'
            }
        
        monitoring_active = False
        
        if monitoring_task:
            monitoring_task.cancel()
            monitoring_task = None
        
        logger.info("⏹️ Real-time monitoring stopped")
        
        return {
            'success': True,
            'message': 'Real-time monitoring stopped'
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to stop monitoring: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to stop monitoring: {str(e)}")

async def monitoring_loop(alert_email: str, check_interval: int):
    """Real-time monitoring loop"""
    global monitoring_active
    
    logger.info(f"🔄 Starting monitoring loop (interval: {check_interval}s)")
    
    last_email_count = 0
    consecutive_errors = 0
    
    while monitoring_active:
        try:
            logger.info("🔍 Checking for new emails...")
            
            # Get recent emails (just a few to check for new ones)
            recent_emails = robust_imap.get_all_emails(5)
            
            if recent_emails:
                current_count = len(recent_emails)
                
                # Simple new email detection (in real implementation, you'd use message IDs)
                if current_count > last_email_count:
                    new_emails_count = current_count - last_email_count
                    logger.info(f"🆕 Detected {new_emails_count} potential new emails")
                    
                    # Process recent emails
                    for email_data in recent_emails[:new_emails_count]:
                        await process_monitored_email(email_data, alert_email)
                
                last_email_count = current_count
                consecutive_errors = 0
            
            # Wait for next check
            await asyncio.sleep(check_interval)
            
        except Exception as e:
            consecutive_errors += 1
            logger.error(f"❌ Monitoring error (attempt {consecutive_errors}): {str(e)}")
            
            if consecutive_errors > 5:
                logger.error("❌ Too many consecutive errors, stopping monitoring")
                monitoring_active = False
                break
            
            await asyncio.sleep(check_interval)
    
    logger.info("⏹️ Monitoring loop ended")

async def process_monitored_email(email_data: Dict[str, Any], alert_email: str):
    """Process a monitored email"""
    try:
        logger.info(f"🔍 Processing monitored email: {email_data.get('subject', 'No subject')}")
        
        # Convert to email content format
        email_content = f"""From: {email_data.get('from', '')}
To: {email_data.get('to', '')}
Subject: {email_data.get('subject', '')}
Date: {email_data.get('date', '')}

{email_data.get('body', '')}
"""
        
        # Analyze with enhanced detector
        analysis_result = await phishing_detector.analyze_email_comprehensive(
            email_content,
            email_data,
            f"monitored_{email_data.get('id', 'unknown')}.eml"
        )
        
        threat_level = analysis_result.get('threat_level', 'LOW')
        confidence_score = analysis_result.get('confidence_score', 0)
        
        logger.info(f"🎯 Monitored email analysis: {threat_level} threat (confidence: {confidence_score}%)")
        
        # Store analysis
        email_analysis = EmailAnalysisResult(
            filename=f"monitored_{email_data.get('id', 'unknown')}.eml",
            analysis_result={
                **analysis_result,
                'email_data': email_data,
                'scan_type': 'real_time_monitoring'
            },
            threat_level=threat_level
        )
        
        await db.email_analyses.insert_one(email_analysis.dict())
        
        # Take action for threats
        if threat_level in ['HIGH', 'CRITICAL']:
            logger.warning(f"🚨 {threat_level} threat detected in monitoring!")
            
            # Mark as spam
            spam_success = robust_imap.mark_as_spam(email_data.get('id'))
            logger.info(f"📬 Mark as spam: {'✅' if spam_success else '❌'}")
            
            # Send alert
            if alert_email and robust_imap:
                threat_details = {
                    **analysis_result,
                    **email_data,
                    'monitored_account': os.environ.get('GMAIL_EMAIL', 'Unknown')
                }
                
                alert_success = robust_imap.send_alert_email(threat_details, alert_email)
                logger.info(f"📧 Alert sent: {'✅' if alert_success else '❌'}")
        
        elif threat_level == 'MEDIUM':
            logger.info(f"⚠️ MEDIUM threat detected - sending alert only")
            
            if alert_email and robust_imap:
                threat_details = {
                    **analysis_result,
                    **email_data,
                    'monitored_account': os.environ.get('GMAIL_EMAIL', 'Unknown')
                }
                
                alert_success = robust_imap.send_alert_email(threat_details, alert_email)
                logger.info(f"📧 Alert sent: {'✅' if alert_success else '❌'}")
        
    except Exception as e:
        logger.error(f"❌ Error processing monitored email: {str(e)}")

@api_router.get("/reports/blocked-emails")
async def download_blocked_emails_report():
    """Generate and download report of all blocked emails"""
    try:
        # Get all analyses with High/Critical threat levels
        blocked_analyses = await db.email_analyses.find({
            "threat_level": {"$in": ["HIGH", "CRITICAL"]}
        }).sort("timestamp", -1).to_list(1000)
        
        # Generate CSV content
        csv_content = "Timestamp,Sender,Receiver,Subject,Threat Level,Confidence Score,Detection Reasons\n"
        
        for analysis in blocked_analyses:
            email_info = analysis.get('email_info', {})
            timestamp = analysis.get('timestamp', '')
            sender = email_info.get('from', 'N/A').replace(',', ';')
            receiver = email_info.get('to', 'N/A').replace(',', ';')
            subject = email_info.get('subject', 'N/A').replace(',', ';')
            threat_level = analysis.get('threat_level', 'UNKNOWN')
            confidence = analysis.get('confidence_score', 0)
            reasons = '; '.join(analysis.get('detection_reasons', [])).replace(',', ';')
            
            csv_content += f'"{timestamp}","{sender}","{receiver}","{subject}","{threat_level}","{confidence}","{reasons}"\n'
        
        return {
            'success': True,
            'filename': f'blocked_emails_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv',
            'content': csv_content,
            'total_blocked': len(blocked_analyses)
        }
        
    except Exception as e:
        logger.error(f"❌ Failed to generate report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@api_router.get("/analyses/{analysis_id}")
async def get_analysis_details(analysis_id: str):
    """Get detailed analysis of a specific email"""
    try:
        logger.info(f"🔍 Fetching analysis details for ID: {analysis_id}")
        
        # Find the analysis in the database
        analysis = await db.email_analyses.find_one({"id": analysis_id})
        
        if not analysis:
            raise HTTPException(status_code=404, detail="Analysis not found")
        
        return {
            'success': True,
            'analysis': EmailAnalysisResult(**analysis)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Failed to get analysis details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve analysis: {str(e)}")

@api_router.get("/analyses")
async def get_analyses():
    """Get all email analyses"""
    try:
        analyses = await db.email_analyses.find().sort("timestamp", -1).to_list(100)
        return [EmailAnalysisResult(**analysis) for analysis in analyses]
    except Exception as e:
        logger.error(f"❌ Failed to get analyses: {str(e)}")
        return []

@api_router.get("/monitoring/stats")
async def get_monitoring_stats():
    """Get monitoring statistics"""
    try:
        total_analyses = await db.email_analyses.count_documents({})
        critical_count = await db.email_analyses.count_documents({"threat_level": "CRITICAL"})
        high_count = await db.email_analyses.count_documents({"threat_level": "HIGH"})
        medium_count = await db.email_analyses.count_documents({"threat_level": "MEDIUM"})
        
        recent_analysis = await db.email_analyses.find_one({}, sort=[("timestamp", -1)])
        last_scan = None
        if recent_analysis:
            last_scan = recent_analysis.get('timestamp', datetime.utcnow()).strftime('%H:%M:%S')
        
        return {
            "totalProcessed": total_analyses,
            "threatsFound": critical_count + high_count,
            "criticalThreats": critical_count,
            "highThreats": high_count,
            "mediumThreats": medium_count,
            "lastScan": last_scan,
            "uptime": "Running",
            "alertsSent": critical_count + high_count,
            "detectionRate": round((critical_count + high_count + medium_count) / max(total_analyses, 1) * 100, 1),
            "monitoring_active": monitoring_active
        }
        
    except Exception as e:
        logger.error(f"❌ Error getting stats: {str(e)}")
        return {
            "totalProcessed": 0,
            "threatsFound": 0,
            "lastScan": None,
            "monitoring_active": False
        }

@api_router.get("/debug/analyze-sample")
async def debug_analyze_sample():
    """Debug endpoint with Office-365 phishing sample"""
    sample_phishing_email = """From: Helpdesk-Message <info@compresssave.org>
To: user@company.com
Subject: User Confidential 9122204
Date: Friday, September 13, 2024 8:53 AM

Office-365

Hello

Your password is due for update today.

You can change your password or keep password.

Keep Active Password

@consulting Service
"""
    
    try:
        sample_email_data = {
            'id': 'debug_sample',
            'from': 'Helpdesk-Message <info@compresssave.org>',
            'to': 'user@company.com',
            'subject': 'User Confidential 9122204',
            'date': 'Friday, September 13, 2024 8:53 AM',
            'body': 'Office-365\n\nHello\n\nYour password is due for update today.\n\nYou can change your password or keep password.\n\nKeep Active Password\n\n@consulting Service',
            'attachments': []
        }
        
        analysis_result = await phishing_detector.analyze_email_comprehensive(
            sample_phishing_email,
            sample_email_data,
            "debug_office365_sample.eml"
        )
        
        return {
            'success': True,
            'sample_email': 'Office-365 credential harvesting phishing attempt',
            'analysis': analysis_result,
            'detection_summary': {
                'threat_level': analysis_result.get('threat_level', 'UNKNOWN'),
                'confidence_score': analysis_result.get('confidence_score', 0),
                'detection_reasons': analysis_result.get('detection_reasons', []),
                'threat_indicators': len(analysis_result.get('threat_indicators', [])),
                'url_issues': len(analysis_result.get('url_analysis', [])),
                'brand_impersonation': len(analysis_result.get('brand_impersonation', [])),
                'should_be_blocked': analysis_result.get('threat_level') in ['HIGH', 'CRITICAL']
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Debug analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Debug analysis failed: {str(e)}")

@api_router.get("/enterprise/accounts")
async def get_enterprise_accounts():
    """Get enterprise accounts (placeholder for now)"""
    try:
        # For now, return empty accounts - this will be expanded later
        return {
            'success': True,
            'accounts': []
        }
    except Exception as e:
        logger.error(f"❌ Error getting enterprise accounts: {str(e)}")
        return {'success': False, 'accounts': []}

@api_router.get("/enterprise/stats")
async def get_enterprise_stats():
    """Get enterprise statistics (placeholder for now)"""
    try:
        # For now, return basic stats - this will be expanded later
        return {
            'success': True,
            'enterprise_stats': {
                'total_accounts': 0,
                'active_monitoring': 0,
                'total_threats_blocked': 0,
                'accounts_with_threats': 0
            }
        }
    except Exception as e:
        logger.error(f"❌ Error getting enterprise stats: {str(e)}")
        return {
            'success': False,
            'enterprise_stats': {
                'total_accounts': 0,
                'active_monitoring': 0,
                'total_threats_blocked': 0,
                'accounts_with_threats': 0
            }
        }

@api_router.get("/enterprise/blocked-emails")
async def get_blocked_emails():
    """Get blocked emails (placeholder for now)"""
    try:
        # For now, return empty blocked emails - this will be expanded later
        return {
            'success': True,
            'blocked_emails': []
        }
    except Exception as e:
        logger.error(f"❌ Error getting blocked emails: {str(e)}")
        return {'success': False, 'blocked_emails': []}

@api_router.post("/enterprise/accounts/add")
async def add_enterprise_account(account_data: dict):
    """Add enterprise account (placeholder for now)"""
    try:
        # For now, just return success - this will be expanded later
        return {
            'success': True,
            'message': 'Enterprise account management coming soon',
            'account': account_data
        }
    except Exception as e:
        logger.error(f"❌ Error adding enterprise account: {str(e)}")
        return {'success': False, 'message': 'Failed to add account'}

@api_router.post("/enterprise/accounts/{email}/start-monitoring")
async def start_enterprise_monitoring(email: str):
    """Start monitoring for enterprise account (placeholder for now)"""
    try:
        return {
            'success': True,
            'message': 'Enterprise monitoring coming soon',
            'email': email
        }
    except Exception as e:
        logger.error(f"❌ Error starting enterprise monitoring: {str(e)}")
        return {'success': False, 'message': 'Failed to start monitoring'}

@api_router.post("/enterprise/accounts/{email}/stop-monitoring")
async def stop_enterprise_monitoring(email: str):
    """Stop monitoring for enterprise account (placeholder for now)"""
    try:
        return {
            'success': True,
            'message': 'Enterprise monitoring stopped',
            'email': email
        }
    except Exception as e:
        logger.error(f"❌ Error stopping enterprise monitoring: {str(e)}")
        return {'success': False, 'message': 'Failed to stop monitoring'}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global robust_imap
    
    email = os.environ.get('GMAIL_EMAIL')
    password = os.environ.get('GMAIL_APP_PASSWORD')
    
    if email and password:
        robust_imap = RobustIMAPService(email, password)
        logger.info(f"✅ IMAP service initialized for {email}")
    else:
        logger.info("⚠️ IMAP credentials not found - setup required")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global monitoring_active, monitoring_task
    
    monitoring_active = False
    if monitoring_task:
        monitoring_task.cancel()
    
    if robust_imap:
        robust_imap.close_connection()
    
    client.close()
    logger.info("🛑 Application shutdown complete")