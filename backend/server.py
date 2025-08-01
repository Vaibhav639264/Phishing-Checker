from fastapi import FastAPI, APIRouter, File, UploadFile, HTTPException
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
import email
import re
import base64
import urllib.parse
import json
from emergentintegrations.llm.chat import LlmChat, UserMessage, FileContentWithMimeType

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

# Models
class EmailAnalysisResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    analysis_result: Dict[str, Any]
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class StatusCheck(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class StatusCheckCreate(BaseModel):
    client_name: str

# Phishing Detection Engine
class PhishingDetector:
    def __init__(self):
        self.gemini_api_key = os.environ.get('GEMINI_API_KEY')
        self.suspicious_patterns = [
            r'your\s+account\s+will\s+be\s+suspended',
            r'immediate\s+action\s+required',
            r'unusual\s+login\s+attempt',
            r'verify\s+your\s+account',
            r'click\s+here\s+to\s+confirm',
            r'suspended\s+due\s+to\s+security',
        ]
        
    def decode_url(self, url: str) -> str:
        """Decode URL encoded strings and base64"""
        try:
            # URL decode
            decoded = urllib.parse.unquote(url)
            
            # Check for base64 in query parameters
            base64_pattern = r'[A-Za-z0-9+/=]{20,}'
            matches = re.findall(base64_pattern, decoded)
            
            for match in matches:
                try:
                    b64_decoded = base64.b64decode(match).decode('utf-8')
                    if 'http' in b64_decoded:
                        return b64_decoded
                except:
                    continue
                    
            return decoded
        except Exception:
            return url

    def check_url_redirections(self, content: str) -> Dict[str, Any]:
        """Check for suspicious URL redirections"""
        findings = []
        
        # Find all URLs in content
        url_pattern = r'https?://[^\s<>"\'()]+|www\.[^\s<>"\'()]+'
        urls = re.findall(url_pattern, content, re.IGNORECASE)
        
        for url in urls:
            decoded_url = self.decode_url(url)
            
            # Check for redirection parameters
            redirect_params = ['url=', 'redirect=', 'r=', 'target=', 'goto=', 'next=']
            for param in redirect_params:
                if param in url.lower():
                    findings.append({
                        'type': 'suspicious_redirect',
                        'original_url': url,
                        'decoded_url': decoded_url,
                        'risk': 'HIGH'
                    })
                    
            # Check for domain spoofing
            common_domains = ['microsoft', 'google', 'amazon', 'paypal', 'apple']
            for domain in common_domains:
                if domain in url.lower() and not url.lower().startswith(f'https://{domain}.'):
                    # Check for character substitution
                    if any(char in url for char in ['0', '1', 'rn', 'ii']):
                        findings.append({
                            'type': 'domain_spoofing',
                            'url': url,
                            'suspected_target': domain,
                            'risk': 'HIGH'
                        })
        
        return {'url_analysis': findings}

    def check_sender_authenticity(self, email_msg) -> Dict[str, Any]:
        """Check sender authenticity"""
        findings = []
        
        # Get sender information
        from_header = email_msg.get('From', '')
        reply_to = email_msg.get('Reply-To', '')
        
        # Check for display name vs domain mismatch
        if '<' in from_header and '>' in from_header:
            display_name = from_header.split('<')[0].strip()
            email_addr = from_header.split('<')[1].split('>')[0].strip()
            
            # Check for brand impersonation
            brands = ['microsoft', 'google', 'amazon', 'paypal', 'apple', 'facebook', 'twitter']
            for brand in brands:
                if brand.lower() in display_name.lower():
                    if brand.lower() not in email_addr.lower():
                        findings.append({
                            'type': 'brand_impersonation',
                            'display_name': display_name,
                            'email': email_addr,
                            'suspected_brand': brand,
                            'risk': 'HIGH'
                        })

        # Check Reply-To manipulation  
        if reply_to and reply_to != from_header:
            findings.append({
                'type': 'reply_to_manipulation',
                'from': from_header,
                'reply_to': reply_to,
                'risk': 'MEDIUM'
            })
            
        return {'sender_analysis': findings}

    def check_social_engineering(self, content: str) -> Dict[str, Any]:
        """Check for social engineering tactics"""
        findings = []
        urgency_score = 0
        
        for pattern in self.suspicious_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                urgency_score += len(matches)
                findings.append({
                    'type': 'urgency_language',
                    'pattern': pattern,
                    'matches': matches,
                    'risk': 'MEDIUM'
                })
        
        # Check for generic greetings
        generic_greetings = ['dear user', 'dear customer', 'dear sir/madam']
        for greeting in generic_greetings:
            if greeting in content.lower():
                findings.append({
                    'type': 'generic_greeting',
                    'greeting': greeting,
                    'risk': 'LOW'
                })
        
        return {
            'social_engineering': findings,
            'urgency_score': urgency_score
        }

    def check_attachments(self, email_msg) -> Dict[str, Any]:
        """Check email attachments for suspicious content"""
        findings = []
        
        for part in email_msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                if filename:
                    # Check for suspicious extensions
                    suspicious_exts = ['.exe', '.bat', '.vbs', '.scr', '.com', '.pif', '.lnk']
                    for ext in suspicious_exts:
                        if filename.lower().endswith(ext):
                            findings.append({
                                'type': 'suspicious_attachment',
                                'filename': filename,
                                'risk': 'HIGH'
                            })
                    
                    # Check for double extensions
                    if filename.count('.') >= 2:
                        findings.append({
                            'type': 'double_extension',
                            'filename': filename,
                            'risk': 'HIGH'
                        })
        
        return {'attachment_analysis': findings}

    async def analyze_with_llm(self, email_content: str, detection_results: Dict) -> Dict[str, Any]:
        """Use Gemini LLM for advanced analysis"""
        try:
            # Create LLM chat instance
            chat = LlmChat(
                api_key=self.gemini_api_key,
                session_id=str(uuid.uuid4()),
                system_message="""You are an expert email security analyst specializing in phishing detection. 
                
Analyze the provided email content and detection results to determine if this email is legitimate or malicious.

Consider these factors:
1. URL redirections and domain spoofing
2. Sender authenticity and brand impersonation  
3. Social engineering tactics and urgency language
4. Suspicious attachments
5. Overall context and legitimacy

Provide a threat assessment with:
- Threat Level: LOW/MEDIUM/HIGH/CRITICAL
- Confidence Score: 0-100%
- Key Indicators: List main suspicious elements
- Explanation: Why this email is/isn't phishing
- Recommended Action: What user should do"""
            ).with_model("gemini", "gemini-2.0-flash")

            # Prepare analysis prompt
            analysis_prompt = f"""
EMAIL CONTENT:
{email_content[:3000]}...

DETECTION RESULTS:
{json.dumps(detection_results, indent=2)}

Please analyze this email and provide a comprehensive threat assessment.
"""

            user_message = UserMessage(text=analysis_prompt)
            response = await chat.send_message(user_message)
            
            return {
                'llm_analysis': response,
                'analysis_successful': True
            }
            
        except Exception as e:
            return {
                'llm_analysis': f"LLM analysis failed: {str(e)}",
                'analysis_successful': False
            }

    async def analyze_email(self, email_content: str, filename: str) -> Dict[str, Any]:
        """Complete email analysis"""
        try:
            # Parse email
            email_msg = email.message_from_string(email_content)
            
            # Get email body
            body = ""
            if email_msg.is_multipart():
                for part in email_msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    elif part.get_content_type() == "text/html":
                        body += part.get_payload(decode=True).decode('utf-8', errors='ignore')
            else:
                body = email_msg.get_payload(decode=True).decode('utf-8', errors='ignore')

            # Run all detection checks
            results = {
                'filename': filename,
                'subject': email_msg.get('Subject', ''),
                'from': email_msg.get('From', ''),
                'to': email_msg.get('To', ''),
                'date': email_msg.get('Date', ''),
            }
            
            # Combine all detection results
            results.update(self.check_url_redirections(email_content))
            results.update(self.check_sender_authenticity(email_msg))
            results.update(self.check_social_engineering(body))
            results.update(self.check_attachments(email_msg))
            
            # LLM Analysis
            llm_results = await self.analyze_with_llm(email_content, results)
            results.update(llm_results)
            
            # Calculate threat level
            threat_level = self.calculate_threat_level(results)
            results['threat_level'] = threat_level
            
            return results
            
        except Exception as e:
            return {
                'error': f"Analysis failed: {str(e)}",
                'threat_level': 'UNKNOWN'
            }

    def calculate_threat_level(self, results: Dict) -> str:
        """Calculate overall threat level"""
        risk_score = 0
        
        # URL analysis
        if 'url_analysis' in results:
            for finding in results['url_analysis']:
                if finding['risk'] == 'HIGH':
                    risk_score += 30
                elif finding['risk'] == 'MEDIUM':
                    risk_score += 15

        # Sender analysis  
        if 'sender_analysis' in results:
            for finding in results['sender_analysis']:
                if finding['risk'] == 'HIGH':
                    risk_score += 25
                elif finding['risk'] == 'MEDIUM':
                    risk_score += 10

        # Social engineering
        if 'urgency_score' in results:
            risk_score += results['urgency_score'] * 5

        # Attachments
        if 'attachment_analysis' in results:
            for finding in results['attachment_analysis']:
                if finding['risk'] == 'HIGH':
                    risk_score += 35

        # Determine threat level
        if risk_score >= 70:
            return 'CRITICAL'
        elif risk_score >= 45:
            return 'HIGH'
        elif risk_score >= 20:
            return 'MEDIUM'
        else:
            return 'LOW'

# Initialize detector
detector = PhishingDetector()

# Routes
@api_router.get("/")
async def root():
    return {"message": "Email Phishing Detection API"}

@api_router.post("/analyze-email")
async def analyze_email(file: UploadFile = File(...)):
    """Analyze uploaded email for phishing indicators"""
    try:
        # Read file content
        content = await file.read()
        email_content = content.decode('utf-8', errors='ignore')
        
        # Analyze email
        analysis_result = await detector.analyze_email(email_content, file.filename)
        
        # Save to database
        email_analysis = EmailAnalysisResult(
            filename=file.filename,
            analysis_result=analysis_result,
            threat_level=analysis_result.get('threat_level', 'UNKNOWN')
        )
        
        await db.email_analyses.insert_one(email_analysis.dict())
        
        return {
            'success': True,
            'analysis': analysis_result,
            'id': email_analysis.id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@api_router.get("/analyses")
async def get_analyses():
    """Get all email analyses"""
    analyses = await db.email_analyses.find().sort("timestamp", -1).to_list(100)
    return [EmailAnalysisResult(**analysis) for analysis in analyses]

@api_router.get("/analyses/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Get specific analysis by ID"""
    analysis = await db.email_analyses.find_one({"id": analysis_id})
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return EmailAnalysisResult(**analysis)

# Legacy routes
@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.dict()
    status_obj = StatusCheck(**status_dict)
    _ = await db.status_checks.insert_one(status_obj.dict())
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find().to_list(1000)
    return [StatusCheck(**status_check) for status_check in status_checks]

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()