from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import os
import email
import uuid
import re
from datetime import datetime
import uvicorn
import logging

# Configure logging for Google Cloud
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Email Phishing Detector",
    description="Advanced AI-powered email phishing detection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (in production, use Cloud Firestore)
analyses = []

@app.get("/")
async def root():
    """Root endpoint with welcome message"""
    return {
        "message": "🛡️ Email Phishing Detector API",
        "status": "active",
        "version": "1.0.0",
        "endpoints": {
            "analyze": "/api/analyze-email",
            "analyses": "/api/analyses",
            "health": "/health",
            "docs": "/docs"
        },
        "deployment": "Google Cloud Platform"
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for load balancer"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "total_analyses": len(analyses)
    }

@app.post("/api/analyze-email")
async def analyze_email(file: UploadFile = File(...)):
    """Analyze uploaded email for phishing indicators"""
    try:
        logger.info(f"Analyzing email: {file.filename}")
        
        # Read and parse email
        content = await file.read()
        email_content = content.decode('utf-8', errors='ignore')
        email_msg = email.message_from_string(email_content)
        
        # Extract email data
        subject = email_msg.get('Subject', '')
        from_addr = email_msg.get('From', '')
        to_addr = email_msg.get('To', '')
        body = email_msg.get_payload() if not email_msg.is_multipart() else ''
        
        if isinstance(body, bytes):
            body = body.decode('utf-8', errors='ignore')
        
        # Advanced phishing detection
        threat_score = 0
        reasons = []
        
        # Critical phishing patterns
        critical_patterns = [
            (r'urgent.*action.*required', 30, 'Urgent action required'),
            (r'verify.*account.*immediately', 35, 'Account verification demand'),
            (r'suspend.*account.*24.*hour', 40, 'Account suspension threat'),
            (r'click.*here.*(now|immediately)', 25, 'Suspicious urgency'),
            (r'office.*365.*expire', 45, 'Office 365 phishing'),
            (r'microsoft.*account.*suspend', 40, 'Microsoft impersonation'),
            (r'paypal.*payment.*failed', 35, 'PayPal scam'),
            (r'amazon.*order.*problem', 30, 'Amazon scam'),
            (r'security.*alert.*verify', 35, 'Security alert scam'),
            (r'unusual.*activity.*detected', 30, 'Activity alert scam')
        ]
        
        full_text = f"{subject} {body}".lower()
        
        # Check critical patterns
        for pattern, score, description in critical_patterns:
            if re.search(pattern, full_text):
                threat_score += score
                reasons.append(f"Critical: {description}")
        
        # URL analysis
        urls = re.findall(r'https?://[^\s<>"\'()]+', body)
        suspicious_url_keywords = ['verify', 'secure', 'login', 'account', 'update']
        
        for url in urls:
            for keyword in suspicious_url_keywords:
                if keyword in url.lower():
                    threat_score += 20
                    reasons.append(f"Suspicious URL: {url[:50]}...")
                    break
        
        # Domain analysis
        if from_addr and '@' in from_addr:
            domain = from_addr.split('@')[-1].split('>')[0].strip()
            suspicious_domains = ['bit.ly', 'tinyurl', 'short.link']
            
            if any(sus_domain in domain for sus_domain in suspicious_domains):
                threat_score += 40
                reasons.append(f"Suspicious sender domain: {domain}")
        
        # Determine threat level
        if threat_score >= 80:
            threat_level = "CRITICAL"
            recommendation = "BLOCK IMMEDIATELY"
        elif threat_score >= 50:
            threat_level = "HIGH"
            recommendation = "BLOCK EMAIL"
        elif threat_score >= 25:
            threat_level = "MEDIUM"
            recommendation = "REVIEW CAREFULLY"
        else:
            threat_level = "LOW"
            recommendation = "LIKELY SAFE"
        
        # Create analysis result
        analysis = {
            'id': str(uuid.uuid4()),
            'filename': file.filename,
            'threat_level': threat_level,
            'confidence_score': min(threat_score, 100),
            'recommendation': recommendation,
            'detection_reasons': reasons,
            'email_info': {
                'subject': subject,
                'from': from_addr,
                'to': to_addr,
                'date': email_msg.get('Date', ''),
                'body_length': len(body),
                'urls_found': len(urls)
            },
            'timestamp': datetime.utcnow().isoformat(),
            'analyzed_by': 'Google Cloud AI'
        }
        
        # Store analysis
        analyses.append(analysis)
        
        # Keep only last 100 analyses
        if len(analyses) > 100:
            analyses.pop(0)
        
        logger.info(f"Analysis complete: {threat_level} threat detected")
        return analysis
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/analyses")
async def get_analyses():
    """Get recent email analyses"""
    return analyses[-20:]  # Return last 20 analyses

@app.get("/api/analyses/{analysis_id}")
async def get_analysis(analysis_id: str):
    """Get specific analysis by ID"""
    for analysis in analyses:
        if analysis['id'] == analysis_id:
            return analysis
    raise HTTPException(status_code=404, detail="Analysis not found")

@app.get("/api/stats")
async def get_stats():
    """Get analysis statistics"""
    if not analyses:
        return {"total": 0, "threat_levels": {}}
    
    threat_counts = {}
    for analysis in analyses:
        level = analysis['threat_level']
        threat_counts[level] = threat_counts.get(level, 0) + 1
    
    return {
        "total_analyses": len(analyses),
        "threat_levels": threat_counts,
        "last_analysis": analyses[-1]['timestamp'] if analyses else None
    }

# For Google App Engine
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
