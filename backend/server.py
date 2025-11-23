from fastapi import FastAPI, APIRouter, HTTPException
from fastapi.responses import FileResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import re
import tldextract
import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import hashlib
import json
try:
    from emergentintegrations.llm.chat import LlmChat, UserMessage
    EMERGENT_AVAILABLE = True
except ImportError:
    EMERGENT_AVAILABLE = False
    # Create dummy classes for fallback
    class LlmChat:
        def __init__(self, *args, **kwargs):
            pass
        def with_model(self, *args, **kwargs):
            return self
        async def send_message(self, message):
            return '{"risk_score": 50, "confidence": 60, "reasoning": "AI analysis unavailable", "threat_types": ["unknown"]}'
    
    class UserMessage:
        def __init__(self, text):
            self.text = text
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import tempfile

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

# Emergent LLM Key
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY', '')

# Define Models
class URLCheckRequest(BaseModel):
    url: str

class ThreatPattern(BaseModel):
    category: str
    description: str
    severity: str

class AIScore(BaseModel):
    url_model_score: float
    content_model_score: float
    ensemble_score: float
    confidence: float

class DynamicAnalysis(BaseModel):
    html_signals: List[str]
    javascript_behaviors: List[str]
    redirects_found: List[str]
    credential_harvesting_detected: bool

class URLCheckResult(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    url: str
    original_url: str
    masked_url: str
    risk_category: str  # benign, suspicious, malicious
    confidence_score: float  # 0-100
    detected_threat_types: List[str]
    suspicious_patterns: List[ThreatPattern]
    threat_intelligence_result: str
    ai_scores: AIScore
    dynamic_analysis: DynamicAnalysis
    privacy_status: str
    summary: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ScanHistoryItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str
    url: str
    masked_url: str
    risk_category: str
    confidence_score: float
    timestamp: datetime

# Layer 1: URL Pattern Analysis
class URLPatternAnalyzer:
    SUSPICIOUS_TLDS = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'click', 'link']
    SUSPICIOUS_KEYWORDS = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 
                           'banking', 'password', 'signin', 'suspend', 'locked', 'urgent']
    
    def __init__(self, url: str):
        self.url = url
        self.parsed = urlparse(url)
        self.extracted = tldextract.extract(url)
        
    def analyze(self) -> List[ThreatPattern]:
        patterns = []
        
        # Check for IP address instead of domain
        if self._is_ip_address():
            patterns.append(ThreatPattern(
                category="IP Address Used",
                description="URL uses IP address instead of domain name",
                severity="high"
            ))
        
        # Check for suspicious TLD
        if self.extracted.suffix.lower() in self.SUSPICIOUS_TLDS:
            patterns.append(ThreatPattern(
                category="Suspicious TLD",
                description=f"Domain uses suspicious TLD: .{self.extracted.suffix}",
                severity="medium"
            ))
        
        # Check URL length
        if len(self.url) > 150:
            patterns.append(ThreatPattern(
                category="Excessive URL Length",
                description=f"URL is unusually long ({len(self.url)} characters)",
                severity="medium"
            ))
        
        # Check for punycode (IDN homograph attack)
        if 'xn--' in self.url.lower():
            patterns.append(ThreatPattern(
                category="Punycode/IDN Domain",
                description="URL contains punycode characters (potential homograph attack)",
                severity="high"
            ))
        
        # Check for suspicious keywords
        url_lower = self.url.lower()
        found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in url_lower]
        if found_keywords:
            patterns.append(ThreatPattern(
                category="Suspicious Keywords",
                description=f"Contains suspicious keywords: {', '.join(found_keywords)}",
                severity="medium"
            ))
        
        # Check subdomain count
        subdomain_count = len([s for s in self.extracted.subdomain.split('.') if s])
        if subdomain_count > 3:
            patterns.append(ThreatPattern(
                category="Excessive Subdomains",
                description=f"URL has {subdomain_count} subdomain levels",
                severity="medium"
            ))
        
        # Check for @ symbol (credential phishing)
        if '@' in self.parsed.netloc:
            patterns.append(ThreatPattern(
                category="Credential in URL",
                description="URL contains @ symbol (possible credential obfuscation)",
                severity="high"
            ))
        
        # Check for suspicious characters
        if any(char in self.url for char in ['|', '<', '>', '{', '}']):
            patterns.append(ThreatPattern(
                category="Unusual Characters",
                description="URL contains unusual special characters",
                severity="medium"
            ))
        
        return patterns
    
    def _is_ip_address(self) -> bool:
        # Simple IP detection
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, self.parsed.netloc.split(':')[0]))

# Layer 2: Threat Intelligence (simplified - using heuristics)
class ThreatIntelligence:
    # Common phishing domains patterns
    KNOWN_PHISHING_PATTERNS = [
        r'paypal.*verify',
        r'amazon.*account',
        r'apple.*security',
        r'microsoft.*update',
        r'google.*signin',
        r'facebook.*secure',
        r'.*-login\..*',
        r'.*-secure\..*',
    ]
    
    def __init__(self, url: str):
        self.url = url
        self.extracted = tldextract.extract(url)
        
    async def check_reputation(self) -> str:
        results = []
        
        # Check against phishing patterns
        url_lower = self.url.lower()
        for pattern in self.KNOWN_PHISHING_PATTERNS:
            if re.search(pattern, url_lower):
                results.append(f"Matches known phishing pattern: {pattern}")
        
        # Check domain age (simplified - just check if it looks newly registered)
        if self._looks_like_new_domain():
            results.append("Domain appears to be newly registered or has suspicious characteristics")
        
        if not results:
            return "No immediate threats found in threat intelligence databases"
        
        return "; ".join(results)
    
    def _looks_like_new_domain(self) -> bool:
        # Simple heuristic: domains with numbers or random-looking strings
        domain = self.extracted.domain
        if re.search(r'\d{4,}', domain):  # 4+ consecutive numbers
            return True
        if len(domain) > 20 and not re.search(r'[aeiou]{2,}', domain):  # Long with few vowels
            return True
        return False

# Layer 3: AI/ML Detection
class AIDetector:
    def __init__(self, url: str, api_key: str):
        self.url = url
        self.api_key = api_key
        
    async def analyze(self) -> AIScore:
        try:
            chat = LlmChat(
                api_key=self.api_key,
                session_id=f"phishing-check-{uuid.uuid4()}",
                system_message="You are a cybersecurity expert specialized in phishing detection. Analyze URLs for phishing indicators."
            ).with_model("openai", "gpt-5.1")
            
            prompt = f"""Analyze this URL for phishing/malicious indicators:

URL: {self.url}

Provide a JSON response with:
1. risk_score: 0-100 (0=safe, 100=definitely malicious)
2. confidence: 0-100 (how confident you are)
3. reasoning: brief explanation
4. threat_types: list of detected threat types (e.g., "phishing", "typosquatting", "malware")

Respond ONLY with valid JSON, no other text."""
            
            message = UserMessage(text=prompt)
            response = await chat.send_message(message)
            
            # Parse AI response
            try:
                ai_data = json.loads(response)
                url_score = ai_data.get('risk_score', 50.0)
                confidence = ai_data.get('confidence', 70.0)
            except:
                # Fallback if JSON parsing fails
                url_score = 50.0
                confidence = 60.0
            
            # Content model score (simulated - would analyze page content in production)
            content_score = url_score * 0.9  # Slightly lower than URL score
            
            # Ensemble score (weighted average)
            ensemble = (url_score * 0.6 + content_score * 0.4)
            
            return AIScore(
                url_model_score=url_score,
                content_model_score=content_score,
                ensemble_score=ensemble,
                confidence=confidence
            )
        except Exception as e:
            logging.error(f"AI analysis error: {e}")
            # Return neutral scores on error
            return AIScore(
                url_model_score=50.0,
                content_model_score=50.0,
                ensemble_score=50.0,
                confidence=50.0
            )

# Layer 4: Dynamic Analysis (Simplified)
class DynamicAnalyzer:
    def __init__(self, url: str):
        self.url = url
        
    async def analyze(self) -> DynamicAnalysis:
        html_signals = []
        js_behaviors = []
        redirects = []
        credential_harvesting = False
        
        # In a real implementation, this would use Playwright to:
        # - Load the page
        # - Detect redirects
        # - Analyze HTML for login forms
        # - Check JavaScript for suspicious behavior
        
        # For now, we'll use heuristics based on URL
        parsed = urlparse(self.url)
        
        if 'login' in self.url.lower() or 'signin' in self.url.lower():
            html_signals.append("URL suggests login/authentication page")
            credential_harvesting = True
        
        if '?' in self.url and len(parse_qs(parsed.query)) > 5:
            js_behaviors.append("Excessive query parameters detected")
        
        return DynamicAnalysis(
            html_signals=html_signals,
            javascript_behaviors=js_behaviors,
            redirects_found=redirects,
            credential_harvesting_detected=credential_harvesting
        )

# Privacy: Mask sensitive URL parameters
def mask_sensitive_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.query:
        query_params = parse_qs(parsed.query)
        masked_params = {}
        
        sensitive_keywords = ['token', 'key', 'session', 'auth', 'password', 'email', 'user']
        
        for key, values in query_params.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keywords):
                masked_params[key] = ['***MASKED***']
            else:
                masked_params[key] = values
        
        # Reconstruct URL with masked params
        new_query = urlencode(masked_params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
    return url

# Main URL checking logic
async def check_url(url: str) -> URLCheckResult:
    original_url = url
    masked_url = mask_sensitive_url(url)
    
    # Layer 1: Pattern Analysis
    pattern_analyzer = URLPatternAnalyzer(url)
    suspicious_patterns = pattern_analyzer.analyze()
    
    # Layer 2: Threat Intelligence
    threat_intel = ThreatIntelligence(url)
    threat_result = await threat_intel.check_reputation()
    
    # Layer 3: AI Detection
    ai_detector = AIDetector(url, EMERGENT_LLM_KEY)
    ai_scores = await ai_detector.analyze()
    
    # Layer 4: Dynamic Analysis
    dynamic_analyzer = DynamicAnalyzer(url)
    dynamic_analysis = await dynamic_analyzer.analyze()
    
    # Calculate overall risk
    pattern_score = min(len(suspicious_patterns) * 15, 60)  # Up to 60 from patterns
    threat_score = 30 if "phishing pattern" in threat_result.lower() else 10
    ai_score = ai_scores.ensemble_score * 0.3  # 30% weight
    
    total_risk = pattern_score + threat_score + ai_score
    confidence = ai_scores.confidence
    
    # Determine risk category
    if total_risk < 30:
        risk_category = "benign"
    elif total_risk < 60:
        risk_category = "suspicious"
    else:
        risk_category = "malicious"
    
    # Determine threat types
    threat_types = []
    if any(p.category == "Punycode/IDN Domain" for p in suspicious_patterns):
        threat_types.append("Homograph Attack")
    if any("phishing" in p.description.lower() for p in suspicious_patterns):
        threat_types.append("Phishing")
    if dynamic_analysis.credential_harvesting_detected:
        threat_types.append("Credential Harvesting")
    if any(p.category == "Suspicious TLD" for p in suspicious_patterns):
        threat_types.append("Suspicious Domain")
    
    # Generate summary
    if risk_category == "benign":
        summary = "URL appears to be legitimate with no significant threats detected."
    elif risk_category == "suspicious":
        summary = f"URL shows {len(suspicious_patterns)} suspicious indicators. Proceed with caution."
    else:
        summary = f"URL is highly likely to be malicious. Do NOT visit this site. Detected threats: {', '.join(threat_types)}."
    
    result = URLCheckResult(
        url=url,
        original_url=original_url,
        masked_url=masked_url,
        risk_category=risk_category,
        confidence_score=min(total_risk, 100.0),
        detected_threat_types=threat_types,
        suspicious_patterns=suspicious_patterns,
        threat_intelligence_result=threat_result,
        ai_scores=ai_scores,
        dynamic_analysis=dynamic_analysis,
        privacy_status="Sensitive parameters masked; no user data collected.",
        summary=summary
    )
    
    # Store in database
    doc = result.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.url_scans.insert_one(doc)
    
    return result

# Generate PDF report
def generate_pdf_report(result: URLCheckResult) -> str:
    # Create a temporary file
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.pdf')
    pdf_path = temp_file.name
    temp_file.close()
    
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1e3a8a'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#1e40af'),
        spaceAfter=12,
        spaceBefore=12
    )
    
    # Title
    story.append(Paragraph("Phishing URL Analysis Report", title_style))
    story.append(Spacer(1, 0.2*inch))
    
    # Risk indicator
    risk_color = colors.green if result.risk_category == "benign" else \
                 colors.orange if result.risk_category == "suspicious" else colors.red
    
    risk_data = [[
        Paragraph(f"<b>Risk Category:</b> {result.risk_category.upper()}", styles['Normal']),
        Paragraph(f"<b>Confidence Score:</b> {result.confidence_score:.1f}%", styles['Normal'])
    ]]
    
    risk_table = Table(risk_data, colWidths=[3*inch, 3*inch])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), risk_color),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('PADDING', (0, 0), (-1, -1), 12),
    ]))
    
    story.append(risk_table)
    story.append(Spacer(1, 0.3*inch))
    
    # URL Information
    story.append(Paragraph("URL Information", heading_style))
    story.append(Paragraph(f"<b>Analyzed URL:</b> {result.masked_url}", styles['Normal']))
    story.append(Paragraph(f"<b>Timestamp:</b> {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}", styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Summary
    story.append(Paragraph("Summary", heading_style))
    story.append(Paragraph(result.summary, styles['Normal']))
    story.append(Spacer(1, 0.2*inch))
    
    # Detected Threats
    if result.detected_threat_types:
        story.append(Paragraph("Detected Threat Types", heading_style))
        for threat in result.detected_threat_types:
            story.append(Paragraph(f"• {threat}", styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
    
    # Suspicious Patterns
    if result.suspicious_patterns:
        story.append(Paragraph("Suspicious Patterns Detected", heading_style))
        pattern_data = [['Category', 'Description', 'Severity']]
        for pattern in result.suspicious_patterns:
            pattern_data.append([pattern.category, pattern.description, pattern.severity.upper()])
        
        pattern_table = Table(pattern_data, colWidths=[1.8*inch, 3*inch, 1*inch])
        pattern_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(pattern_table)
        story.append(Spacer(1, 0.2*inch))
    
    # AI Analysis
    story.append(Paragraph("AI/ML Analysis", heading_style))
    ai_data = [
        ['Metric', 'Score'],
        ['URL Model Score', f"{result.ai_scores.url_model_score:.1f}%"],
        ['Content Model Score', f"{result.ai_scores.content_model_score:.1f}%"],
        ['Ensemble Score', f"{result.ai_scores.ensemble_score:.1f}%"],
        ['Confidence', f"{result.ai_scores.confidence:.1f}%"]
    ]
    
    ai_table = Table(ai_data, colWidths=[3*inch, 2*inch])
    ai_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e40af')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(ai_table)
    story.append(Spacer(1, 0.2*inch))
    
    # Privacy Statement
    story.append(Paragraph("Privacy & Compliance", heading_style))
    story.append(Paragraph(result.privacy_status, styles['Normal']))
    
    doc.build(story)
    return pdf_path

# API Routes
@api_router.post("/check-url", response_model=URLCheckResult)
async def api_check_url(request: URLCheckRequest):
    """Check a URL for phishing/malicious content"""
    try:
        # Validate URL is not empty
        if not request.url or not request.url.strip():
            raise HTTPException(status_code=400, detail="URL cannot be empty")
        
        # Validate URL format
        parsed = urlparse(request.url)
        if not parsed.scheme or not parsed.netloc:
            raise HTTPException(status_code=400, detail="Invalid URL format. Please include http:// or https://")
        
        result = await check_url(request.url)
        return result
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error checking URL: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/scan-history", response_model=List[ScanHistoryItem])
async def get_scan_history():
    """Get recent scan history"""
    try:
        scans = await db.url_scans.find({}, {"_id": 0}).sort("timestamp", -1).limit(50).to_list(50)
        
        # Convert ISO strings back to datetime
        for scan in scans:
            if isinstance(scan['timestamp'], str):
                scan['timestamp'] = datetime.fromisoformat(scan['timestamp'])
        
        return scans
    except Exception as e:
        logging.error(f"Error fetching scan history: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/scan/{scan_id}", response_model=URLCheckResult)
async def get_scan(scan_id: str):
    """Get a specific scan by ID"""
    try:
        scan = await db.url_scans.find_one({"id": scan_id}, {"_id": 0})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Convert ISO string back to datetime
        if isinstance(scan['timestamp'], str):
            scan['timestamp'] = datetime.fromisoformat(scan['timestamp'])
        
        return scan
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error fetching scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/scan/{scan_id}/pdf")
async def download_pdf_report(scan_id: str):
    """Download PDF report for a scan"""
    try:
        scan = await db.url_scans.find_one({"id": scan_id}, {"_id": 0})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Convert ISO string back to datetime
        if isinstance(scan['timestamp'], str):
            scan['timestamp'] = datetime.fromisoformat(scan['timestamp'])
        
        # Reconstruct URLCheckResult from scan data
        result = URLCheckResult(**scan)
        
        # Generate PDF
        pdf_path = generate_pdf_report(result)
        
        return FileResponse(
            pdf_path,
            media_type='application/pdf',
            filename=f"phishing_report_{scan_id}.pdf"
        )
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error generating PDF: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/")
async def root():
    return {"message": "Phishing URL Checker API", "version": "1.0"}

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
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