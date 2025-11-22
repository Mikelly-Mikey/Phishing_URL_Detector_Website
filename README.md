# SafeCheck - Advanced Phishing URL Checker

A comprehensive, multi-layered phishing detection system powered by AI/ML and real-time threat intelligence.

## Features

### 5-Layer Detection Pipeline

1. **Layer 1: URL Pattern Analysis**
   - Suspicious TLD detection (.tk, .ml, .ga, .cf, etc.)
   - IP address usage detection
   - Punycode/IDN homograph attack detection
   - Excessive URL length analysis
   - Suspicious keyword detection (login, verify, secure, etc.)
   - Subdomain analysis
   - URL obfuscation detection

2. **Layer 2: Threat Intelligence**
   - Known phishing pattern matching
   - Domain reputation analysis
   - Newly registered domain detection
   - Phishing database cross-referencing

3. **Layer 3: AI/ML Detection**
   - OpenAI GPT-5.1 powered risk analysis
   - URL structure pattern recognition
   - Brand impersonation detection
   - Multi-model ensemble scoring
   - Confidence-based risk assessment

4. **Layer 4: Dynamic Analysis**
   - HTML content analysis
   - JavaScript behavior detection
   - Redirect chain tracking
   - Credential harvesting detection
   - Login form detection

5. **Layer 5: Human Review Flagging**
   - Automatic categorization (benign/suspicious/malicious)
   - Risk score calculation (0-100%)
   - Threat type classification
   - Detailed summary generation

### Privacy & Compliance

- **GDPR/CCPA Compliant**
- Sensitive URL parameters automatically masked (tokens, passwords, sessions)
- No personal data collection or storage
- Anonymized logging
- Privacy status included in all reports

### Reporting

- **JSON API Response**: Structured data with all analysis results
- **PDF Reports**: Professional downloadable reports with:
  - Risk category and confidence score
  - Detected threat types
  - Suspicious pattern details
  - AI/ML analysis scores
  - Dynamic analysis findings
  - Privacy compliance statement

### Additional Features

- **Scan History**: View and access past URL scans
- **Real-time Analysis**: Instant threat detection
- **Modern UI**: Clean, professional interface with Space Grotesk font
- **Responsive Design**: Works on desktop and mobile devices

## Tech Stack

### Backend
- **FastAPI**: High-performance Python web framework
- **MongoDB**: Document database for scan storage
- **OpenAI GPT-5.1**: AI-powered threat analysis
- **emergentintegrations**: LLM integration library
- **ReportLab**: PDF generation
- **tldextract**: Domain parsing and analysis

### Frontend
- **React 19**: Modern UI library
- **Tailwind CSS**: Utility-first styling
- **Shadcn UI**: High-quality component library
- **Axios**: HTTP client
- **Sonner**: Toast notifications
- **Lucide React**: Icon library

## API Endpoints

### POST /api/check-url
Analyze a URL for phishing threats.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response:**
```json
{
  "id": "uuid",
  "url": "https://example.com",
  "masked_url": "https://example.com?token=***MASKED***",
  "risk_category": "benign|suspicious|malicious",
  "confidence_score": 85.5,
  "detected_threat_types": ["Phishing", "Credential Harvesting"],
  "suspicious_patterns": [...],
  "threat_intelligence_result": "...",
  "ai_scores": {
    "url_model_score": 75.0,
    "content_model_score": 68.0,
    "ensemble_score": 72.0,
    "confidence": 85.0
  },
  "dynamic_analysis": {
    "html_signals": [...],
    "javascript_behaviors": [...],
    "redirects_found": [...],
    "credential_harvesting_detected": true
  },
  "privacy_status": "Sensitive parameters masked; no user data collected.",
  "summary": "URL is highly likely to be malicious...",
  "timestamp": "2025-01-22T11:08:35Z"
}
```

### GET /api/scan-history
Retrieve recent scan history (last 50 scans).

### GET /api/scan/{scan_id}
Get detailed information about a specific scan.

### GET /api/scan/{scan_id}/pdf
Download PDF report for a specific scan.

## Environment Variables

### Backend (.env)
```
MONGO_URL=mongodb://localhost:27017
DB_NAME=phishing_checker_db
CORS_ORIGINS=*
EMERGENT_LLM_KEY=sk-emergent-xxxxx
```

### Frontend (.env)
```
REACT_APP_BACKEND_URL=https://your-domain.com
```

## Usage

### Check a URL
1. Enter any URL in the input field
2. Click "Check URL" button
3. Wait for multi-layer analysis (5-10 seconds)
4. Review detailed results across all detection layers
5. Download PDF report if needed

### View Scan History
1. Click "Scan History" tab
2. Browse past scans
3. Download PDF reports for any scan

## Risk Categories

- **Benign (Green)**: URL appears safe with no significant threats detected
- **Suspicious (Orange)**: URL shows warning signs, proceed with caution
- **Malicious (Red)**: URL is highly likely to be dangerous, DO NOT visit

## Threat Types Detected

- Phishing
- Credential Harvesting
- Typosquatting
- Homograph Attacks (IDN/Punycode)
- Malware Distribution
- URL Shortener Abuse
- Brand Impersonation
- Suspicious Domain

## Security Best Practices

1. Always validate URLs before visiting
2. Check for HTTPS encryption
3. Verify domain spelling carefully
4. Be cautious of newly registered domains
5. Watch for suspicious keywords in URLs
6. Never enter credentials on suspicious sites
7. Use this tool before clicking unknown links

## License

MIT License
