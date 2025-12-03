# Red Team Agent - Quick Start Guide

## ✅ System is Ready!

Your Red Team Agent is fully configured and ready to use. All AI features are working!

## 🚀 Start the Server

```bash
./START.sh
```

Or manually:
```bash
source venv/bin/activate
python run.py
```

## 🔑 Login Credentials

- **URL**: http://localhost:5000
- **Username**: `admin`
- **Password**: `admin123`

## 🧪 Test It Now!

The server is currently running. You can test it immediately:

### 1. Via Web Browser
Open http://localhost:5000 and login with the credentials above.

### 2. Via Command Line

```bash
# Login and get token
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Save the access_token from response, then:
export TOKEN="your-token-here"

# Create an engagement
curl -X POST http://localhost:5000/api/engagements \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "Test Engagement",
    "client": "Your Company",
    "type": "pentest",
    "scope": ["testphp.vulnweb.com"]
  }'

# Run reconnaissance with AI analysis
curl -X POST http://localhost:5000/api/scan/recon \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "target": "testphp.vulnweb.com",
    "engagement_id": 1,
    "ai_analysis": true
  }'
```

### 3. Run Complete Test Suite

```bash
source venv/bin/activate
python test_ai_agent_complete.py
```

## ✅ What's Working

- ✅ Web Server (Flask)
- ✅ Database (PostgreSQL via Nhost)
- ✅ Authentication & Authorization (JWT)
- ✅ AI Agent (Gemini 2.5 Flash)
- ✅ Reconnaissance Engine
- ✅ Vulnerability Scanner
- ✅ Report Generation
- ✅ Scheduled Scans
- ✅ All API Endpoints

## 🤖 AI Features

The AI agent provides:
- **Reconnaissance Analysis**: Analyzes scan results and identifies attack surface
- **Vulnerability Analysis**: Explains vulnerabilities and provides remediation
- **Report Generation**: Creates executive and technical reports
- **Attack Strategy**: Suggests safe testing methodologies

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Login and get JWT token |
| `/api/auth/register` | POST | Register new user |
| `/api/engagements` | GET/POST | List/Create engagements |
| `/api/scan/recon` | POST | Run reconnaissance |
| `/api/scan/vulnerabilities` | POST | Run vulnerability scan |
| `/api/reports/generate` | POST | Generate report |
| `/api/findings` | GET | List findings |

## 🔒 Security Notes

⚠️ **CRITICAL**: This tool is for authorized security testing ONLY.

- Only test systems you own or have explicit permission to test
- Always comply with applicable laws and regulations
- Never use on production systems without authorization
- Default password should be changed immediately

## 🛠️ System Configuration

- **Python**: 3.12.3
- **Database**: PostgreSQL (Nhost)
- **AI Provider**: Google Gemini 2.5 Flash
- **Web Framework**: Flask
- **Auth**: JWT with role-based access control

## 📊 Current Status

Server is running on:
- http://127.0.0.1:5000
- http://192.168.100.32:5000

All tests passed successfully!

## 🆘 Need Help?

Check the full README.md for detailed documentation, or run:

```bash
python test_ai_agent_complete.py
```

This will verify all features are working correctly.

---

**Ready to test!** 🎯
