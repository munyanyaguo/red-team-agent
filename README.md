# Red Team Agent 🛡️

A comprehensive AI-powered security testing platform built with Flask, featuring automated reconnaissance, vulnerability scanning, and intelligent reporting.

## ⚠️ LEGAL DISCLAIMER

**CRITICAL**: This tool is designed for authorized security testing ONLY. 

- ✅ Only use on systems you own or have explicit written permission to test
- ✅ Ensure you have proper authorization documentation
- ✅ Understand and comply with all applicable laws
- ❌ Unauthorized access to computer systems is illegal
- ❌ This tool does not provide legal protection

**The developers assume NO liability for misuse of this software.**

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites

- Python 3.12 or higher
- Docker & Docker Compose (for databases)
- nmap installed on your system
- **pipenv** for dependency management
- **Google Chrome/Chromium** and **ChromeDriver** (for Wappalyzer technology detection)
- Anthropic API key (for AI features)

### Step 1: Clone and Setup

```bash
# Create project directory
mkdir red-team-agent
cd red-team-agent

# Create virtual environment and install dependencies using Pipenv
# First, install pipenv if you don't have it:
pip install pipenv

# Then, install project dependencies
pipenv install --deploy --system

# Activate the virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Step 2: Configure Environment

```bash
# Copy .env file and edit with your settings
cp .env.example .env
nano .env  # or use your preferred editor
```

**Required environment variables:**
```bash
# Get your Anthropic API key from: https://console.anthropic.com/
ANTHROPIC_API_KEY=your-api-key-here

# Database (will use PostgreSQL from Docker)
DATABASE_URL=postgresql://redteam:securepassword@postgres:5432/redteam_db

# Redis (for caching, future features)
REDIS_URL=redis://localhost:6379/0
```

### Step 3: Start Database Services

```bash
# Start PostgreSQL, Redis, and n8n
docker-compose up -d

# Wait for services to be ready (about 30 seconds)
docker-compose ps
```

### Step 4: Run the Application

```bash
# Start the Flask application
python run.py
```

You should see:
```
Red Team Agent - Starting
Server running on http://0.0.0.0:5000
```

### Step 5: Test It Out!

Open a new terminal and try this:

```bash
# Create your first engagement
curl -X POST http://localhost:5000/api/engagements \
  -H "Content-Type: application/json" \
  -d 
'{ "name": "Test Assessment", "client": "Your Company", "type": "internal", "scope": ["testphp.vulnweb.com"] }'

# You'll get back an engagement ID, use it for scanning
# Replace {engagement_id} with the ID you received

# Run reconnaissance on a test target
curl -X POST http://localhost:5000/api/scan/full \
  -H "Content-Type: application/json" \
  -d 
'{ "target": "testphp.vulnweb.com", "engagement_id": 1 }'

# Generate a report
curl -X POST http://localhost:5000/api/reports/generate \
  -H "Content-Type: application/json" \
  -d 
'{ "engagement_id": 1, "report_type": "technical" }'
```

---

## 📖 Complete Setup Guide

### System Requirements

**Minimum:**
- 4GB RAM
- 2 CPU cores
- 10GB disk space

**Recommended:**
- 8GB RAM
- 4 CPU cores
- 50GB disk space (for logs and reports)

### Installing nmap

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**macOS:**
```bash
brew install nmap
```

**Windows:**
Download from https://nmap.org/download.html

### Installing Wappalyzer Dependencies

For `python-wappalyzer` to function, you need a browser (like Google Chrome or Chromium) and its corresponding WebDriver (like ChromeDriver) installed and accessible in your system\'s PATH.

**Ubuntu/Debian (for Chromium and ChromeDriver):**
```bash
sudo apt-get update
sudo apt-get install -y chromium-browser chromium-chromedriver
```

**macOS (for Chrome and ChromeDriver):**
```bash
brew install --cask google-chrome
brew install chromedriver
```

**Windows:**
1. Download Google Chrome: https://www.google.com/chrome/
2. Download ChromeDriver matching your Chrome version: https://chromedriver.chromium.org/downloads
3. Extract `chromedriver.exe` and place it in a directory included in your system\'s PATH.

### Database Setup

**Option 1: Docker (Recommended)**
```bash
docker-compose up -d postgres redis
```

**Option 2: Local PostgreSQL**
```bash
# Install PostgreSQL
sudo apt-get install postgresql

# Create database
sudo -u postgres createdb redteam_db
sudo -u postgres createuser redteam -P

# Update .env with your credentials
DATABASE_URL=postgresql://redteam:yourpassword@localhost:5432/redteam_db
```

### API Keys Setup

1. **Anthropic Claude API** (Required for AI features)
   - Sign up at https://console.anthropic.com/
   - Create an API key
   - Add to `.env`: `ANTHROPIC_API_KEY=your-key`

2. **OpenAI API** (Optional alternative)
   - Sign up at https://platform.openai.com/
   - Create an API key
   - Add to `.env`: `OPENAI_API_KEY=your-key`

---

## 🎯 Usage Guide

### API Endpoints

#### Engagements

**Create an Engagement:**
```bash
POST /api/engagements
{
  "name": "Q4 2024 Security Assessment",
  "client": "Acme Corp",
  "type": "pentest",
  "scope": ["example.com", "api.example.com"]
}
```

**List Engagements:**
```bash
GET /api/engagements
```

**Get Engagement Details:**
```bash
GET /api/engagements/{id}
```

#### Scanning

**Run Reconnaissance:**
```bash
POST /api/scan/recon
{
  "target": "example.com",
  "engagement_id": 1,
  "ai_analysis": true
}
```

**Run Vulnerability Scan:**
```bash
POST /api/scan/vulnerabilities
{
  "target": "https://example.com",
  "engagement_id": 1,
  "scan_type": "web"
}
```

**Run Full Assessment:**
```bash
POST /api/scan/full
{
  "target": "example.com",
  "engagement_id": 1
}
```

#### Reports

**Generate Report:**
```bash
POST /api/reports/generate
{
  "engagement_id": 1,
  "report_type": "technical"  # or "executive", "remediation"
}
```

**List Reports:**
```bash
GET /api/reports?engagement_id=1
```

**Get Report:**
```bash
GET /api/reports/{id}?content=true
```

#### Findings

**List Findings:**
```bash
GET /api/findings?engagement_id=1&severity=critical
```

**Get Finding Details:**
```bash
GET /api/findings/{id}?explain=true
```

**Update Finding:**
```bash
PUT /api/findings/{id}
{
  "status": "validated"
}
```

---

## 🤖 AI Features

### Reconnaissance Analysis
The AI analyzes reconnaissance data and provides:
- Attack surface summary
- Priority targets
- Technology stack assessment
- Risk level analysis
- Recommended next steps

### Vulnerability Analysis
The AI analyzes findings and provides:
- Executive summary
- Critical issues breakdown
- Attack chain possibilities
- Business impact assessment
- Prioritized remediation plan

### Report Generation
AI-powered reports include:
- Executive summaries for leadership
- Technical details for security teams
- Remediation guides for developers

---

## 🔧 Advanced Configuration

### Custom Scan Profiles

Create `config/scan_profiles.json`:
```json
{
  "quick": {
    "recon": true,
    "port_scan": "1-1000",
    "vuln_scan": "basic"
  },
  "full": {
    "recon": true,
    "port_scan": "1-65535",
    "vuln_scan": "comprehensive"
  }
}
```

### Rate Limiting

Edit `.env`:
```bash
MAX_SCAN_TIMEOUT=300
RATE_LIMIT_PER_HOUR=100
```

### Logging

Configure logging levels in `.env`:
```bash
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
LOG_FILE=logs/redteam.log
```

---

## 🔌 n8n Integration

### Access n8n Workflow Editor

1. Navigate to `http://localhost:5678`
2. Login with credentials from `docker-compose.yml`
3. Import workflow templates

### Example n8n Workflow

```
Webhook (Trigger)
  ↓
HTTP Request (Create Engagement)
  ↓
HTTP Request (Run Scan)
  ↓
Wait (5 minutes)
  ↓
HTTP Request (Generate Report)
  ↓
Send Email (Notify Team)
```

### Connecting n8n to Flask API

In n8n HTTP Request nodes:
- **URL**: `http://host.docker.internal:5000/api/...`
- **Method**: POST/GET as needed
- **Headers**: `Content-Type: application/json`

---

## 📊 Monitoring & Dashboards

### View Logs
```bash
tail -f logs/redteam.log
```

### Database Stats
```bash
# Connect to database
docker exec -it redteam_postgres psql -U redteam -d redteam_db

# Check stats
SELECT status, COUNT(*) FROM engagements GROUP BY status;
SELECT severity, COUNT(*) FROM findings GROUP BY severity;
```

### System Stats API
```bash
GET /api/stats
```

---

## 🧪 Testing

### Run Tests
```bash
# Install test dependencies
pipenv install pytest pytest-cov --dev --system

# Run tests
pytest

# With coverage
pytest --cov=app tests/
```

### Test Against Safe Targets

**Recommended test targets** (legal to test):
- `testphp.vulnweb.com` - Acunetix test site
- `scanme.nmap.org` - Nmap test server
- `example.com` - IANA reserved domain

---

## 🚨 Troubleshooting

### Common Issues

**Issue: "nmap: command not found"**
```bash
# Install nmap
sudo apt-get install nmap  # Linux
brew install nmap           # macOS
```

**Issue: "Database connection failed"**
```bash
# Check if PostgreSQL is running
docker-compose ps

# Restart database
docker-compose restart postgres
```

**Issue: "AI features not working"**
```bash
# Check API key
echo $ANTHROPIC_API_KEY

# Verify in logs
tail -f logs/redteam.log | grep -i "anthropic"
```

**Issue: "Port 5000 already in use"**
```bash
# Change port in .env
FLASK_PORT=8080

# Or kill existing process
lsof -ti:5000 | xargs kill -9
```

**Issue: "Permission denied" errors**
```bash
# Fix permissions
chmod -R 755 logs/ reports/ data/
```

**Issue: "Wappalyzer not detecting technologies"**
```bash
# Ensure Chrome/Chromium and ChromeDriver are installed and in PATH
# Check ChromeDriver version compatibility with your browser
```

---

## 📁 Project Structure

```
red-team-agent/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── config.py                # Configuration
│   ├── models.py                # Database models
│   ├── routes.py                # API endpoints
│   └── modules/
│       ├── __init__.py
│       ├── recon.py             # Reconnaissance engine
│       ├── scanner.py           # Vulnerability scanner
│       ├── ai_agent.py          # AI analysis
│       └── reporter.py          # Report generator
├── data/                         # Data storage
├── reports/                      # Generated reports
├── logs/                         # Application logs
├── tests/                        # Test files (create this)
├── .env                         # Environment variables
├── requirements.txt             # Python dependencies
├── docker-compose.yml           # Docker services setup
├── run.py                       # Application entry point
├── example_usage.py             # Complete usage example
├── test_basic.py                # Test suite
├── setup.sh                     # Automated setup script
├── README.md                    # This file
└── tutorial.md                  # Step-by-step tutorial
```

---

## 🔐 Security Best Practices

### For Development

1. **Never commit `.env` files**
   ```bash
   echo ".env" >> .gitignore
   ```

2. **Use strong database passwords**
   ```bash
   # Generate random password
   openssl rand -base64 32
   ```

3. **Rotate API keys regularly**
   - Set reminders to rotate keys every 90 days
   - Use separate keys for dev/staging/prod

### For Production

1. **Use HTTPS only**
   - Deploy behind nginx with SSL
   - Use Let\'s Encrypt for certificates

2. **Implement authentication**
   - Add JWT tokens or OAuth
   - Use Flask-Login for session management

3. **Enable audit logging**
   ```python
   # Add to config.py
   AUDIT_LOG = True
   AUDIT_LOG_FILE = 'logs/audit.log'
   ```

4. **Restrict network access**
   - Use VPN or IP whitelist
   - Deploy in isolated network segment

5. **Database security**
   - Use encrypted connections
   - Regular backups
   - Principle of least privilege

---

## 🎓 Learning Resources

### Understanding the Code

**Start here if you\'re new:**
1. Read `app/__init__.py` - See how Flask app is created
2. Read `app/models.py` - Understand database structure
3. Read `app/routes.py` - See API endpoints
4. Read `app/modules/recon.py` - Learn reconnaissance
5. Read `app/modules/scanner.py` - Learn vulnerability scanning

### Security Testing Concepts

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **Port Scanning**: https://nmap.org/book/man.html
- **Web Security**: https://portswigger.net/web-security
- **CVE Database**: https://cve.mitre.org/

### Flask & Python

- **Flask Documentation**: https://flask.palletsprojects.com/
- **SQLAlchemy ORM**: https://docs.sqlalchemy.org/
- **Python Security**: https://python.readthedocs.io/en/stable/library/security_warnings.html

---

## 🛠️ Extending the Agent

### Adding a New Scan Module

1. Create `app/modules/my_scanner.py`:
```python
import logging

logger = logging.getLogger(__name__)

class MyCustomScanner:
    def __init__(self):
        pass
    
    def scan(self, target: str):
        logger.info(f"Scanning {target}")
        # Your scanning logic here
        return {'findings': []}
```

2. Import in `app/routes.py`:
```python
from app.modules.my_scanner import MyCustomScanner

my_scanner = MyCustomScanner()
```

3. Add API endpoint:
```python
 @api_bp.route('/scan/custom', methods=['POST'])
def run_custom_scan():
    data = request.get_json()
    results = my_scanner.scan(data['target'])
    return jsonify(results), 200
```

### Adding New Report Templates

1. Modify `app/modules/reporter.py`
2. Add new template in `_generate_custom_report()` method
3. Update route in `app/routes.py`

### Integrating External Tools

Example: Adding Nikto scanner
```python
import subprocess

def run_nikto(target):
    cmd = ['nikto', '-h', target, '-Format', 'json']
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)
```

---

## 🔄 Update & Maintenance

### Updating Dependencies

```bash
# Check for outdated packages
pipenv update --outdated

# Update specific package
pipenv update package-name

# Update all packages
pipenv update
```

### Database Migrations

```bash
# Install Flask-Migrate
pipenv install flask-migrate --system

# Initialize migrations
flask db init

# Create migration
flask db migrate -m "Add new field"

# Apply migration
flask db upgrade
```

### Backup Procedures

**Database Backup:**
```bash
# Backup
docker exec redteam_postgres pg_dump -U redteam redteam_db > backup.sql

# Restore
docker exec -i redteam_postgres psql -U redteam redteam_db < backup.sql
```

**Full System Backup:**
```bash
# Create backup
tar -czf redteam-backup-$(date +%Y%m%d).tar.gz \
  data/ reports/ logs/ .env

# Restore
tar -xzf redteam-backup-20240101.tar.gz
```

---

## 🚀 Deployment

### Docker Deployment

1. Create `Dockerfile`:
```dockerfile
FROM python:3.12-slim # Updated Python version

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    chromium-browser \
    chromium-chromedriver \
    && rm -rf /var/lib/apt/lists/*

# Install pipenv
RUN pip install pipenv

# Copy Pipfile and Pipfile.lock and install dependencies
COPY Pipfile Pipfile.lock ./
RUN pipenv install --system --deploy --ignore-pipfile

# Copy application
COPY . . 

# Create directories
RUN mkdir -p logs reports data

EXPOSE 5000

CMD ["pipenv", "run", "gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "run:app"]
```

2. Update `docker-compose.yml`:
```yaml
app:
  build: .
  container_name: redteam_app
  ports:
    - "5000:5000"
  environment:
    - FLASK_ENV=development # Or production
    - SECRET_KEY=your-flask-secret-key # CHANGE THIS IN PRODUCTION
    - DATABASE_URL=postgresql://redteam:securepassword@postgres:5432/redteam_db # Use service name 'postgres'
    - REDIS_URL=redis://redis:6379/0 # Use service name 'redis'
    - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY} # Passed from host .env
    - OPENAI_API_KEY=${OPENAI_API_KEY} # Passed from host .env
    - MAX_SCAN_TIMEOUT=300
    - ENABLE_EXPLOITATION=false
    - LOG_LEVEL=INFO
  volumes:
    - .:/app # Mount current directory into container
    - ./reports:/app/reports # Ensure reports persist on host
    - ./logs:/app/logs # Ensure logs persist on host
    - ./data:/app/data # Ensure data persists on host
  depends_on:
    - postgres
    - redis
  restart: unless-stopped
```

3. Deploy:
```bash
docker-compose up --build -d
```

### Production Deployment (Linux Server)

1. Install system dependencies
sudo apt-get update
sudo apt-get install -y python3.12 python3.12-venv python3-pip nginx chromium-browser chromium-chromedriver

2. Clone repository
git clone https://github.com/yourusername/red-team-agent.git
cd red-team-agent

3. Create virtual environment and install pipenv
python3.12 -m venv venv
source venv/bin/activate
pip install pipenv

4. Install dependencies
pipenv install --deploy --system

5. Configure environment
cp .env.example .env
nano .env  # Edit with production settings

6. Setup systemd service
sudo nano /etc/systemd/system/redteam.service

**Service file content:**
```ini
[Unit]
Description=Red Team Agent
After=network.target postgresql.service

[Service]
User=redteam
WorkingDirectory=/home/redteam/red-team-agent
Environment="PATH=/home/redteam/red-team-agent/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/home/redteam/red-team-agent/venv/bin/pipenv run gunicorn -w 4 -b 0.0.0.0:5000 run:app

[Install]
WantedBy=multi-user.target
```

7. Start service
sudo systemctl daemon-reload
sudo systemctl enable redteam
sudo systemctl start redteam

8. Configure nginx
sudo nano /etc/nginx/sites-available/redteam

**Nginx configuration:**
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

9. Enable site and reload nginx
sudo ln -s /etc/nginx/sites-available/redteam /etc/nginx/sites-enabled/
sudo systemctl reload nginx

---

## 📞 Support & Community

### Getting Help

1. **Check the logs first:**
   ```bash
   tail -f logs/redteam.log
   ```

2. **Enable debug mode:**
   ```bash
   FLASK_ENV=development python run.py
   ```

3. **Common solutions:**
   - Clear database: `docker-compose down -v && docker-compose up -d`
   - Reinstall dependencies: `pipenv install --deploy --system`
   - Check permissions: `ls -la logs/ reports/ data/`

### Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Reporting Issues

When reporting issues, include:
- Python version (`python --version`)
- Operating system
- Error messages from logs
- Steps to reproduce

---

## 📜 License

This project is for educational and authorized security testing purposes only.

**MIT License** - See LICENSE file for details.

---

## 🎯 Roadmap

### Phase 1 (Current)
- ✅ Basic reconnaissance
- ✅ Vulnerability scanning
- ✅ AI analysis
- ✅ Report generation

### Phase 2 (Next)
- [ ] Web UI dashboard
- [ ] Scheduled scans
- [ ] Email notifications
- [ ] Multi-user support

### Phase 3 (Future)
- [ ] Exploitation module
- [ ] Cloud scanner (AWS/Azure/GCP)
- [ ] API security testing
- [ ] Mobile app testing
- [ ] Integration with bug bounty platforms

---

## 🙏 Acknowledgments

Built with:
- **Flask** - Web framework
- **Claude AI** - Intelligent analysis
- **Nmap** - Network scanning
- **n8n** - Workflow automation
- **PostgreSQL** - Database
- **Wappalyzer** - Technology detection

Inspired by security tools:
- Metasploit
- Burp Suite
- OWASP ZAP
- Nuclei

---

## 📝 Changelog

### v1.0.0 (Current)
- Initial release
- Basic reconnaissance engine
- Vulnerability scanner
- AI-powered analysis
- Report generation
- REST API

---

**Remember**: With great power comes great responsibility. Always test ethically and legally!