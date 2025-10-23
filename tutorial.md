# Getting Started with Red Team Agent 🚀

This tutorial will walk you through your first security assessment using the Red Team Agent, from installation to generating your first report.

## 📋 What You'll Learn

By the end of this tutorial, you'll know how to:
- Set up the Red Team Agent
- Create a security engagement
- Run reconnaissance and vulnerability scans
- Use AI-powered analysis
- Generate professional reports
- Integrate with n8n for automation

**Time Required:** 30-45 minutes

---

## Part 1: Installation (10 minutes)

### Option A: Automated Setup (Recommended)

```bash
# Download and run the setup script
chmod +x setup.sh
./setup.sh
```

The script will:
- Check all prerequisites
- Create a virtual environment
- Install dependencies
- Start Docker services
- Initialize the database

### Option B: Manual Setup

If you prefer to understand each step:

**1. Install Prerequisites:**

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y python3.11 python3-pip nmap docker.io docker-compose

# macOS
brew install python@3.11 nmap docker docker-compose
```

**2. Create Project and Virtual Environment:**

```bash
mkdir red-team-agent
cd red-team-agent

python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

**3. Install Python Dependencies:**

Create `requirements.txt` with the provided content, then:

```bash
pip install -r requirements.txt
```

**4. Start Docker Services:**

```bash
docker-compose up -d
```

**5. Configure Environment:**

```bash
cp .env.example .env
nano .env  # Edit and add your API keys
```

**6. Initialize Database:**

```bash
python -c "from app import create_app; from app.models import db; app = create_app(); app.app_context().push(); db.create_all()"
```

### Verify Installation

```bash
# Check if services are running
docker-compose ps

# You should see:
# - redteam_postgres (running)
# - redteam_redis (running)
# - redteam_n8n (running)
```

---

## Part 2: First Run (5 minutes)

### Start the Application

```bash
python run.py
```

You should see:
```
Red Team Agent - Starting
Server running on http://0.0.0.0:5000
```

### Test the API

Open a new terminal:

```bash
# Health check
curl http://localhost:5000/health

# Expected output:
# {"status":"healthy","message":"Red Team Agent is running"}
```

### Access the Web Interface

- **API**: http://localhost:5000/
- **n8n**: http://localhost:5678/ (username: admin, password: change-this-password)

---

## Part 3: Your First Assessment (15 minutes)

Let's perform a complete security assessment on a safe test target.

### Step 1: Create an Engagement

```bash
curl -X POST http://localhost:5000/api/engagements \
  -H "Content-Type: application/json" \
  -d 
  {
    "name": "My First Assessment",
    "client": "Learning Labs",
    "type": "internal",
    "scope": ["testphp.vulnweb.com"]
  }
```

**Response:**
```json
{
  "success": true,
  "message": "Engagement created successfully",
  "engagement": {
    "id": 1,
    "name": "My First Assessment",
    "status": "planning"
  }
}
```

**Save the engagement ID** (in this case: 1) - you'll need it!

### Step 2: Run Reconnaissance

```bash
curl -X POST http://localhost:5000/api/scan/recon \
  -H "Content-Type: application/json" \
  -d 
  {
    "target": "testphp.vulnweb.com",
    "engagement_id": 1,
    "ai_analysis": true
  }
```

**What's happening:**
- DNS enumeration
- Subdomain discovery
- Port scanning
- Technology detection
- AI analysis of attack surface

**This will take 2-3 minutes.** You'll get results like:

```json
{
  "success": true,
  "results": {
    "target_type": "domain",
    "ip_address": "44.228.249.3",
    "dns_info": {...},
    "port_scan": {
      "open_ports": [80, 443],
      "services": {...}
    },
    "technologies": [
      {"name": "Nginx", "category": "Web Server"}
    ],
    "ai_analysis": {
      "attack_surface": "...",
      "priority_targets": [...],
      "risk_level": "Medium"
    }
  }
}
```

### Step 3: Run Vulnerability Scan

```bash
curl -X POST http://localhost:5000/api/scan/vulnerabilities \
  -H "Content-Type: application/json" \
  -d 
  {
    "target": "http://testphp.vulnweb.com",
    "engagement_id": 1,
    "scan_type": "web",
    "ai_analysis": true
  }
```

**What's happening:**
- HTTP header analysis
- Security header checks
- Common vulnerability scanning
- XSS testing
- Information disclosure checks
- AI-powered risk assessment

**Results include:**

```json
{
  "findings": [
    {
      "title": "Missing Security Header: X-Frame-Options",
      "severity": "medium",
      "description": "Site may be vulnerable to clickjacking",
      "remediation": "Add X-Frame-Options: DENY"
    }
  ],
  "ai_analysis": {
    "executive_summary": "...",
    "critical_issues": [...],
    "remediation_plan": [...] 
  }
}
```

### Step 4: View Your Findings

```bash
curl http://localhost:5000/api/findings?engagement_id=1
```

**Or get detailed statistics:**

```bash
curl http://localhost:5000/api/findings/stats?engagement_id=1
```

### Step 5: Generate Reports

Generate all three report types:

```bash
# Executive Report (for management)
curl -X POST http://localhost:5000/api/reports/generate \
  -H "Content-Type: application/json" \
  -d 
  {
    "engagement_id": 1,
    "report_type": "executive"
  }

# Technical Report (for security team)
curl -X POST http://localhost:5000/api/reports/generate \
  -H "Content-Type: application/json" \
  -d 
  {
    "engagement_id": 1,
    "report_type": "technical"
  }

# Remediation Guide (for developers)
curl -X POST http://localhost:5000/api/reports/generate \
  -H "Content-Type: application/json" \
  -d 
  {
    "engagement_id": 1,
    "report_type": "remediation"
  }
```

**View your reports:**

```bash
ls -lh reports/
```

**Read a report:**

```bash
cat reports/technical_report_1_*.md
```

---

## Part 4: Using the Example Script (5 minutes)

We've created a Python script that automates the entire workflow:

```bash
python example_usage.py
```

This will:
1. Create an engagement
2. Run full assessment
3. Retrieve findings
4. Generate all reports
5. Show statistics

**Watch the output** to see each phase complete!

---

## Part 5: Understanding the Results (5 minutes)

### Reading the Reports

**Executive Report:**
- High-level overview for non-technical stakeholders
- Business risk assessment
- Key recommendations

**Technical Report:**
- Detailed vulnerability information
- Reproduction steps
- Technical remediation guidance
- Evidence and screenshots

**Remediation Guide:**
- Prioritized fix list
- Implementation steps
- Validation procedures

### Understanding Severity Levels

| Severity | Description | Timeline |
|----------|-------------|----------|
| **Critical** | Immediate exploitation possible, severe impact | Fix within 7 days |
| **High** | Significant security risk, likely exploitation | Fix within 30 days |
| **Medium** | Moderate risk, may require specific conditions | Fix within 90 days |
| **Low** | Minor security concerns | Fix within 6 months |
| **Info** | No immediate risk, informational | Address as convenient |

### AI Analysis Components

The AI provides:

1. **Attack Surface Analysis**
   - Entry points identified
   - Potential attack vectors
   - Risk assessment

2. **Priority Recommendations**
   - What to fix first
   - Why it matters
   - Business impact

3. **Attack Chains**
   - How vulnerabilities can be combined
   - Escalation paths
   - Potential damage

---

## Part 6: Next Steps

### Learn the API

Explore all available endpoints:

```bash
# Get all engagements
curl http://localhost:5000/api/engagements

# Get engagement details
curl http://localhost:5000/api/engagements/1

# Get system statistics
curl http://localhost:5000/api/stats

# Explain a vulnerability using AI
curl -X POST http://localhost:5000/api/ai/explain/vulnerability \
  -H "Content-Type: application/json" \
  -d '{"finding_id": 1}'
```

### Automate with n8n

1. Access n8n at http://localhost:5678
2. Create a new workflow
3. Add these nodes:
   - **Trigger**: Schedule (daily)
   - **HTTP Request**: Run scan
   - **Wait**: 5 minutes
   - **HTTP Request**: Generate report
   - **Send Email**: Notify team

### Scan Your Own Targets

**⚠️ IMPORTANT: Get written authorization first!**

```bash
# Add your target
curl -X POST http://localhost:5000/api/engagements/1/targets \
  -H "Content-Type: application/json" \
  -d 
  {
    "target": "your-authorized-target.com",
    "priority": 1
  }

# Validate target first
curl -X POST http://localhost:5000/api/validate-target \
  -H "Content-Type: application/json" \
  -d '{"target": "your-target.com"}'
```

### Customize Scans

Create custom scan profiles by modifying the modules in `app/modules/`:
- `recon.py` - Add new reconnaissance techniques
- `scanner.py` - Add custom vulnerability checks
- `ai_agent.py` - Customize AI prompts
- `reporter.py` - Customize report templates

---

## Part 7: Best Practices

### Security Testing Ethics

✅ **Always:**
- Get written authorization before testing
- Define scope clearly
- Test during approved windows
- Document everything
- Report findings responsibly

❌ **Never:**
- Test systems without permission
- Exceed authorized scope
- Cause service disruption
- Access/modify real user data
- Share findings publicly without consent

### Performance Tips

1. **For faster scans:**
   - Reduce port range in reconnaissance
   - Skip AI analysis during testing
   - Use parallel scanning (future feature)

2. **For comprehensive scans:**
   - Scan all 65535 ports
   - Enable all vulnerability checks
   - Use AI analysis for deep insights

3. **For resource management:**
   - Schedule scans during off-hours
   - Monitor system resources
   - Clean up old reports regularly

---

## Troubleshooting Common Issues

### "Connection refused" error

```bash
# Check if the app is running
ps aux | grep python

# Restart the application
python run.py
```

### "Database connection failed"

```bash
# Check PostgreSQL status
docker-compose ps

# Restart database
docker-compose restart postgres

# Wait 10 seconds, then try again
```

### "AI analysis not working"

```bash
# Check if API key is set
cat .env | grep ANTHROPIC_API_KEY

# Test API key
python -c "
from anthropic import Anthropic
client = Anthropic()
print('API key is valid!')
"
```

### "nmap not found"

```bash
# Install nmap
sudo apt-get install nmap  # Linux
brew install nmap           # macOS
```

---

## Quick Reference

### Essential Commands

```bash
# Start application
python run.py

# Run example
python example_usage.py

# Run tests
pytest test_basic.py -v

# View logs
tail -f logs/redteam.log

# Start/stop Docker services
docker-compose up -d
docker-compose down

# Database access
docker exec -it redteam_postgres psql -U redteam -d redteam_db
```

### Common API Calls

```bash
# Create engagement
curl -X POST http://localhost:5000/api/engagements -H "Content-Type: application/json" -d '{"name":"Test","client":"Me","type":"internal"}'

# Run full scan
curl -X POST http://localhost:5000/api/scan/full -H "Content-Type: application/json" -d '{"target":"example.com","engagement_id":1}'

# Generate report
curl -X POST http://localhost:5000/api/reports/generate -H "Content-Type: application/json" -d '{"engagement_id":1,"report_type":"technical"}'

# Get stats
curl http://localhost:5000/api/stats
```

---

## 🎉 Congratulations!

You've successfully:
- ✅ Set up the Red Team Agent
- ✅ Run your first security assessment
- ✅ Generated professional reports
- ✅ Used AI-powered analysis

### What's Next?

1. **Explore the codebase** - Understand how it works
2. **Customize modules** - Add your own checks
3. **Integrate with n8n** - Automate workflows
4. **Read the full documentation** - Master advanced features

### Need Help?

- Check the logs: `tail -f logs/redteam.log`
- Read README.md for detailed documentation
- Review test_basic.py for examples
- Examine example_usage.py for workflows

---

**Happy (ethical) hacking! 🛡️**
