# Red Team Agent - API Documentation

## Overview

The Red Team Agent provides a comprehensive REST API for authorized security testing operations.

**Base URL**: `http://localhost:5000/api`

**Authentication**: JWT Bearer tokens or API Keys

---

## Authentication

### POST /api/auth/login
Login and obtain JWT access token.

**Request:**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Response:**
```json
{
  "success": true,
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

---

## Engagements

### POST /api/engagements
Create a new security engagement.

**Headers:**
- `Authorization: Bearer {token}`

**Request:**
```json
{
  "name": "Q4 Security Assessment",
  "client": "Acme Corp",
  "type": "pentest",
  "scope": ["example.com", "api.example.com"]
}
```

**Response:**
```json
{
  "success": true,
  "engagement": {
    "id": 1,
    "name": "Q4 Security Assessment",
    "status": "planning"
  }
}
```

---

## Scanning

### POST /api/scan/recon
Run reconnaissance on a target.

**Rate Limit**: 50 per hour

**Headers:**
- `Authorization: Bearer {token}`

**Request:**
```json
{
  "target": "https://example.com",
  "engagement_id": 1,
  "ai_analysis": true
}
```

**Response:**
```json
{
  "success": true,
  "results": {
    "target": "example.com",
    "target_type": "domain",
    "ports": {...},
    "technologies": {...},
    "ai_analysis": {
      "attack_surface": "...",
      "risk_level": "Medium",
      "next_steps": [...]
    }
  }
}
```

### POST /api/scan/full
Run complete assessment (recon + vulnerability scan).

**Rate Limit**: 20 per hour

**Request:**
```json
{
  "target": "https://example.com",
  "engagement_id": 1
}
```

---

## Findings

### GET /api/findings
List all findings (optionally filtered).

**Query Parameters:**
- `engagement_id` (optional): Filter by engagement
- `severity` (optional): Filter by severity (critical, high, medium, low)

**Response:**
```json
{
  "success": true,
  "count": 5,
  "findings": [
    {
      "id": 1,
      "title": "SQL Injection",
      "severity": "critical",
      "status": "new",
      "discovered_at": "2025-12-02T10:00:00Z"
    }
  ]
}
```

### GET /api/findings/{id}?explain=true
Get detailed finding with AI explanation.

**Response:**
```json
{
  "success": true,
  "finding": {
    "id": 1,
    "title": "SQL Injection",
    "description": "...",
    "severity": "critical",
    "detailed_explanation": "AI-generated explanation...",
    "remediation": "..."
  }
}
```

---

## Advanced Features (Admin Only)

### POST /api/rootkit/info
Get rootkit module capabilities.

**Requires**: Admin role

**Rate Limit**: 10 per hour

**Response:**
```json
{
  "success": true,
  "info": {
    "platform": "Linux",
    "has_admin_privileges": false,
    "capabilities": {
      "process_hiding": true,
      "file_hiding": true
    },
    "warning": "AUTHORIZED USE ONLY"
  }
}
```

### POST /api/rootkit/hide-process
Hide process (requires active engagement).

**Requires**:
- Admin role
- Active engagement
- Administrative system privileges

**Rate Limit**: 5 per hour

**Request:**
```json
{
  "process_name": "test_process",
  "engagement_id": 1
}
```

---

## Error Responses

### 400 Bad Request
```json
{
  "success": false,
  "error": "Invalid input: target is required"
}
```

### 401 Unauthorized
```json
{
  "success": false,
  "error": "Authorization header required"
}
```

### 403 Forbidden
```json
{
  "success": false,
  "error": "Admin role required"
}
```

### 429 Too Many Requests
```json
{
  "success": false,
  "error": "Rate limit exceeded"
}
```

### 500 Internal Server Error
```json
{
  "success": false,
  "error": "Internal server error message"
}
```

---

## Rate Limits

| Endpoint Category | Limit |
|------------------|-------|
| Default | 200/day, 50/hour |
| Scanning | 50/hour |
| Full Assessment | 20/hour |
| Rootkit Operations | 5/hour |
| Report Generation | 10/hour |

---

## Security Features

### Input Validation
All endpoints validate:
- ✅ URL formats
- ✅ No localhost/internal IPs
- ✅ No SQL injection in parameters
- ✅ No shell metacharacters
- ✅ Payload size limits (max 10KB)

### Authorization
- ✅ JWT token validation
- ✅ Role-based access control (Admin, Analyst, Viewer)
- ✅ Engagement context validation
- ✅ Explicit authorization for dangerous operations

### Rate Limiting
- ✅ Per-IP rate limiting
- ✅ Endpoint-specific limits
- ✅ Automatic throttling

---

## Client Examples

### Python
```python
import requests

# Login
response = requests.post('http://localhost:5000/api/auth/login', json={
    'username': 'admin',
    'password': 'admin123'
})
token = response.json()['access_token']

# Create engagement
headers = {'Authorization': f'Bearer {token}'}
engagement = requests.post('http://localhost:5000/api/engagements',
    headers=headers,
    json={
        'name': 'Test Engagement',
        'client': 'Acme Corp',
        'type': 'pentest',
        'scope': ['testphp.vulnweb.com']
    }
)
```

### cURL
```bash
# Login
TOKEN=$(curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' \
  | jq -r '.access_token')

# Run scan
curl -X POST http://localhost:5000/api/scan/recon \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"testphp.vulnweb.com","engagement_id":1,"ai_analysis":true}'
```

---

## Complete Endpoint List

### Authentication
- `POST /api/auth/login` - Login
- `POST /api/auth/register` - Register new user
- `POST /api/auth/refresh` - Refresh token
- `POST /api/auth/logout` - Logout

### Engagements
- `GET /api/engagements` - List engagements
- `POST /api/engagements` - Create engagement
- `GET /api/engagements/{id}` - Get engagement
- `PUT /api/engagements/{id}` - Update engagement
- `POST /api/engagements/{id}/targets` - Add target

### Scanning
- `POST /api/scan/recon` - Reconnaissance
- `POST /api/scan/vulnerabilities` - Vulnerability scan
- `POST /api/scan/full` - Full assessment
- `POST /api/scans/schedule` - Schedule scan

### Findings
- `GET /api/findings` - List findings
- `GET /api/findings/{id}` - Get finding
- `PUT /api/findings/{id}` - Update finding status

### Reports
- `POST /api/reports/generate` - Generate report
- `GET /api/reports` - List reports
- `GET /api/reports/{id}` - Get report

### Admin (Admin role only)
- `GET /api/admin/users` - List users
- `POST /api/admin/users` - Create user
- `DELETE /api/admin/users/{id}` - Delete user
- `GET /api/admin/api-keys` - List API keys
- `POST /api/admin/api-keys` - Create API key
- `DELETE /api/admin/api-keys/{id}` - Revoke API key
- `GET /api/admin/statistics` - System statistics

### Rootkit (Admin only, requires engagement)
- `GET /api/rootkit/info` - Module info
- `POST /api/rootkit/hide-process` - Hide process
- `POST /api/rootkit/hide-file` - Hide file
- `POST /api/rootkit/hide-network` - Hide connection
- `GET /api/rootkit/status` - Status

---

## Support

For issues or questions:
- Check logs: `tail -f logs/redteam.log`
- Health check: `GET /health`
- Documentation: This file

**Legal Notice**: This API is for authorized security testing only. Unauthorized use is illegal.
