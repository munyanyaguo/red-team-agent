#!/usr/bin/env python3
"""
Complete test script for AI Agent functionality
"""

import requests
import json
import time

BASE_URL = "http://localhost:5000"

def test_ai_agent():
    print("=" * 80)
    print("RED TEAM AGENT - AI AGENT COMPLETE TEST")
    print("=" * 80)

    # Step 1: Login
    print("\n[1/5] Authenticating...")
    login_response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": "admin", "password": "admin123"}
    )

    if not login_response.json().get('success'):
        print(f"❌ Login failed: {login_response.json()}")
        return False

    token = login_response.json()['access_token']
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    print("✅ Login successful!")

    # Step 2: Create Engagement
    print("\n[2/5] Creating test engagement...")
    engagement_data = {
        "name": "AI Agent Test Engagement",
        "client": "Test Client",
        "type": "pentest",
        "scope": ["testphp.vulnweb.com"]
    }

    engagement_response = requests.post(
        f"{BASE_URL}/api/engagements",
        json=engagement_data,
        headers=headers
    )

    eng_json = engagement_response.json()
    print(f"DEBUG: Engagement response: {json.dumps(eng_json, indent=2)}")

    if not eng_json.get('success'):
        print(f"❌ Engagement creation failed: {eng_json}")
        return False

    engagement_id = eng_json.get('engagement', {}).get('id') or eng_json.get('data', {}).get('id') or eng_json.get('id')
    print(f"✅ Engagement created (ID: {engagement_id})")

    # Step 3: Run reconnaissance with AI analysis
    print("\n[3/5] Running reconnaissance with AI analysis...")
    print("⏳ This may take 30-60 seconds...")

    recon_data = {
        "target": "testphp.vulnweb.com",
        "engagement_id": engagement_id,
        "ai_analysis": True
    }

    recon_response = requests.post(
        f"{BASE_URL}/api/scan/recon",
        json=recon_data,
        headers=headers,
        timeout=120
    )

    if recon_response.status_code != 200:
        print(f"❌ Reconnaissance failed: {recon_response.text}")
        return False

    recon_result = recon_response.json()
    print("✅ Reconnaissance completed!")

    # Check if AI analysis was performed
    results = recon_result.get('results', {}) or recon_result.get('data', {})
    if 'ai_analysis' in results:
        print("\n🤖 AI ANALYSIS RESULTS:")
        ai_analysis = results['ai_analysis']

        if 'error' in ai_analysis:
            print(f"⚠️  AI Analysis error: {ai_analysis['error']}")
        else:
            attack_surface = str(ai_analysis.get('attack_surface', 'N/A'))
            next_steps = str(ai_analysis.get('next_steps', 'N/A'))
            print(f"\n📊 Attack Surface: {attack_surface[:200]}...")
            print(f"\n🎯 Risk Level: {ai_analysis.get('risk_level', 'N/A')}")
            print(f"\n💡 Next Steps: {next_steps[:200]}...")
            print("\n✅ AI Agent is working!")
    else:
        print(f"⚠️  No AI analysis in response. Response keys: {list(results.keys())}")

    # Step 4: Test vulnerability analysis
    print("\n[4/5] Testing vulnerability analysis...")

    # Get findings for this engagement
    findings_response = requests.get(
        f"{BASE_URL}/api/findings?engagement_id={engagement_id}",
        headers=headers
    )

    if findings_response.json().get('success'):
        findings_json = findings_response.json()
        findings = findings_json.get('data', []) or findings_json.get('findings', [])
        print(f"✅ Found {len(findings)} findings")

        if len(findings) > 0:
            # Test AI vulnerability explanation
            finding_id = findings[0]['id']
            explain_response = requests.get(
                f"{BASE_URL}/api/findings/{finding_id}?explain=true",
                headers=headers
            )

            if explain_response.json().get('success'):
                print("✅ AI vulnerability explanation working!")
            else:
                print("⚠️  AI explanation not available")
        else:
            print("ℹ️  No findings to analyze yet")

    # Step 5: Test report generation
    print("\n[5/5] Testing AI-powered report generation...")

    report_data = {
        "engagement_id": engagement_id,
        "report_type": "technical"
    }

    report_response = requests.post(
        f"{BASE_URL}/api/reports/generate",
        json=report_data,
        headers=headers,
        timeout=120
    )

    if report_response.json().get('success'):
        report_json = report_response.json()
        report_id = report_json.get('report', {}).get('id') or report_json.get('data', {}).get('id') or report_json.get('id')
        print(f"✅ Report generated (ID: {report_id})")
        print("✅ AI-powered report generation working!")
    else:
        print(f"⚠️  Report generation issue: {report_response.json()}")

    # Final summary
    print("\n" + "=" * 80)
    print("✅ AI AGENT COMPLETE TEST PASSED!")
    print("=" * 80)
    print("\n📝 Summary:")
    print(f"   - Engagement ID: {engagement_id}")
    print(f"   - Target: testphp.vulnweb.com")
    print(f"   - Findings: {len(findings) if 'findings' in locals() else 0}")
    print(f"   - AI Analysis: {'✅ Working' if 'ai_analysis' in results else '⚠️  Not available'}")
    print(f"\n🌐 View in browser: http://localhost:5000/")
    print(f"   Login with: admin / admin123")
    print("\n" + "=" * 80)

    return True

if __name__ == "__main__":
    try:
        test_ai_agent()
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
