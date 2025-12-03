# 🚨 SECURITY INCIDENT: Exposed Google API Key

**Date**: December 3, 2025
**Severity**: CRITICAL
**Status**: ACTIVE REMEDIATION

## What Happened

Google Gemini API key was hardcoded in `test_gemini_key.py` and committed to GitHub repository.

**Exposed Key**: `AIzaSyAHPsLN0ji4nExqYbndvwRNs0hvNxKMPik`
**Repository**: https://github.com/munyanyaguo/red-team-agent
**Commit**: 1c54064 "made some minor improvements"

## Immediate Actions (DO THIS NOW)

### 1. REVOKE THE EXPOSED API KEY (URGENT - Do this first!)

1. Go to: https://console.cloud.google.com/apis/credentials
2. Find the API key: `AIzaSyAHPsLN0ji4nExqYbndvwRNs0hvNxKMPik`
3. Click "DELETE" or "RESTRICT" immediately
4. Generate a NEW API key
5. Update your `.env` file with the NEW key:
   ```bash
   GEMINI_API_KEY="your-new-key-here"
   ```

### 2. Why This Is Critical

- ✅ The key is PUBLIC on GitHub
- ✅ Anyone can see it in commit history
- ✅ Bots scan GitHub for exposed API keys within minutes
- ✅ Unauthorized usage could rack up massive bills
- ✅ Your Google Cloud account could be compromised

## What We've Fixed

✅ Removed hardcoded API key from `test_gemini_key.py`
✅ Updated `.gitignore` to prevent future exposure
✅ Added environment variable validation

## Next Steps (After Revoking Key)

### Clean Git History

The old key is still in git history. After revoking, run:

```bash
# Option 1: Use BFG Repo-Cleaner (recommended)
# Download from: https://rdrr.io/cran/bfg/
java -jar bfg.jar --replace-text passwords.txt

# Option 2: Use git filter-branch (slower)
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch test_gemini_key.py" \
  --prune-empty --tag-name-filter cat -- --all

# Force push to update remote (WARNING: Rewrites history)
git push origin --force --all
```

### Verify No Other Secrets

```bash
# Scan for potential secrets
grep -r "API.*KEY" --include="*.py" --exclude-dir=venv .
grep -r "SECRET" --include="*.py" --exclude-dir=venv .
grep -r "TOKEN" --include="*.py" --exclude-dir=venv .
grep -r "PASSWORD" --include="*.py" --exclude-dir=venv .
```

## Prevention Measures Implemented

1. ✅ Updated `.gitignore` with comprehensive patterns
2. ✅ Added environment variable validation
3. ✅ Removed hardcoded credentials
4. ✅ Created this incident response document

## Security Best Practices Going Forward

1. **NEVER** hardcode API keys, passwords, or secrets
2. **ALWAYS** use environment variables (`.env` file)
3. **VERIFY** `.env` is in `.gitignore`
4. **CHECK** commits before pushing: `git diff HEAD`
5. **USE** pre-commit hooks to scan for secrets
6. **ROTATE** keys regularly (every 90 days)
7. **RESTRICT** API keys to specific IPs/domains when possible

## Install Pre-Commit Hook (Recommended)

```bash
# Install detect-secrets
pip install detect-secrets

# Scan current repository
detect-secrets scan > .secrets.baseline

# Set up pre-commit hook
cat > .git/hooks/pre-commit << 'HOOK'
#!/bin/bash
detect-secrets-hook --baseline .secrets.baseline
HOOK
chmod +x .git/hooks/pre-commit
```

## Monitoring

After revoking and rotating the key:

1. Monitor Google Cloud Console for unusual activity
2. Check billing for unexpected charges
3. Review API usage logs
4. Set up billing alerts

## Contact

If you see unauthorized usage:
- Google Cloud Support: https://cloud.google.com/support
- Report the exposed key: https://support.google.com/cloud/answer/6310037

## Status Updates

- [x] Key exposure identified
- [x] Code fixed to remove hardcoded key
- [x] .gitignore updated
- [ ] **YOU NEED TO: Revoke exposed key**
- [ ] **YOU NEED TO: Generate new key**
- [ ] **YOU NEED TO: Clean git history**
- [ ] **YOU NEED TO: Force push cleaned history**

---

**REMEMBER**: The exposed key is PUBLIC and can be used by anyone. Revoke it IMMEDIATELY!
