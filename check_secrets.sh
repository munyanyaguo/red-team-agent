#!/bin/bash
# Security: Check for exposed secrets before committing

echo "🔍 Scanning for potential secrets..."

SECRETS_FOUND=0

# Check for API keys
if grep -r "AIza[0-9A-Za-z_-]{35}" --include="*.py" --include="*.js" --exclude="*.example" --exclude-dir=venv --exclude-dir=node_modules . 2>/dev/null; then
    echo "❌ Found Google API key pattern"
    SECRETS_FOUND=1
fi

# Check for Anthropic keys
if grep -r "sk-ant-[0-9A-Za-z_-]{95,}" --include="*.py" --include="*.js" --exclude="*.example" --exclude-dir=venv --exclude-dir=node_modules . 2>/dev/null; then
    echo "❌ Found Anthropic API key pattern"
    SECRETS_FOUND=1
fi

# Check for JWT secrets (longer than 20 chars)
if grep -rE "JWT_SECRET.*[\"'][a-zA-Z0-9]{20,}[\"']" --include="*.py" --include="*.js" --exclude="*.example" --exclude-dir=venv --exclude-dir=node_modules . 2>/dev/null; then
    echo "❌ Found potential JWT secret"
    SECRETS_FOUND=1
fi

# Check for database URLs with credentials
if grep -rE "postgres(ql)?://[^:]+:[^@]+@" --include="*.py" --include="*.js" --exclude="*.example" --exclude-dir=venv --exclude-dir=node_modules . 2>/dev/null; then
    echo "❌ Found database URL with credentials"
    SECRETS_FOUND=1
fi

if [ $SECRETS_FOUND -eq 0 ]; then
    echo "✅ No secrets detected"
    exit 0
else
    echo ""
    echo "🚨 CRITICAL: Secrets detected in code!"
    echo "Do NOT commit these files."
    echo "Move secrets to .env file and use environment variables."
    exit 1
fi
