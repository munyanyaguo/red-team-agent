#!/bin/bash
# Script to remove exposed API key from git history

echo "🔧 STEP 1: Creating backup branch..."
git branch backup-before-cleanup

echo ""
echo "🔧 STEP 2: Removing API key from git history..."
echo "This will rewrite history for test_gemini_key.py..."
echo ""

# Remove the file from all history
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch test_gemini_key.py' \
  --prune-empty --tag-name-filter cat -- --all

echo ""
echo "🔧 STEP 3: Cleaning up refs..."
rm -rf .git/refs/original/
git reflog expire --expire=now --all
git gc --prune=now --aggressive

echo ""
echo "✅ History cleaned locally!"
echo ""
echo "📊 Verify the key is gone:"
echo "   git log --all --oneline | head -10"
echo ""
echo "⚠️  NEXT STEPS:"
echo "1. Verify the old commit no longer shows the key:"
echo "   git show 1c54064:test_gemini_key.py"
echo ""
echo "2. Force push to GitHub (DANGEROUS - rewrites remote history):"
echo "   git push origin --force --all"
echo "   git push origin --force --tags"
echo ""
echo "3. All collaborators must re-clone the repository"
echo ""
echo "💾 If something goes wrong, restore from backup:"
echo "   git checkout backup-before-cleanup"
