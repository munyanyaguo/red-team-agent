#!/bin/bash
# Red Team Agent - Server Start Script
# This script properly activates the virtual environment and starts the server

echo "🚀 Starting Red Team Agent..."
echo ""

# Navigate to project directory
cd /home/chei/personal-projects/red-team-agent

# Exit any existing pipenv shell
exit 2>/dev/null || true

# Activate the correct virtual environment
source venv/bin/activate

# Verify Flask is installed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "❌ Flask not found. Installing dependencies..."
    pipenv install --deploy
fi

# Start the server
echo "✅ Starting server on http://localhost:5000"
echo "📝 Login with: admin / admin123"
echo ""
python3 run.py
