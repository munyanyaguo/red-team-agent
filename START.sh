#!/bin/bash
# Red Team Agent - Quick Start Script

echo "════════════════════════════════════════════════════════════════"
echo "           RED TEAM AGENT - STARTING UP                          "
echo "════════════════════════════════════════════════════════════════"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "⚙️  Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "⚙️  Activating virtual environment..."
source venv/bin/activate

# Check if dependencies are installed
if [ ! -f "venv/lib/python3.12/site-packages/flask/__init__.py" ]; then
    echo "📦 Installing dependencies (this may take a few minutes)..."
    pipenv install --deploy
fi

# Start the server
echo ""
echo "🚀 Starting Red Team Agent..."
echo ""

python run.py
