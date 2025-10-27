#!/bin/bash

# Red Team Agent - Quick Setup Script
# This script will set up the entire Red Team Agent environment

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                                                          ║"
    echo "║         RED TEAM AGENT - AUTOMATED SETUP                 ║"
    echo "║                                                          ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    echo -e "\n${GREEN}➜ $1${NC}\n"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Main setup
print_header

echo "This script will:"
echo "  1. Check prerequisites"
echo "  2. Create virtual environment"
echo "  3. Install Python dependencies (using Pipenv)"
echo "  4. Start Docker services"
echo "  5. Configure environment"
echo "  6. Initialize database"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Step 1: Checking Prerequisites
print_step "Step 1: Checking Prerequisites"

MISSING_DEPS=0

if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is required. Please install Python 3.10 or higher."
    MISSING_DEPS=1
else
    print_success "python3 is installed"
fi

if ! command -v docker &> /dev/null; then
    print_error "Docker is required. Please install Docker."
    MISSING_DEPS=1
else
    print_success "docker is installed"
fi

# Check for docker-compose (v1) or docker compose (v2)
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    print_error "Docker Compose (v1 or v2) is required. Please install Docker Compose."
    MISSING_DEPS=1
else
    print_success "Docker Compose (v1 or v2) is installed"
fi

if ! command -v nmap &> /dev/null; then
    print_warning "nmap is not installed. Attempting to install..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        sudo apt-get update && sudo apt-get install -y nmap
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        brew install nmap
    else
        print_error "Please install nmap manually"
        MISSING_DEPS=1
    fi
else
    print_success "nmap is installed"
fi

if [ $MISSING_DEPS -eq 1 ]; then
    print_error "Please install missing dependencies and try again"
    exit 1
fi

# Step 2: Create Virtual Environment
print_step "Step 2: Creating Virtual Environment"

if [ -d "venv" ]; then
    print_warning "Virtual environment already exists. Skipping..."
else
    # Check if python3-venv is installed for Debian/Ubuntu
    if [[ "$OSTYPE" == "linux-gnu"* ]] && ! dpkg -s python3-venv &> /dev/null; then
        print_warning "python3-venv is not installed. Attempting to install..."
        sudo apt-get update && sudo apt-get install -y python3-venv || print_error "Failed to install python3-venv. Please install it manually." && exit 1
    fi
    python3 -m venv venv
    print_success "Virtual environment created"
fi

# Activate virtual environment
source venv/bin/activate

# Step 3: Install Python Dependencies (using Pipenv)
print_step "Step 3: Installing Python Dependencies (using Pipenv)"

pip install --upgrade pip
pip install pipenv # Install pipenv itself

# Use pipenv to install dependencies
pipenv install --deploy --system

print_success "Python dependencies installed"

# Step 4: Start Docker Services
print_step "Step 4: Starting Docker Services"

# Check if services are already running
if docker ps | grep -q "redteam_postgres"; then
    print_warning "Docker services already running. Skipping..."
else
    docker-compose up -d
    print_success "Docker services started"
    
    # Wait for PostgreSQL to be ready
    echo "Waiting for PostgreSQL to be ready..."
    sleep 10
    
    # Check if PostgreSQL is ready
    for i in {1..30}; do
        if docker exec redteam_postgres pg_isready -U redteam &> /dev/null; then
            print_success "PostgreSQL is ready"
            break
        fi
        echo -n "."
        sleep 1
    done
fi

# Step 5: Configure Environment
print_step "Step 5: Configuring Environment"

if [ -f ".env" ]; then
    print_warning ".env file already exists. Skipping..."
else
    cat > .env << EOF
# Flask Configuration
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY=$(openssl rand -base64 32)

# Database
DATABASE_URL=postgresql://redteam:securepassword@postgres:5432/redteam_db
REDIS_URL=redis://localhost:6379/0

# AI API Keys (ADD YOUR KEYS HERE)
ANTHROPIC_API_KEY=your-anthropic-api-key-here
OPENAI_API_KEY=your-openai-api-key-here

# Security Settings
AUTHORIZED_DOMAINS=example.com,testsite.local
MAX_SCAN_TIMEOUT=300
ENABLE_EXPLOITATION=false

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/redteam.log
EOF
    
    print_success ".env file created"
    print_warning "IMPORTANT: Edit .env and add your Anthropic API key!"
    echo "Get your key from: https://console.anthropic.com/"
fi

# Create necessary directories
print_step "Creating Directories"

mkdir -p logs reports data
print_success "Directories created"

# Step 6: Initialize Database
print_step "Step 6: Initializing Database"

python << EOF
from app import create_app
from app.models import db

app = create_app('development')
with app.app_context():
    db.create_all()
    print("Database initialized successfully!")
EOF

print_success "Database initialized"

# Step 7: Run Tests (Optional)
print_step "Step 7: Running Basic Tests (Optional)"

read -p "Run basic tests? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Ensure pytest and pytest-cov are installed via pipenv
    pipenv install pytest pytest-cov --dev --system
    pytest test_basic.py -v --tb=short || print_warning "Some tests failed (this is okay for first setup)"
fi

# Final Summary
echo ""
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║              SETUP COMPLETED SUCCESSFULLY! 🎉            ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo ""
echo "Next Steps:"
echo ""
echo "1. Edit .env and add your Anthropic API key:"
echo -e "   ${YELLOW}nano .env${NC}"
echo ""
echo "2. Start the application:"
echo -e "   ${YELLOW}python run.py${NC}"
echo ""
echo "3. In a new terminal, run the example:"
echo -e "   ${YELLOW}python example_usage.py${NC}"
echo ""
echo "4. Access n8n workflow editor:"
echo -e "   ${YELLOW}http://localhost:5678${NC}"
echo "   Username: admin"
echo "   Password: change-this-password"
echo ""
echo "Services Status:"
docker-compose ps

echo ""
echo "Useful commands:"
echo "  - View logs: tail -f logs/redteam.log"
echo "  - Stop services: docker-compose down"
echo "  - Database access: docker exec -it redteam_postgres psql -U redteam -d redteam_db"
echo ""
print_warning "Remember: Always get proper authorization before security testing!"
echo ""