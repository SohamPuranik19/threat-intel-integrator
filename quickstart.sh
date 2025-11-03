#!/bin/bash
# Quick Start Script for Threat Intel Integrator
# This script helps you get started quickly

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════╗"
echo "║   Threat Intel Integrator - Quick Start Script       ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if we're in the right directory
if [ ! -f "requirements.txt" ]; then
    echo -e "${YELLOW}⚠️  Please run this script from the project root directory${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Found project root"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}⚠️  Python 3 not found. Please install Python 3.9+${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Python 3 found: $(python3 --version)"

# Check Node.js
if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}⚠️  Node.js not found. Please install Node.js 16+${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Node.js found: $(node --version)"

# Check npm
if ! command -v npm &> /dev/null; then
    echo -e "${YELLOW}⚠️  npm not found. Please install npm${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} npm found: $(npm --version)"

echo ""
echo -e "${BLUE}Step 1: Setting up Python environment${NC}"
echo "────────────────────────────────────────"

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
    echo -e "${GREEN}✓${NC} Virtual environment created"
else
    echo -e "${GREEN}✓${NC} Virtual environment already exists"
fi

# Activate and install Python dependencies
echo "Installing Python dependencies..."
source .venv/bin/activate
pip install -q -r requirements.txt
echo -e "${GREEN}✓${NC} Python dependencies installed"

echo ""
echo -e "${BLUE}Step 2: Setting up Frontend${NC}"
echo "────────────────────────────────────────"

# Install npm dependencies if node_modules doesn't exist
if [ ! -d "frontend/node_modules" ]; then
    echo "Installing Node.js dependencies..."
    cd frontend
    npm install
    cd ..
    echo -e "${GREEN}✓${NC} Node.js dependencies installed"
else
    echo -e "${GREEN}✓${NC} Node.js dependencies already installed"
fi

echo ""
echo -e "${BLUE}Step 3: Adding sample data${NC}"
echo "────────────────────────────────────────"

if [ ! -f "threat_intel.db" ]; then
    echo "Creating database with sample data..."
    python scripts/add_test_data.py
    echo -e "${GREEN}✓${NC} Sample data added"
else
    echo -e "${GREEN}✓${NC} Database already exists"
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗"
echo "║          Setup Complete! Ready to Launch             ║"
echo "╚═══════════════════════════════════════════════════════╝${NC}"
echo ""
echo "You can now start the application in three ways:"
echo ""
echo -e "${BLUE}Option 1: Modern React Frontend (Recommended)${NC}"
echo "  Terminal 1: source .venv/bin/activate && uvicorn infosecwriteups.api_server:app --host 127.0.0.1 --port 8000 --reload"
echo "  Terminal 2: cd frontend && npm run dev"
echo "  Then open: http://localhost:3000"
echo ""
echo -e "${BLUE}Option 2: Streamlit Dashboard${NC}"
echo "  source .venv/bin/activate && streamlit run infosecwriteups/dashboard.py --server.port 8502"
echo "  Then open: http://localhost:8502"
echo ""
echo -e "${BLUE}Option 3: API Only${NC}"
echo "  source .venv/bin/activate && uvicorn infosecwriteups.api_server:app --host 127.0.0.1 --port 8000"
echo "  API docs: http://127.0.0.1:8000/docs"
echo ""
echo -e "${YELLOW}Quick Test:${NC}"
echo "  Run smoke tests: ./tests/smoke_test.sh"
echo ""
echo -e "${GREEN}Happy Threat Hunting! 🔍🛡️${NC}"
echo ""
