#!/bin/bash
# Smoke tests for Threat Intel Integrator
# Tests basic functionality of frontend and backend

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FRONTEND_URL="http://localhost:3000"
BACKEND_URL="http://127.0.0.1:8000"

echo "🧪 Running Smoke Tests for Threat Intel Integrator"
echo "=================================================="
echo ""

# Test 1: Frontend loads
echo -n "Test 1: Frontend loads (HTTP 200)... "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" $FRONTEND_URL)
if [ "$STATUS" -eq 200 ]; then
    echo -e "${GREEN}✓ PASS${NC} (HTTP $STATUS)"
else
    echo -e "${RED}✗ FAIL${NC} (HTTP $STATUS)"
    exit 1
fi

# Test 2: Frontend has correct title
echo -n "Test 2: Frontend has correct title... "
TITLE=$(curl -s $FRONTEND_URL | grep -o '<title>.*</title>')
if [[ $TITLE == *"Threat Intel Dashboard"* ]]; then
    echo -e "${GREEN}✓ PASS${NC}"
else
    echo -e "${RED}✗ FAIL${NC} (Got: $TITLE)"
    exit 1
fi

# Test 3: Backend /search endpoint works
echo -n "Test 3: Backend /search endpoint... "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/search?limit=1")
if [ "$STATUS" -eq 200 ]; then
    echo -e "${GREEN}✓ PASS${NC} (HTTP $STATUS)"
else
    echo -e "${RED}✗ FAIL${NC} (HTTP $STATUS)"
    exit 1
fi

# Test 4: Backend /search returns valid JSON
echo -n "Test 4: /search returns valid JSON... "
RESPONSE=$(curl -s "$BACKEND_URL/search?limit=1")
COUNT=$(echo $RESPONSE | jq -r '.count' 2>/dev/null || echo "error")
if [ "$COUNT" != "error" ] && [ "$COUNT" != "null" ]; then
    echo -e "${GREEN}✓ PASS${NC} (count: $COUNT)"
else
    echo -e "${RED}✗ FAIL${NC}"
    exit 1
fi

# Test 5: Backend /lookup endpoint works
echo -n "Test 5: Backend /lookup endpoint... "
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BACKEND_URL/lookup" \
    -H "Content-Type: application/json" \
    -d '{"indicator":"8.8.8.8","analyze":false}')
if [ "$STATUS" -eq 200 ]; then
    echo -e "${GREEN}✓ PASS${NC} (HTTP $STATUS)"
else
    echo -e "${RED}✗ FAIL${NC} (HTTP $STATUS)"
    exit 1
fi

# Test 6: /lookup returns classification
echo -n "Test 6: /lookup returns classification... "
RESPONSE=$(curl -s -X POST "$BACKEND_URL/lookup" \
    -H "Content-Type: application/json" \
    -d '{"indicator":"google.com","analyze":false}')
CLASSIFICATION=$(echo $RESPONSE | jq -r '.classification' 2>/dev/null || echo "error")
if [ "$CLASSIFICATION" != "error" ] && [ "$CLASSIFICATION" != "null" ]; then
    echo -e "${GREEN}✓ PASS${NC} (classification: $CLASSIFICATION)"
else
    echo -e "${RED}✗ FAIL${NC}"
    exit 1
fi

# Test 7: CORS headers present
echo -n "Test 7: CORS headers configured... "
CORS_HEADER=$(curl -s -I -X OPTIONS "$BACKEND_URL/search?q=test" \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: GET" | grep -i "access-control-allow-origin")
if [[ $CORS_HEADER == *"localhost:3000"* ]]; then
    echo -e "${GREEN}✓ PASS${NC}"
else
    echo -e "${RED}✗ FAIL${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=================================================="
echo "✓ All smoke tests passed!"
echo -e "==================================================${NC}"
echo ""
