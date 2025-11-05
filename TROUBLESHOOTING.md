# 🔧 Quick Troubleshooting Guide

## ✅ **System Status Check**

### **Backend Server (Port 8000)**
```bash
# Check if running
curl http://localhost:8000/health

# Should return:
{"status": "healthy", "service": "Advanced Threat Intelligence API"}
```

### **Frontend Server (Port 3000)**
```bash
# Check if running
curl http://localhost:3000

# Should return HTML with status 200
```

---

## 🚨 **Common Issues & Solutions**

### **Issue 1: "404 Not Found" or "Connection Refused"**

**Symptom:** Errors when clicking "Lookup" or "Load Table"

**Cause:** One or both servers are not running

**Solution:**
```bash
# Terminal 1: Start Backend
cd /Users/sohampuranik/Documents/projects/threat-intel-integrator-main
python3 -m uvicorn infosecwriteups.api_server_enhanced:app --port 8000

# Terminal 2: Start Frontend  
cd /Users/sohampuranik/Documents/projects/threat-intel-integrator-main/frontend
npm run dev
```

---

### **Issue 2: Table Not Loading**

**Symptom:** Clicking "Load Table" shows "No data available"

**Cause:** No indicators have been analyzed yet

**Solution:**
1. First analyze some indicators:
   - Type `8.8.8.8` → Click "Lookup"
   - Type `google.com` → Click "Lookup"
   - Type `1.1.1.1` → Click "Lookup"
2. Then click "Load Table" → Should show 3 rows

---

### **Issue 3: "CORS Error" in Browser Console**

**Symptom:** Requests blocked by CORS policy

**Cause:** Frontend/backend not communicating

**Solution:**
1. Verify backend is running on port 8000
2. Refresh the browser page (Ctrl+R or Cmd+R)
3. Clear browser cache if needed

---

### **Issue 4: Blank Page or Not Loading**

**Symptom:** Frontend shows blank page

**Solution:**
```bash
# Stop frontend (Ctrl+C)
# Clear Next.js cache
cd /Users/sohampuranik/Documents/projects/threat-intel-integrator-main/frontend
rm -rf .next

# Restart frontend
npm run dev
```

---

### **Issue 5: Old Data Showing**

**Symptom:** See old field names or errors about missing fields

**Cause:** Browser cached old JavaScript

**Solution:**
1. Hard refresh browser: `Ctrl+Shift+R` (Windows/Linux) or `Cmd+Shift+R` (Mac)
2. Or clear browser cache completely
3. Or open incognito/private window

---

## 🧪 **Quick Test Commands**

### **Test Backend API:**
```bash
# 1. Check health
curl http://localhost:8000/health

# 2. List sources
curl http://localhost:8000/sources | python3 -m json.tool

# 3. Analyze an IP
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"indicator":"8.8.8.8","indicator_type":"ip"}' \
  | python3 -m json.tool

# 4. Get indicators
curl http://localhost:8000/indicators?limit=5 | python3 -m json.tool
```

### **Test Frontend:**
```bash
# Open in browser
open http://localhost:3000

# Or test if it's responding
curl http://localhost:3000
```

---

## 📊 **Step-by-Step Testing**

### **Test 1: Verify Both Servers Running**
```bash
# Backend check
curl http://localhost:8000/health
# ✅ Should return: {"status":"healthy"...}

# Frontend check  
curl -I http://localhost:3000
# ✅ Should return: HTTP/1.1 200 OK
```

### **Test 2: Login**
1. Go to http://localhost:3000
2. Enter any email/password
3. Click "Access System"
4. ✅ Should redirect to dashboard

### **Test 3: Analyze Indicator**
1. Type: `8.8.8.8`
2. Click "Lookup"
3. ✅ Should show Quick Verdict card within 5-10 seconds
4. ✅ Should display: Benign, Score ~0-5, Low Severity

### **Test 4: Load Table**
1. Click "Load Table" button
2. ✅ Should show analyzed indicators in table
3. ✅ Table should have columns: Indicator, Type, Classification, Score, IOC Type, Severity, Timestamp

---

## 🔍 **Debug: What's Actually Happening**

### **Check Browser Console (F12):**
```javascript
// Open DevTools (F12)
// Go to Console tab
// Look for errors (red text)

// Common errors:
- "Failed to fetch" → Backend not running
- "404 Not Found" → Wrong endpoint
- "CORS error" → CORS not configured
- "Network error" → Server not accessible
```

### **Check Backend Logs:**
Look at the terminal running the backend:
```
INFO:     127.0.0.1:51698 - "POST /analyze HTTP/1.1" 200 OK  ← ✅ Good
INFO:     127.0.0.1:51604 - "POST /lookup HTTP/1.1" 404     ← ❌ Old endpoint
```

If you see **404 errors**, the frontend is still using old code (clear cache).

---

## 🎯 **Verification Checklist**

Before reporting an issue, verify:

- [ ] Backend running: `curl http://localhost:8000/health`
- [ ] Frontend running: `curl http://localhost:3000`
- [ ] Browser on http://localhost:3000
- [ ] Cleared browser cache (Cmd+Shift+R)
- [ ] Analyzed at least 1 indicator before loading table
- [ ] Checked browser console for errors (F12)
- [ ] Checked backend terminal for 404/500 errors

---

## 🚀 **Fresh Start (If Everything Fails)**

```bash
# 1. Stop everything (Ctrl+C in all terminals)

# 2. Kill any processes on ports
lsof -ti:8000 | xargs kill -9 2>/dev/null
lsof -ti:3000 | xargs kill -9 2>/dev/null

# 3. Clear frontend cache
cd /Users/sohampuranik/Documents/projects/threat-intel-integrator-main/frontend
rm -rf .next

# 4. Start backend (Terminal 1)
cd /Users/sohampuranik/Documents/projects/threat-intel-integrator-main
python3 -m uvicorn infosecwriteups.api_server_enhanced:app --port 8000

# 5. Start frontend (Terminal 2)
cd /Users/sohampuranik/Documents/projects/threat-intel-integrator-main/frontend
npm run dev

# 6. Open browser in incognito mode
# 7. Go to http://localhost:3000
```

---

## 📞 **Still Not Working?**

### **Share these details:**

1. **Backend status:**
   ```bash
   curl http://localhost:8000/health
   ```

2. **Frontend status:**
   ```bash
   curl -I http://localhost:3000
   ```

3. **Browser console errors:**
   - Press F12 → Console tab → Copy any red errors

4. **Backend terminal output:**
   - Copy last 20 lines from backend terminal

5. **What you're trying to do:**
   - "Clicking Lookup" or "Loading Table" etc.

6. **What happens:**
   - Error message, blank page, timeout, etc.

---

## ✅ **Expected Behavior**

### **When Everything Works:**

1. **Login Page:**
   - See 6 layers of animations
   - Can login with any credentials
   - Redirects to dashboard

2. **Dashboard:**
   - Search bar is visible
   - Can type indicators
   - "Lookup" button works

3. **Analysis:**
   - Takes 5-10 seconds
   - Shows Quick Verdict card
   - Displays score, classification, severity

4. **Table:**
   - "Load Table" shows analyzed indicators
   - Can filter, sort, export CSV
   - Shows correct columns

---

## 🎓 **Pro Tips**

1. **Always check both servers are running** before testing
2. **Analyze indicators first** before loading table
3. **Use hard refresh** (Cmd+Shift+R) after code changes
4. **Check browser console** (F12) for JavaScript errors
5. **Check backend terminal** for API errors
6. **Use incognito mode** to avoid cache issues

---

**Both servers are currently running! Go test at http://localhost:3000** 🚀
