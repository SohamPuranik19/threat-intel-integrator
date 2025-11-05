## Production Deployment Checklist

### ✅ Pre-Deployment Setup

**Files Created:**
- [x] `Dockerfile` - Container configuration for backend
- [x] `render.yaml` - Render deployment configuration
- [x] `.gitignore` - Already exists with proper exclusions
- [x] `frontend/src/config/api.ts` - Environment-based API URL configuration
- [x] `DEPLOYMENT_GUIDE.md` - Complete deployment instructions

**Next Steps:**

### 1️⃣ Push Code to GitHub

```bash
cd /Users/sohampuranik/Documents/projects/threat-intel-integrator-main

# Initialize git if not already done
git init
git add .
git commit -m "feat: Production-ready threat intelligence platform

- 9 threat intelligence sources (URLhaus, ThreatFox, WHOIS, VirusTotal, etc.)
- Multi-source IOC analysis with composite scoring
- MITRE ATT&CK framework classification
- Connection graph visualization
- Enhanced API with 10 endpoints
- Next.js frontend with real-time analysis
- Comprehensive documentation suite"

# Add your GitHub remote
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git

# Push to GitHub
git push -u origin main
```

### 2️⃣ Deploy Backend to Render.com (FREE)

1. **Go to [render.com](https://render.com)** and sign up (free)
2. Click **"New +" → "Web Service"**
3. **Connect GitHub repository** you just created
4. Render will detect `render.yaml` automatically
5. **Or manually configure:**
   - **Name:** `threat-intel-backend`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn infosecwriteups.api_server_enhanced:app --host 0.0.0.0 --port $PORT`
   - **Plan:** `Free` (spins down after 15min inactivity)

6. **Add Disk for SQLite Database:**
   - Under "Disks", click **"Add Disk"**
   - **Name:** `threat-intel-data`
   - **Mount Path:** `/app/data`
   - **Size:** `1 GB` (free tier)

7. **Add Environment Variables (optional API keys):**
   ```
   VIRUSTOTAL_API_KEY=your_key_here
   ABUSEIPDB_API_KEY=your_key_here
   OTX_API_KEY=your_key_here
   URLSCAN_API_KEY=your_key_here
   SHODAN_API_KEY=your_key_here
   HYBRID_ANALYSIS_API_KEY=your_key_here
   ```

8. Click **"Create Web Service"**
9. **Wait 5-10 minutes** for deployment
10. **Copy your backend URL:** `https://YOUR_APP_NAME.onrender.com`

### 3️⃣ Update Frontend API Configuration

**Before deploying frontend, update the production URL:**

```bash
# Edit frontend/src/config/api.ts
# Replace 'https://your-backend-url.onrender.com' with your actual Render URL
```

Update this line in `frontend/src/config/api.ts`:
```typescript
const PRODUCTION_API_URL = 'https://YOUR_APP_NAME.onrender.com';
```

**Commit the change:**
```bash
git add frontend/src/config/api.ts
git commit -m "feat: Update production backend URL"
git push
```

### 4️⃣ Deploy Frontend to Vercel (FREE)

1. **Go to [vercel.com](https://vercel.com)** and sign up (free)
2. Click **"Add New..." → "Project"**
3. **Import your GitHub repository**
4. **Configure project:**
   - **Framework Preset:** `Next.js`
   - **Root Directory:** `frontend`
   - **Build Command:** `npm run build` (auto-detected)
   - **Output Directory:** `.next` (auto-detected)

5. **Add Environment Variable:**
   ```
   Name: NEXT_PUBLIC_API_URL
   Value: https://YOUR_APP_NAME.onrender.com
   ```

6. Click **"Deploy"**
7. **Wait 2-3 minutes** for deployment
8. **Copy your frontend URL:** `https://YOUR_PROJECT.vercel.app`

### 5️⃣ Update Backend CORS for Frontend

**Edit `infosecwriteups/api_server_enhanced.py`** to allow your Vercel domain:

```python
# Find this section (around line 40-50)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://YOUR_PROJECT.vercel.app",  # ← ADD THIS LINE
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Commit and push:**
```bash
git add infosecwriteups/api_server_enhanced.py
git commit -m "feat: Add Vercel domain to CORS"
git push
```

Render will automatically redeploy the backend (takes ~2 minutes).

### 6️⃣ Test Production Deployment

**Backend Health Check:**
```bash
curl https://YOUR_APP_NAME.onrender.com/health
# Should return: {"status":"healthy"}
```

**Frontend Test:**
1. Visit `https://YOUR_PROJECT.vercel.app`
2. Login with demo credentials (or any username if auth is disabled)
3. Test IOC analysis:
   - Enter: `8.8.8.8`
   - Click "Analyze"
   - Should see composite score, MITRE classification, sources checked
4. Check "Recent Indicators" table loads
5. Test CSV export

**Full Feature Test:**
- ✅ Multi-source integration (9 sources listed)
- ✅ Composite scorecard (0-100 score displayed)
- ✅ IOC classification (phishing/C2/malware + severity)
- ✅ MITRE ATT&CK mapping (tactic + technique shown)
- ✅ Connection graph (related IOCs displayed)
- ✅ Data table with filtering and export

### 7️⃣ Get Free API Keys (Optional but Recommended)

To enable all 9 sources instead of just 3:

**VirusTotal (20% weight):**
- Sign up: https://www.virustotal.com/gui/join-us
- Get API key: https://www.virustotal.com/gui/my-apikey
- Free tier: 500 requests/day

**AbuseIPDB (15% weight):**
- Sign up: https://www.abuseipdb.com/register
- Get API key: https://www.abuseipdb.com/account/api
- Free tier: 1,000 requests/day

**AlienVault OTX (15% weight):**
- Sign up: https://otx.alienvault.com/
- Get API key: Settings → API Integration
- Free tier: Unlimited

**URLScan.io (15% weight):**
- Sign up: https://urlscan.io/user/signup
- Get API key: https://urlscan.io/user/profile/
- Free tier: 1,000 requests/day

**Shodan (10% weight):**
- Sign up: https://account.shodan.io/register
- Get API key: https://account.shodan.io/
- Free tier: 100 queries/month

**Hybrid Analysis (10% weight):**
- Sign up: https://www.hybrid-analysis.com/signup
- Get API key: Settings → API
- Free tier: 200 requests/day

**Add keys to Render:**
1. Go to your Render dashboard
2. Select your `threat-intel-backend` service
3. Click **"Environment"** tab
4. Click **"Add Environment Variable"**
5. Add each API key
6. Click **"Save Changes"** (triggers auto-redeploy)

### 8️⃣ Post-Deployment Configuration

**Update Database Location (if using persistent disk):**

Edit `infosecwriteups/config.py`:
```python
import os

# Use /app/data for production (Render disk mount)
DB_PATH = os.getenv('DB_PATH', '/app/data/threat_intel_enhanced.db')
```

**Set Up Monitoring:**
- Render provides basic monitoring in dashboard
- Add Sentry for error tracking (optional): https://sentry.io
- Set up UptimeRobot for uptime monitoring (free): https://uptimerobot.com

### 🎉 Your Platform is LIVE!

**URLs:**
- **Frontend:** `https://YOUR_PROJECT.vercel.app`
- **Backend API:** `https://YOUR_APP_NAME.onrender.com`
- **API Docs:** `https://YOUR_APP_NAME.onrender.com/docs`

**Free Tier Limits:**
- **Render:** Backend sleeps after 15min (cold start ~30sec)
- **Vercel:** Unlimited deployments, 100GB bandwidth/month
- **Total Cost:** $0/month

**Share with SOC/IR Teams:**
Your platform is now production-ready for real-world threat intelligence analysis! 🚀

---

## 📚 Documentation Reference

- **Testing:** See `TESTING_GUIDE.md`, `MANUAL_TESTING_GUIDE.md`
- **Troubleshooting:** See `TROUBLESHOOTING.md`
- **Use Cases:** See `REAL_WORLD_USE_CASES.md`
- **User Guide:** See `USER_GUIDE.md`
- **Full Deployment:** See `DEPLOYMENT_GUIDE.md`

---

## 🔥 Quick Troubleshooting

**Backend not responding (502 error):**
- Free tier spins down after 15min
- First request takes ~30sec to wake up
- Subsequent requests are fast

**CORS errors in browser console:**
- Check you added Vercel URL to CORS in `api_server_enhanced.py`
- Redeploy backend after CORS update

**Table not loading:**
- Check browser console for API errors
- Verify backend URL in `frontend/src/config/api.ts`
- Check NEXT_PUBLIC_API_URL environment variable in Vercel

**API keys not working:**
- Verify keys are added in Render dashboard
- Check backend logs for authentication errors
- Some APIs require email verification before activation
