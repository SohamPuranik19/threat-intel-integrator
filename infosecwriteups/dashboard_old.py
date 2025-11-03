import os
import sys
import pathlib
import re

# Ensure the repository root is on sys.path so `infosecwriteups` can be imported
# when Streamlit runs this file as a script (Streamlit executes the file as __main__).
repo_root = pathlib.Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit.components.v1 as components
from dotenv import load_dotenv
import requests

# Canonical category set used across the UI and DB inserts. Keep machine-friendly names.
CATEGORY_CHOICES = [
    'Phishing', 'Malware', 'Ransomware', 'CredentialLeak', 'CommandAndControl', 'Botnet',
    'Spam', 'Fraud', 'C2', 'DataExfiltration', 'Reconnaissance', 'UnauthorizedAccess',
    'PolicyViolation', 'Suspicious', 'Benign'
]

def normalize_category(value: str):
    """Normalize a free-form category value to one of CATEGORY_CHOICES when possible.

    - Uses keyword matching and simple lower-case comparison.
    - Returns the original value if no mapping was found (so we don't lose data).
    """
    if not value:
        return 'Suspicious'
    lv = str(value).strip().lower()
    # common placeholders
    if lv in ('', 'unknown', 'none', 'n/a', 'na'):
        return 'Suspicious'
    # reuse variable for remaining checks
    v = str(value).strip()
    lv = v.lower()
    # direct match
    for c in CATEGORY_CHOICES:
        if lv == c.lower():
            return c
    # keyword heuristics
    if 'phish' in lv:
        return 'Phishing'
    if 'ransom' in lv:
        return 'Ransomware'
    if 'malware' in lv or 'trojan' in lv or 'virus' in lv:
        return 'Malware'
    if 'credential' in lv or 'leak' in lv or 'password' in lv:
        return 'CredentialLeak'
    if 'c2' in lv or 'command' in lv or 'control' in lv:
        return 'CommandAndControl'
    if 'bot' in lv:
        return 'Botnet'
    if 'spam' in lv:
        return 'Spam'
    if 'fraud' in lv:
        return 'Fraud'
    if 'exfil' in lv or 'data' in lv:
        return 'DataExfiltration'
    if 'recon' in lv or 'scan' in lv or 'reconnaissance' in lv:
        return 'Reconnaissance'
    if 'unauthor' in lv or 'unauth' in lv or 'unauthorized' in lv:
        return 'UnauthorizedAccess'
    if 'policy' in lv:
        return 'PolicyViolation'
    if 'suspicious' in lv:
        return 'Suspicious'
    if 'benign' in lv or 'false' in lv:
        return 'Benign'
    # fallback: return original trimmed value so we don't drop custom categories
    return v

try:
    from infosecwriteups.database import ThreatDatabase
    from infosecwriteups.api_integrations import ThreatIntelAPI
    from infosecwriteups.processor import ThreatProcessor
except ModuleNotFoundError:
    cwd = pathlib.Path.cwd()
    if (cwd / 'infosecwriteups').is_dir():
        sys.path.insert(0, str(cwd))
    else:
        for parent in pathlib.Path(__file__).resolve().parents:
            if (parent / 'infosecwriteups').is_dir():
                sys.path.insert(0, str(parent))
                break
    from infosecwriteups.database import ThreatDatabase
    from infosecwriteups.api_integrations import ThreatIntelAPI
    from infosecwriteups.processor import ThreatProcessor


def run_dashboard():
    st.set_page_config(page_title="Threat Intel Dashboard", layout="wide", page_icon="🔒")

    # Custom CSS for a distinctive look
    # Dark-mode friendly CSS
    custom_css = '''
    <style>
    :root{ --accent:#7c3aed; --accent-2:#06b6d4; --muted:#94a3b8 }
    body { background-color: #0b1220; color: #e6eef8 }
    .custom-header{display:flex;align-items:center;gap:12px;margin-bottom:8px}
    .brand-pill{background:linear-gradient(90deg,var(--accent),var(--accent-2));padding:6px 10px;border-radius:8px;color:white;font-weight:700}
    .subtle{color:#9aa6b2;font-size:13px}
    .metric-card{background:linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));padding:12px;border-radius:8px;color:#e6eef8;border:1px solid rgba(255,255,255,0.03)}
    .metric-value{font-size:18px;font-weight:700;color:#ffffff}
    .metric-label{font-size:12px;color:#9aa6b2}
    .styled-table{border-collapse:collapse;width:100%;font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial;background:transparent;color:#e6eef8}
    .styled-table thead th{color:#cbd5e1;padding:8px;text-align:left}
    .styled-table th,.styled-table td{padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);text-align:left}
    .styled-table tr:nth-child(even){background:rgba(255,255,255,0.01)}
    .styled-table tr:hover{background:rgba(255,255,255,0.02)}
    .badge{padding:4px 8px;border-radius:6px;color:#fff;font-size:12px}
    .badge-phishing{background:#ef4444}
    .badge-malware{background:#f97316}
    .badge-suspicious{background:#f59e0b;color:#111}
    .badge-benign{background:#10b981}
    /* Ensure Streamlit components (body) render dark backgrounds */
    .stButton>button, .stDownloadButton>button { background-color: #1f2937; color: #e6eef8 }
    </style>
    '''
    st.markdown(custom_css, unsafe_allow_html=True)

    # New unique header / navbar
    st.markdown(
                """
                <div style='display:flex;align-items:center;justify-content:space-between;padding:14px 6px;border-radius:8px;margin-bottom:12px;background:linear-gradient(90deg,#071124 0%, #0b1220 40%, rgba(12,20,30,0.6) 100%);'>
                    <div style='display:flex;align-items:center;gap:14px'>
                        <div style='width:44px;height:44px;border-radius:10px;background:linear-gradient(135deg,#7c3aed,#06b6d4);display:flex;align-items:center;justify-content:center;font-weight:800;color:white;font-size:18px'>TI</div>
                        <div>
                            <div style='font-size:18px;font-weight:800;color:#e6eef8'>Threat Intel Integrator</div>
                            <div style='font-size:12px;color:#9aa6b2'>Consolidated indicators • AbuseIPDB • VirusTotal • AlienVault OTX</div>
                        </div>
                    </div>
                    <div style='display:flex;align-items:center;gap:10px'>
                        <div style='color:#9aa6b2;font-size:13px'>Logged in as: <b style='color:#e6eef8'>{st.session_state.get('user') or 'guest'}</b></div>
                        <div>
                            <button onclick="window.location.reload();" style='background:#111827;border:0;padding:8px 10px;border-radius:8px;color:#e6eef8'>Refresh</button>
                        </div>
                    </div>
                </div>
        """,
        unsafe_allow_html=True,
    )

    # Database and auth
    db = ThreatDatabase()

    # Optional external API server URL to decouple UI from enrichment/backend.
    # Configure via TI_API_URL env var; defaults to local FastAPI server used in this project.
    API_URL = os.getenv('TI_API_URL') or os.getenv('TI_API') or 'http://127.0.0.1:8000'

    def api_search(q: str = '', type_: str = 'Any', limit: int = 1000):
        """Query the backend /search endpoint. Returns list of dicts or None on failure."""
        try:
            resp = requests.get(f"{API_URL}/search", params={'q': q, 'type': type_, 'limit': limit}, timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            # network/API not available — UI will fallback to local DB
            pass
        return None

    def api_lookup(indicator: str, analyze: bool = True):
        """Call backend /lookup to analyze an indicator. Returns dict or None on failure."""
        try:
            resp = requests.post(f"{API_URL}/lookup", json={'indicator': indicator, 'analyze': analyze}, timeout=12)
            if resp.status_code == 200:
                return resp.json()
            # bubble up a structured error for display
            return {'error': f'API returned {resp.status_code}', 'status_code': resp.status_code}
        except Exception:
            return None

    if 'user' not in st.session_state:
        st.session_state['user'] = None

    # Sidebar user area
    if st.session_state.get('user'):
        with st.sidebar:
            st.header('User')
            st.write(f"Signed in as: {st.session_state['user']}")
            if st.button('Logout', key='logout_button'):
                st.session_state['user'] = None

    # Auth forms for unauthenticated users
    if not st.session_state.get('user'):
        cols = st.columns([1, 2, 1])
        with cols[1]:
            st.markdown("""
                <div style="display:flex;justify-content:center;align-items:center;flex-direction:column;">
                <h2>Welcome — please login or register</h2>
                </div>
            """, unsafe_allow_html=True)

            auth_tab = st.radio('Auth mode', ['Login', 'Register'], index=0, horizontal=True, label_visibility='collapsed')

            if auth_tab == 'Login':
                with st.form('login_form'):
                    email = st.text_input('Email')
                    password = st.text_input('Password', type='password')
                    submitted = st.form_submit_button('Login')
                    if submitted:
                        if not email or not password:
                            st.error('Email and password required')
                        else:
                            try:
                                if db.verify_user(email, password):
                                    st.session_state['user'] = email
                                    st.success('Logged in')
                                    rerun = getattr(st, 'experimental_rerun', None)
                                    if callable(rerun):
                                        rerun()
                                else:
                                    st.error('Invalid credentials')
                            except Exception as e:
                                st.error(f'Login error: {e}')
            else:  # Register
                with st.form('register_form'):
                    r_email = st.text_input('Email', key='reg_email')
                    r_password = st.text_input('Password', type='password', key='reg_pw')
                    r_password2 = st.text_input('Confirm Password', type='password', key='reg_pw2')
                    reg_submitted = st.form_submit_button('Register')
                    if reg_submitted:
                        if not r_email or not r_password:
                            st.error('Email and password required')
                        elif r_password != r_password2:
                            st.error('Passwords do not match')
                        else:
                            try:
                                db.create_user(r_email, r_password)
                                st.success('Registration successful — please login')
                            except ValueError as ve:
                                st.error(str(ve))
                            except Exception as e:
                                st.error(f'Unable to register: {e}')

    # stop if unauthenticated
    if not st.session_state.get('user'):
        return

    # Load data (try API first, otherwise fallback to local DB)
    data = None
    api_data = api_search(q='', type_='Any', limit=10000)
    if api_data:
        # Normalize API payloads: the FastAPI /search returns {'count': N, 'items': [...]}
        # while older callers expect a list of records. Ensure `data` is a list.
        if isinstance(api_data, dict):
            if 'items' in api_data and isinstance(api_data['items'], list):
                data = api_data['items']
            else:
                # Unexpected dict shape — try to coerce to a single-record list if possible
                # or fall back to an empty list.
                try:
                    # If the dict looks like a single record (has 'indicator'), wrap it.
                    if 'indicator' in api_data:
                        data = [api_data]
                    else:
                        data = []
                except Exception:
                    data = []
        elif isinstance(api_data, list):
            data = api_data
        else:
            data = []
    else:
        try:
            data = db.get_all_threats()
        except Exception:
            data = []

    if not data:
        st.warning("⚠️ No threat data available. Please run the analysis first.")
        st.info("Run: `python main.py` to analyze indicators")
        return

    df = pd.DataFrame(data)

    import ipaddress

    # Search box
    search_cols = st.columns([3, 1])
    with search_cols[0]:
        search = st.text_input("Search", placeholder="enter IP or domain (or free text)")
    with search_cols[1]:
        search_type = st.selectbox("Type", options=["Any", "IP", "Domain"])    

    # Email-specific auto-lookup feature removed

    # ---- Quick Verdict panel (DB exact match; optional live analyze for IP) ----
    def infer_indicator_type(txt: str):
        if not txt:
            return None
        s = txt.strip()
        # IP
        import ipaddress as _ip
        try:
            _ip.ip_address(s)
            return 'IP'
        except Exception:
            pass
        # Email
        email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        if email_re.match(s):
            return 'Email'
        # Domain
        dom_re = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
        if dom_re.match(s.lower()):
            return 'Domain'
        return None

    def verdict_from_row(row):
        score = float(row.get('threat_score') or 0)
        cls = str(row.get('classification') or '')
        if cls.lower() == 'malicious' or score >= 70:
            return 'Malicious', '🔴'
        if cls.lower() == 'suspicious' or 40 <= score < 70:
            return 'Suspicious', '🟠'
        return 'Benign', '🟢'

    if search and search.strip():
        s_raw = search.strip()
        s_low = s_raw.lower()
        inferred = infer_indicator_type(s_raw) if search_type == 'Any' else search_type
        if inferred in {'IP', 'Domain'}:
            exact = df[df['indicator'].astype(str).str.lower().str.strip() == s_low]
            st.markdown("### Quick verdict")
            if len(exact):
                row = exact.sort_values('timestamp', ascending=False).iloc[0]
                verdict, emoji = verdict_from_row(row)
                st.success(f"{emoji} {inferred} detected. Verdict: {verdict} | Score: {row.get('threat_score', 0)} | Class: {row.get('classification', 'Unknown')} | Category: {row.get('category', 'unknown')}")
            # If exact not found or even if found, also show broader matches so users can search by substring
            # Broad filter across indicators and some textual fields
            try:
                mask = df['indicator'].astype(str).str.lower().str.contains(s_low, na=False)
                # also search in country, isp, classification
                for col in ['country', 'isp', 'classification', 'category']:
                    if col in df.columns:
                        mask = mask | df[col].astype(str).str.lower().str.contains(s_low, na=False)
                results = df[mask]
                if not results.empty:
                    st.markdown('**Search results (database matches):**')
                    st.table(results[['indicator','classification','threat_score']].head(50))
                else:
                    st.info(f"No database matches found containing '{s_raw}'.")
            except Exception:
                pass

            # Email search not supported — removed to simplify UI
            if False:
                    load_dotenv()
                    has_api_keys = any([os.getenv('VIRUSTOTAL_KEY'), os.getenv('OTX_KEY'), os.getenv('ABUSEIPDB_KEY')])
                    with st.spinner(f'Looking up {email_to_check}...'):
                        api_resp = api_lookup(email_to_check, analyze=True)
                        if api_resp is None:
                            # If we have API keys, try local API clients; otherwise run heuristic
                            if has_api_keys:
                                try:
                                    api = ThreatIntelAPI(
                                        abuse_key=os.getenv('ABUSEIPDB_KEY'),
                                        vt_key=os.getenv('VIRUSTOTAL_KEY'),
                                        otx_key=os.getenv('OTX_KEY')
                                    )
                                    processor = ThreatProcessor()
                                    results = api.fetch_all_sources(email_to_check)
                                    analysis = processor.calculate_consensus(results)
                                    enriched = processor.enrich_data(email_to_check, analysis)
                                    st.markdown('**Lookup results (not saved, local APIs):**')
                                    try:
                                        df_preview = pd.DataFrame([enriched])
                                        st.table(df_preview[[c for c in df_preview.columns if c in ['indicator','classification','threat_score','category','abuseipdb_score','virustotal_score','otx_score']]])
                                    except Exception:
                                        st.json(enriched)
                                    return
                                except Exception as e:
                                    # fall back to heuristic if external local lookup fails
                                    st.warning(f'Local external lookup failed: {e}. Running heuristic fallback.')
                        else:
                            if isinstance(api_resp, dict) and api_resp.get('error'):
                                st.error(f"Lookup API error: {api_resp.get('error')}")
                                return
                            st.markdown('**Lookup results (from API):**')
                            st.json(api_resp)
                            return

                        # Heuristic fallback (runs when api_resp is None and/or no API keys)
                        try:
                            import socket
                            domain = email_to_check.split('@')[1] if '@' in email_to_check else None
                            username = email_to_check.split('@')[0] if '@' in email_to_check else email_to_check
                            resolved = False
                            mx_found = False
                            domain_ip = None
                            if domain:
                                try:
                                    domain_ip = socket.gethostbyname(domain)
                                    resolved = True
                                except Exception:
                                    resolved = False
                                try:
                                    import importlib, importlib.util
                                    if importlib.util.find_spec('dns') is not None:
                                        dns_resolver = importlib.import_module('dns.resolver')
                                        answers = dns_resolver.resolve(domain, 'MX', lifetime=5)
                                        mx_found = len(answers) > 0
                                    else:
                                        mx_found = False
                                except Exception:
                                    mx_found = False

                            disposable = {'mailinator.com','10minutemail.com','sharklasers.com','guerrillamail.com','tempmail.com','dispostable.com'}
                            is_disposable = domain.lower() in disposable if domain else False

                            suspicious_tokens = ['spam','phish','scam','malware','promo','noreply','admin']
                            token_score = 0
                            for t in suspicious_tokens:
                                if t in username.lower():
                                    token_score += 25

                            score = 10
                            if resolved:
                                score += 30
                            if mx_found:
                                score += 20
                            score += token_score
                            if is_disposable:
                                score = max(0, score - 60)
                            score = max(0, min(100, score))

                            classification = 'Malicious' if score >= 70 else ('Suspicious' if score >= 40 else 'Benign')
                            st.markdown('**Heuristic lookup results (not saved):**')
                            st.write({'indicator': email_to_check, 'domain_resolves': resolved, 'domain_ip': domain_ip, 'mx': mx_found, 'is_disposable': is_disposable, 'heuristic_score': score, 'classification': classification})
                        except Exception as e:
                            st.error(f'Heuristic lookup failed: {e}')

                # If auto-run is enabled and we haven't already run it for this query, run lookup now
                try:
                    if st.session_state.get('auto_lookup', True) and st.session_state.get('last_auto_lookup') != s_raw:
                        run_lookup_for_email(s_raw)
                        st.session_state['last_auto_lookup'] = s_raw
                except Exception:
                    # non-fatal: continue to show manual buttons below
                    pass
                st.markdown("""
                <div style='margin-top:8px'>
                  <div style='color:#9aa6b2;font-size:13px'>This email is not in the database. You can either paste related emails (one per line) to add them, or run external lookups if API keys are configured.</div>
                </div>
                """, unsafe_allow_html=True)

                # Quick fix suggestions for common typos in emails (e.g. missing '.' before tld)
                suggested_fix = None
                try:
                    if '@' in s_raw:
                        user_part, domain_part = s_raw.split('@', 1)
                        # if domain_part has no dot and looks like 'gmailcom' or similar, suggest 'gmail.com'
                        if '.' not in domain_part:
                            common_providers = ['gmail', 'yahoo', 'outlook', 'hotmail', 'protonmail', 'icloud', 'aol', 'viit']
                            for prov in common_providers:
                                if domain_part.lower().endswith(prov + 'com') or domain_part.lower() == prov + 'com':
                                    suggested_fix = f"{user_part}@{prov}.com"
                                    break
                            if not suggested_fix and len(domain_part) > 4:
                                # fallback: insert dot before last 3 chars (common .com)
                                suggested_fix = f"{user_part}@{domain_part[:-3]}.{domain_part[-3:]}"
                except Exception:
                    suggested_fix = None

                if suggested_fix:
                    st.markdown(f"**Did you mean:** `{suggested_fix}` ?")
                    if st.button('Use suggested email', key='suggest_fix_button'):
                        # Immediately run lookup for the suggested email and show results (does not insert)
                        with st.spinner(f'Looking up {suggested_fix}...'):
                            api_resp = api_lookup(suggested_fix, analyze=True)
                            if api_resp is None:
                                # fallback to local heuristic
                                try:
                                    import socket
                                    domain = suggested_fix.split('@')[1] if '@' in suggested_fix else None
                                    username = suggested_fix.split('@')[0] if '@' in suggested_fix else suggested_fix
                                    resolved = False
                                    mx_found = False
                                    domain_ip = None
                                    if domain:
                                        try:
                                            domain_ip = socket.gethostbyname(domain)
                                            resolved = True
                                        except Exception:
                                            resolved = False
                                    # simple heuristic scoring
                                    token_score = 0
                                    suspicious_tokens = ['spam','phish','scam','malware','promo','noreply','admin']
                                    for t in suspicious_tokens:
                                        if t in username.lower():
                                            token_score += 25
                                    score = 10 + (30 if resolved else 0) + token_score
                                    score = max(0, min(100, score))
                                    classification = 'Malicious' if score >= 70 else ('Suspicious' if score >= 40 else 'Benign')
                                    st.write({'indicator': suggested_fix, 'domain_resolves': resolved, 'domain_ip': domain_ip, 'heuristic_score': score, 'classification': classification})
                                except Exception as e:
                                    st.error(f'Heuristic lookup failed: {e}')
                            else:
                                if isinstance(api_resp, dict) and api_resp.get('error'):
                                    st.error(f"Lookup API error: {api_resp.get('error')}")
                                else:
                                    st.markdown('**Lookup results (from API):**')
                                    st.json(api_resp)

                # Analyze-only lookup: prefer external APIs if configured, otherwise run a local heuristic
                load_dotenv()
                has_api_keys = any([os.getenv('VIRUSTOTAL_KEY'), os.getenv('OTX_KEY'), os.getenv('ABUSEIPDB_KEY')])
                if has_api_keys:
                    if st.button('Lookup this email (external sources, no insert)', key='lookup_email_button'):
                        with st.spinner(f'Querying external sources for {s_raw}...'):
                            # Prefer backend API; fallback to local API clients if backend not reachable
                            api_resp = api_lookup(s_raw, analyze=True)
                            if api_resp is None:
                                try:
                                    api = ThreatIntelAPI(
                                        abuse_key=os.getenv('ABUSEIPDB_KEY'),
                                        vt_key=os.getenv('VIRUSTOTAL_KEY'),
                                        otx_key=os.getenv('OTX_KEY')
                                    )
                                    processor = ThreatProcessor()
                                    results = api.fetch_all_sources(s_raw)
                                    analysis = processor.calculate_consensus(results)
                                    enriched = processor.enrich_data(s_raw, analysis)
                                    st.markdown('**Lookup results (not saved, local APIs):**')
                                    st.write({'indicator': enriched.get('indicator'), 'classification': enriched.get('classification'), 'threat_score': enriched.get('threat_score'), 'category': enriched.get('category')})
                                    try:
                                        df_preview = pd.DataFrame([enriched])
                                        st.table(df_preview[[c for c in df_preview.columns if c in ['indicator','classification','threat_score','category','abuseipdb_score','virustotal_score','otx_score']]])
                                    except Exception:
                                        st.json(enriched)
                                except Exception as e:
                                    st.error(f'External lookup failed (local): {e}')
                            else:
                                if isinstance(api_resp, dict) and api_resp.get('error'):
                                    st.error(f"Lookup API error: {api_resp.get('error')}")
                                else:
                                    st.markdown('**Lookup results (from API):**')
                                    st.json(api_resp)
                else:
                    st.info('No API keys found. Running a local heuristic lookup instead (no external queries).')
                    if st.button('Run heuristic lookup (no API keys)', key='heuristic_lookup_button'):
                        # Simple heuristics: domain resolution, MX record check (if dnspython available), username heuristics, disposable domains
                        try:
                            import socket
                            domain = s_raw.split('@')[1] if '@' in s_raw else None
                            username = s_raw.split('@')[0] if '@' in s_raw else s_raw
                            resolved = False
                            mx_found = False
                            domain_ip = None
                            if domain:
                                try:
                                    domain_ip = socket.gethostbyname(domain)
                                    resolved = True
                                except Exception:
                                    resolved = False
                                # try MX lookup if dnspython is available
                                try:
                                    import importlib, importlib.util
                                    if importlib.util.find_spec('dns') is not None:
                                        dns_resolver = importlib.import_module('dns.resolver')
                                        answers = dns_resolver.resolve(domain, 'MX', lifetime=5)
                                        mx_found = len(answers) > 0
                                    else:
                                        mx_found = False
                                except Exception:
                                    mx_found = False

                            # simple disposable domain check (small sample)
                            disposable = {'mailinator.com','10minutemail.com','sharklasers.com','guerrillamail.com','tempmail.com','dispostable.com'}
                            is_disposable = domain.lower() in disposable if domain else False

                            # username suspicious tokens
                            suspicious_tokens = ['spam','phish','scam','malware','promo','noreply','admin']
                            token_score = 0
                            for t in suspicious_tokens:
                                if t in username.lower():
                                    token_score += 25

                            score = 10
                            if resolved:
                                score += 30
                            if mx_found:
                                score += 20
                            score += token_score
                            if is_disposable:
                                score = max(0, score - 60)
                            score = max(0, min(100, score))

                            if score >= 70:
                                classification = 'Malicious'
                            elif score >= 40:
                                classification = 'Suspicious'
                            else:
                                classification = 'Benign'

                            st.markdown('**Heuristic lookup results (not saved):**')
                            st.write({'indicator': s_raw, 'domain_resolves': resolved, 'domain_ip': domain_ip, 'mx': mx_found, 'is_disposable': is_disposable, 'heuristic_score': score, 'classification': classification})
                        except Exception as e:
                            st.error(f'Heuristic lookup failed: {e}')

                related_input = st.text_area('Paste related emails (one per line or comma separated)', height=120, placeholder='alice@example.com\nalice.smith@corp.com')
                # offer smart suggestions: show any DB rows that match username or domain
                try:
                    user_part = s_raw.split('@')[0] if '@' in s_raw else None
                    domain_part = s_raw.split('@')[1] if '@' in s_raw else None
                    suggestions = pd.DataFrame()
                    if user_part:
                        suggestions = df[df['indicator'].astype(str).str.lower().str.contains(user_part.lower(), na=False)].head(8)
                    if domain_part and suggestions.empty:
                        suggestions = df[df['indicator'].astype(str).str.lower().str.contains(domain_part.lower(), na=False)].head(8)
                    if not suggestions.empty:
                        st.markdown("**Possible related indicators from DB:**")
                        st.table(suggestions[['indicator', 'classification', 'threat_score']].head(8))
                except Exception:
                    # non-fatal: continue
                    pass

                # Bulk importer UI (upload) and enrichment toggle
                upload = st.file_uploader('Or upload a file (txt/csv) with emails', type=['txt', 'csv'])
                load_dotenv()
                has_api_keys = any([os.getenv('VIRUSTOTAL_KEY'), os.getenv('OTX_KEY'), os.getenv('ABUSEIPDB_KEY')])
                if has_api_keys:
                    enrich_choice = st.checkbox('Enrich pasted/uploaded emails via external APIs (VirusTotal/OTX/AbuseIPDB) if keys present', value=False)
                else:
                    enrich_choice = False
                    if st.button('How to enable enrichment', key='how_enable_enrichment_button'):
                        st.info('Set VIRUSTOTAL_KEY, OTX_KEY, and/or ABUSEIPDB_KEY in your environment or a .env file at the repo root to enable enrichment.')
                # (single) detect if any API keys are available
                # Note: keep one button only to avoid duplicate Streamlit element IDs
                # has_api_keys and enrich_choice already evaluated above

                col_a, col_b = st.columns([1,1])
                with col_a:
                    if st.button('Add & analyze pasted emails', key='add_analyze_pasted_button'):
                        # parse emails
                        candidates = re.split(r'[\n,;]+', (related_input or '').strip())
                        emails = [e.strip() for e in candidates if e and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e.strip())]
                        if not emails:
                            st.error('No valid emails found in input')
                        else:
                            inserted = 0
                            processor = ThreatProcessor()
                            api = None
                            if enrich_choice and has_api_keys:
                                api = ThreatIntelAPI(
                                    abuse_key=os.getenv('ABUSEIPDB_KEY'),
                                    vt_key=os.getenv('VIRUSTOTAL_KEY'),
                                    otx_key=os.getenv('OTX_KEY')
                                )
                            for em in emails:
                                try:
                                    if api:
                                        with st.spinner(f'Enriching {em} ...'):
                                            # Prefer backend API enrichment for consistency and batching
                                            api_resp = api_lookup(em, analyze=True)
                                            if api_resp is None:
                                                # fallback to local API fetch
                                                try:
                                                    results = api.fetch_all_sources(em)
                                                    analysis = processor.calculate_consensus(results)
                                                    enriched = processor.enrich_data(em, analysis)
                                                except Exception as e:
                                                    st.warning(f'External enrichment failed for {em}: {e}')
                                                    enriched = {
                                                        'indicator': em,
                                                        'timestamp': __import__('datetime').datetime.utcnow().isoformat(),
                                                        'threat_score': 0.0,
                                                        'classification': 'Unknown',
                                                        'category': 'Unknown',
                                                        'abuseipdb_score': 0,
                                                        'virustotal_score': 0,
                                                        'otx_score': 0,
                                                        'source': 'manual_add'
                                                    }
                                            else:
                                                # If API returned a structured response, map it to the DB shape
                                                if isinstance(api_resp, dict) and api_resp.get('indicator'):
                                                    enriched = api_resp
                                                else:
                                                    enriched = {
                                                        'indicator': em,
                                                        'timestamp': __import__('datetime').datetime.utcnow().isoformat(),
                                                        'threat_score': 0.0,
                                                        'classification': 'Unknown',
                                                        'category': 'Unknown',
                                                        'abuseipdb_score': 0,
                                                        'virustotal_score': 0,
                                                        'otx_score': 0,
                                                        'source': 'manual_add'
                                                    }
                                    else:
                                        enriched = {
                                            'indicator': em,
                                            'timestamp': __import__('datetime').datetime.utcnow().isoformat(),
                                            'threat_score': 0.0,
                                            'classification': 'Unknown',
                                            'category': 'Unknown',
                                            'abuseipdb_score': 0,
                                            'virustotal_score': 0,
                                            'otx_score': 0,
                                            'source': 'manual_add'
                                        }
                                    # Normalize category before inserting to DB so stored values match canonical set
                                    try:
                                        enriched['category'] = normalize_category(enriched.get('category'))
                                    except Exception:
                                        pass
                                    db.insert_threat(enriched)
                                    inserted += 1
                                except Exception as e:
                                    st.warning(f'Failed to insert {em}: {e}')
                            st.success(f'Inserted {inserted} emails. Re-running analysis may be required to calculate scores.')
                            rerun = getattr(st, 'experimental_rerun', None)
                            if callable(rerun):
                                rerun()
                with col_b:
                    if st.button('Open bulk importer', key='open_bulk_importer_button'):
                        st.info('Use the bulk importer script (scripts/bulk_import_iocs.py) to add large lists, or paste into the box and click Add & analyze.')

    # Sidebar filters
    st.sidebar.header("🔧 Filters")

    # Build simple interactive filters in the sidebar and apply them to `df`.
    # These control the `filtered_df` used by the main table and charts.
    try:
        # Classification filter
        if 'classification' in df.columns:
            class_options = sorted([c for c in df['classification'].dropna().unique()])
        else:
            class_options = []
        selected_classes = st.sidebar.multiselect('Classification', options=class_options, default=class_options, key='filter_class')

        # Threat score slider
        if 'threat_score' in df.columns and not df['threat_score'].isnull().all():
            min_score = float(df['threat_score'].min())
            max_score = float(df['threat_score'].max())
        else:
            min_score, max_score = 0.0, 100.0
        score_lo, score_hi = st.sidebar.slider('Threat score range', min_value=0.0, max_value=100.0, value=(min_score, max_score), step=1.0, key='filter_score')

        # Category filter
        # Combine categories from the dataset with canonical choices for a consistent UI
        if 'category' in df.columns:
            incoming_cats = [normalize_category(c) for c in df['category'].dropna().unique()]
            cat_options = sorted(set(incoming_cats) | set(CATEGORY_CHOICES))
        else:
            cat_options = sorted(CATEGORY_CHOICES)
        selected_cats = st.sidebar.multiselect('Category', options=cat_options, default=cat_options, key='filter_cat')

    # (auto_lookup checkbox moved earlier to be available during Quick Verdict handling)

        # Apply filters
        filtered_df = df.copy()
        if selected_classes:
            filtered_df = filtered_df[filtered_df['classification'].isin(selected_classes)]
        # Ensure threat_score numeric
        if 'threat_score' in filtered_df.columns:
            filtered_df['threat_score'] = pd.to_numeric(filtered_df['threat_score'], errors='coerce').fillna(0)
            filtered_df = filtered_df[(filtered_df['threat_score'] >= score_lo) & (filtered_df['threat_score'] <= score_hi)]
        if selected_cats:
            # Normalize stored categories on-the-fly for matching
            filtered_df['category'] = filtered_df.get('category', '').apply(lambda v: normalize_category(v) if v is not None else v)
            filtered_df = filtered_df[filtered_df['category'].isin(selected_cats)]
    except Exception:
        # non-fatal: fall back to full df
        filtered_df = df.copy()

    # Reset filters button
    if st.sidebar.button('Reset Filters', key='reset_filters_button'):
        rerun = getattr(st, 'experimental_rerun', None)
        if callable(rerun):
            rerun()
        else:
            existing = dict(getattr(st, 'query_params', {}) or {})
            existing['_reset'] = str(int(__import__('time').time()))
            if hasattr(st, 'query_params'):
                st.query_params = existing
                return
            set_qp = getattr(st, 'experimental_set_query_params', None)
            if callable(set_qp):
                set_qp(_reset=existing['_reset'])
                return

    # Ensure we have a filtered_df (may be created by sidebar filters earlier) and layout columns
    if 'filtered_df' not in locals():
        filtered_df = df.copy()
    col_left, col_right = st.columns([3,1])

    with col_right:
        st.subheader("📈 Threat Score Distribution")
        fig2 = px.histogram(df, x='threat_score', nbins=20, title='Distribution of Threat Scores', color_discrete_sequence=['#636EFA'])
        fig2.update_layout(xaxis_title="Threat Score", yaxis_title="Count", showlegend=False, template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")

    # Source comparison
    st.subheader("🔍 Multi-Source Score Comparison")
    score_df = df[['indicator', 'abuseipdb_score', 'virustotal_score', 'otx_score']].head(10)
    fig3 = go.Figure()
    fig3.add_trace(go.Bar(name='AbuseIPDB', x=score_df['indicator'], y=score_df['abuseipdb_score'], marker_color='#FF6B6B'))
    fig3.add_trace(go.Bar(name='VirusTotal', x=score_df['indicator'], y=score_df['virustotal_score'], marker_color='#4ECDC4'))
    fig3.add_trace(go.Bar(name='AlienVault OTX', x=score_df['indicator'], y=score_df['otx_score'], marker_color='#95E1D3'))
    fig3.update_layout(barmode='group', xaxis_title="Indicator", yaxis_title="Threat Score", hovermode='x unified', template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
    st.plotly_chart(fig3, use_container_width=True)

    st.markdown("---")

    # Detailed table
    st.subheader("📋 Detailed Threat Intelligence Data")
    st.sidebar.markdown(f"**Showing {len(filtered_df)} of {len(df)} indicators**")

    # Ensure category_display exists (some data backfills may not include it)
    if 'category_display' not in filtered_df.columns:
        if 'category' in filtered_df.columns:
            filtered_df['category_display'] = filtered_df['category']
        else:
            filtered_df['category_display'] = 'Unknown'

    display_df = filtered_df[[
        'indicator', 'timestamp', 'threat_score', 'classification',
        'country', 'isp', 'abuseipdb_score', 'virustotal_score', 'otx_score', 'category_display'
    ]].rename(columns={'category_display': 'category'}).sort_values('threat_score', ascending=False)

    def render_styled_table(df_html):
        html = f"""
        <div style='background:transparent;padding:6px;border-radius:8px'>
          {df_html}
        </div>
        """
        components.html(html, height=420)

    def df_to_html_table(df_in):
        rows = []
        for _, r in df_in.iterrows():
            cat = str(r.get('category','')).lower()
            badge_class = 'badge-benign'
            if 'phish' in cat:
                badge_class = 'badge-phishing'
            elif 'malware' in cat or 'ransom' in cat:
                badge_class = 'badge-malware'
            elif 'suspicious' in cat:
                badge_class = 'badge-suspicious'
            rows.append(f"""
                <tr>
                  <td>{r.get('indicator','')}</td>
                  <td>{r.get('timestamp','')}</td>
                  <td>{r.get('threat_score','')}</td>
                  <td>{r.get('classification','')}</td>
                  <td>{r.get('country','')}</td>
                  <td>{r.get('isp','')}</td>
                  <td>{r.get('abuseipdb_score','')}</td>
                  <td>{r.get('virustotal_score','')}</td>
                  <td><span class='badge {badge_class}'>{r.get('category','')}</span></td>
                </tr>
            """)
        header = """
        <table class='styled-table'>
          <thead>
            <tr>
              <th>Indicator</th><th>Timestamp</th><th>Score</th><th>Classification</th>
              <th>Country</th><th>ISP</th><th>AbuseIPDB</th><th>VirusTotal</th><th>Category</th>
            </tr>
          </thead>
          <tbody>
        """
        footer = """
          </tbody>
        </table>
        """
        return header + '\n'.join(rows) + footer

    table_html = df_to_html_table(display_df.head(200))
    render_styled_table(table_html)

    # Download button
    csv = display_df.to_csv(index=False)
    st.download_button(label="📥 Download Data as CSV", data=csv, file_name="threat_intel_data.csv", mime="text/csv")

    # Footer
    st.markdown("---")
    st.markdown("*Dashboard created with Streamlit | Data sources: AbuseIPDB, VirusTotal, AlienVault OTX*")


if __name__ == "__main__":
    run_dashboard()
