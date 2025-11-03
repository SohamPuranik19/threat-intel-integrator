import os
import sys
import pathlib
import re

# Ensure the repository root is on sys.path
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

# Canonical category set
CATEGORY_CHOICES = [
    'Phishing', 'Malware', 'Ransomware', 'CredentialLeak', 'CommandAndControl', 'Botnet',
    'Spam', 'Fraud', 'C2', 'DataExfiltration', 'Reconnaissance', 'UnauthorizedAccess',
    'PolicyViolation', 'Suspicious', 'Benign'
]

def normalize_category(value: str):
    """Normalize category value to canonical set."""
    if not value:
        return 'Suspicious'
    lv = str(value).strip().lower()
    if lv in ('', 'unknown', 'none', 'n/a', 'na'):
        return 'Suspicious'
    v = str(value).strip()
    lv = v.lower()
    for c in CATEGORY_CHOICES:
        if lv == c.lower():
            return c
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

    # Custom CSS with modern color scheme and typography
    custom_css = '''
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&family=Space+Mono:wght@400;700&display=swap');
    
    :root { 
        --primary:#00d9ff; 
        --secondary:#ff006e; 
        --accent:#3a86ff;
        --success:#06d6a0;
        --warning:#ffd60a;
        --danger:#ef476f;
        --dark:#0a0e27;
        --light:#f0f3ff;
        --text-primary:#f0f3ff;
        --text-secondary:#a8adbd;
        --border-color:#2d3142;
    }
    
    body { 
        background-color: #0a0e27;
        color: #f0f3ff;
        font-family: 'Inter', sans-serif;
    }
    
    h1, h2, h3, h4, h5, h6 {
        font-family: 'Inter', sans-serif;
        font-weight: 800;
        letter-spacing: -0.5px;
    }
    
    .custom-header{display:flex;align-items:center;gap:14px;margin-bottom:16px}
    .brand-pill{background:linear-gradient(135deg, #00d9ff, #3a86ff);padding:8px 12px;border-radius:12px;color:#0a0e27;font-weight:800;font-size:14px;letter-spacing:0.5px}
    .subtle{color:#a8adbd;font-size:13px;font-family:'Inter',sans-serif}
    
    .metric-card{
        background:linear-gradient(135deg, rgba(0,217,255,0.08), rgba(58,134,255,0.06));
        padding:14px;
        border-radius:10px;
        color:#f0f3ff;
        border:1px solid rgba(0,217,255,0.2);
        backdrop-filter:blur(10px);
    }
    
    .metric-value{font-size:20px;font-weight:800;color:#00d9ff;font-family:'Space Mono',monospace}
    .metric-label{font-size:12px;color:#a8adbd;text-transform:uppercase;letter-spacing:0.5px}
    
    .styled-table{
        border-collapse:collapse;
        width:100%;
        font-family:'Inter',sans-serif;
        background:transparent;
        color:#f0f3ff;
    }
    
    .styled-table thead th{
        color:#00d9ff;
        padding:12px 8px;
        text-align:left;
        font-weight:700;
        border-bottom:2px solid rgba(0,217,255,0.3);
        font-family:'Space Mono',monospace;
        font-size:12px;
        text-transform:uppercase;
    }
    
    .styled-table th,.styled-table td{
        padding:10px 8px;
        border-bottom:1px solid rgba(0,217,255,0.1);
        text-align:left;
    }
    
    .styled-table tr:nth-child(even){background:rgba(0,217,255,0.02)}
    .styled-table tr:hover{background:rgba(0,217,255,0.05);transition:0.2s}
    
    .badge{
        padding:5px 10px;
        border-radius:8px;
        color:#fff;
        font-size:11px;
        font-weight:700;
        font-family:'Inter',sans-serif;
        text-transform:uppercase;
        letter-spacing:0.5px;
    }
    
    .badge-phishing{background:#ef476f;box-shadow:0 0 12px rgba(239,71,111,0.3)}
    .badge-malware{background:#f97316;box-shadow:0 0 12px rgba(249,115,22,0.3)}
    .badge-suspicious{background:#ffd60a;color:#0a0e27;box-shadow:0 0 12px rgba(255,214,10,0.3)}
    .badge-benign{background:#06d6a0;box-shadow:0 0 12px rgba(6,214,160,0.3)}
    
    .stButton>button, .stDownloadButton>button { 
        background:linear-gradient(135deg, #00d9ff, #3a86ff);
        color:#0a0e27;
        font-weight:700;
        border:none;
        border-radius:8px;
        font-family:'Inter',sans-serif;
        transition:0.3s;
    }
    
    .stButton>button:hover, .stDownloadButton>button:hover {
        transform:translateY(-2px);
        box-shadow:0 8px 20px rgba(0,217,255,0.4);
    }
    </style>
    '''
    st.markdown(custom_css, unsafe_allow_html=True)

    # Header with modern styling
    st.markdown(
        """
        <div style='display:flex;align-items:center;justify-content:space-between;padding:16px 12px;border-radius:12px;margin-bottom:16px;background:linear-gradient(135deg, rgba(0,217,255,0.08) 0%, rgba(58,134,255,0.06) 100%);border:1px solid rgba(0,217,255,0.2);backdrop-filter:blur(10px);'>
            <div style='display:flex;align-items:center;gap:14px'>
                <div style='width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg, #00d9ff, #3a86ff);display:flex;align-items:center;justify-content:center;font-weight:800;color:#0a0e27;font-size:20px;letter-spacing:-1px;font-family:Space Mono,monospace'>TI</div>
                <div>
                    <div style='font-size:20px;font-weight:800;color:#f0f3ff;font-family:Inter,sans-serif;letter-spacing:-0.5px'>Threat Intel Integrator</div>
                    <div style='font-size:12px;color:#a8adbd;font-family:Inter,sans-serif;letter-spacing:0.5px'>🔍 IP & Domain Analysis | AbuseIPDB • VirusTotal • AlienVault OTX</div>
                </div>
            </div>
            <div style='display:flex;align-items:center;gap:12px'>
                <div style='color:#a8adbd;font-size:12px;font-family:Inter,sans-serif'>User: <b style='color:#00d9ff;font-weight:700'>{st.session_state.get('user') or 'guest'}</b></div>
                <button onclick="window.location.reload();" style='background:linear-gradient(135deg, #00d9ff, #3a86ff);border:none;padding:8px 14px;border-radius:8px;color:#0a0e27;font-weight:700;cursor:pointer;font-family:Inter,sans-serif;transition:0.3s;'>Refresh</button>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    db = ThreatDatabase()
    API_URL = os.getenv('TI_API_URL') or os.getenv('TI_API') or 'http://127.0.0.1:8000'

    def api_search(q: str = '', type_: str = 'Any', limit: int = 1000):
        try:
            resp = requests.get(f"{API_URL}/search", params={'q': q, 'type': type_, 'limit': limit}, timeout=5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    if 'user' not in st.session_state:
        st.session_state['user'] = None

    if st.session_state.get('user'):
        with st.sidebar:
            st.header('User')
            st.write(f"Signed in as: {st.session_state['user']}")
            if st.button('Logout', key='logout_button'):
                st.session_state['user'] = None

    if not st.session_state.get('user'):
        cols = st.columns([1, 2, 1])
        with cols[1]:
            st.markdown("<h2>Welcome — please login or register</h2>", unsafe_allow_html=True)
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
            else:
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
        return

    # Load data
    data = None
    api_data = api_search(q='', type_='Any', limit=10000)
    if api_data:
        if isinstance(api_data, dict):
            if 'items' in api_data and isinstance(api_data['items'], list):
                data = api_data['items']
            elif 'indicator' in api_data:
                data = [api_data]
            else:
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
        st.warning("⚠️ No threat data available.")
        st.info("Run: `python main.py` to analyze indicators")
        return

    df = pd.DataFrame(data)

    # Search box
    search_cols = st.columns([3, 1])
    with search_cols[0]:
        search = st.text_input("Search", placeholder="enter IP or domain")
    with search_cols[1]:
        search_type = st.selectbox("Type", options=["Any", "IP", "Domain"])

    # Show sample suggestions
    with st.expander("💡 **Try these samples:**", expanded=False):
        st.markdown("""
        **Benign (Safe):**
        - `google.com` — Popular search engine
        - `github.com` — Code repository
        - `1.1.1.1` — Cloudflare DNS
        - `8.8.4.4` — Google DNS
        
        **Suspicious/Malicious (Test Cases):**
        - `malware-example.com` — Example malware site
        - `phishing-site.net` — Phishing threat
        - `c2-command.evil.com` — Command & Control
        - `203.0.113.45` — Botnet IP
        - `spam-server.suspicious.org` — Spam/Fraud
        """)
        st.info("👉 Click on any sample above and paste it into the search box to try it out!")

    def infer_indicator_type(txt: str):
        if not txt:
            return None
        s = txt.strip()
        import ipaddress as _ip
        try:
            _ip.ip_address(s)
            return 'IP'
        except Exception:
            pass
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
            try:
                mask = df['indicator'].astype(str).str.lower().str.contains(s_low, na=False)
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

    # Sidebar filters
    st.sidebar.header("🔧 Filters")
    try:
        if 'classification' in df.columns:
            class_options = sorted([c for c in df['classification'].dropna().unique()])
        else:
            class_options = []
        selected_classes = st.sidebar.multiselect('Classification', options=class_options, default=class_options, key='filter_class')

        if 'threat_score' in df.columns and not df['threat_score'].isnull().all():
            min_score = float(df['threat_score'].min())
            max_score = float(df['threat_score'].max())
        else:
            min_score, max_score = 0.0, 100.0
        score_lo, score_hi = st.sidebar.slider('Threat score range', min_value=0.0, max_value=100.0, value=(min_score, max_score), step=1.0, key='filter_score')

        if 'category' in df.columns:
            incoming_cats = [normalize_category(c) for c in df['category'].dropna().unique()]
            cat_options = sorted(set(incoming_cats) | set(CATEGORY_CHOICES))
        else:
            cat_options = sorted(CATEGORY_CHOICES)
        selected_cats = st.sidebar.multiselect('Category', options=cat_options, default=cat_options, key='filter_cat')

        filtered_df = df.copy()
        if selected_classes:
            filtered_df = filtered_df[filtered_df['classification'].isin(selected_classes)]
        if 'threat_score' in filtered_df.columns:
            filtered_df['threat_score'] = pd.to_numeric(filtered_df['threat_score'], errors='coerce').fillna(0)
            filtered_df = filtered_df[(filtered_df['threat_score'] >= score_lo) & (filtered_df['threat_score'] <= score_hi)]
        if selected_cats:
            filtered_df['category'] = filtered_df.get('category', '').apply(lambda v: normalize_category(v) if v is not None else v)
            filtered_df = filtered_df[filtered_df['category'].isin(selected_cats)]
    except Exception:
        filtered_df = df.copy()

    if st.sidebar.button('Reset Filters', key='reset_filters_button'):
        rerun = getattr(st, 'experimental_rerun', None)
        if callable(rerun):
            rerun()

    if 'filtered_df' not in locals():
        filtered_df = df.copy()

    col_left, col_right = st.columns([3, 1])

    with col_right:
        st.subheader("📈 Threat Score Distribution")
        fig2 = px.histogram(df, x='threat_score', nbins=20, title='Distribution', color_discrete_sequence=['#636EFA'])
        fig2.update_layout(xaxis_title="Threat Score", yaxis_title="Count", showlegend=False, template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")

    st.subheader("🔍 Multi-Source Score Comparison")
    score_df = df[['indicator', 'abuseipdb_score', 'virustotal_score', 'otx_score']].head(10)
    fig3 = go.Figure()
    fig3.add_trace(go.Bar(name='AbuseIPDB', x=score_df['indicator'], y=score_df['abuseipdb_score'], marker_color='#FF6B6B'))
    fig3.add_trace(go.Bar(name='VirusTotal', x=score_df['indicator'], y=score_df['virustotal_score'], marker_color='#4ECDC4'))
    fig3.add_trace(go.Bar(name='AlienVault OTX', x=score_df['indicator'], y=score_df['otx_score'], marker_color='#95E1D3'))
    fig3.update_layout(barmode='group', xaxis_title="Indicator", yaxis_title="Threat Score", hovermode='x unified', template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
    st.plotly_chart(fig3, use_container_width=True)

    st.markdown("---")

    st.subheader("📋 Detailed Threat Intelligence Data")
    st.sidebar.markdown(f"**Showing {len(filtered_df)} of {len(df)} indicators**")

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
        html = f"<div style='background:transparent;padding:6px;border-radius:8px'>{df_html}</div>"
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
            rows.append(f"<tr><td>{r.get('indicator','')}</td><td>{r.get('timestamp','')}</td><td>{r.get('threat_score','')}</td><td>{r.get('classification','')}</td><td>{r.get('country','')}</td><td>{r.get('isp','')}</td><td>{r.get('abuseipdb_score','')}</td><td>{r.get('virustotal_score','')}</td><td><span class='badge {badge_class}'>{r.get('category','')}</span></td></tr>")
        header = "<table class='styled-table'><thead><tr><th>Indicator</th><th>Timestamp</th><th>Score</th><th>Classification</th><th>Country</th><th>ISP</th><th>AbuseIPDB</th><th>VirusTotal</th><th>Category</th></tr></thead><tbody>"
        footer = "</tbody></table>"
        return header + '\n'.join(rows) + footer

    table_html = df_to_html_table(display_df.head(200))
    render_styled_table(table_html)

    csv = display_df.to_csv(index=False)
    st.download_button(label="📥 Download Data as CSV", data=csv, file_name="threat_intel_data.csv", mime="text/csv")

    st.markdown("---")
    st.markdown("*Dashboard created with Streamlit | Data sources: AbuseIPDB, VirusTotal, AlienVault OTX*")


if __name__ == "__main__":
    run_dashboard()
