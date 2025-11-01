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
    custom_css = '''
    <style>
    :root{ --accent:#7c3aed; --accent-2:#06b6d4; --muted:#94a3b8 }
    .custom-header{display:flex;align-items:center;gap:12px;margin-bottom:8px}
    .brand-pill{background:linear-gradient(90deg,var(--accent),var(--accent-2));padding:6px 10px;border-radius:8px;color:white;font-weight:700}
    .subtle{color:var(--muted);font-size:13px}
    .metric-card{background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));padding:12px;border-radius:8px;color:#e6eef8}
    .metric-value{font-size:18px;font-weight:700}
    .metric-label{font-size:12px;color:var(--muted)}
    .styled-table{border-collapse:collapse;width:100%;font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial}
    .styled-table th,.styled-table td{padding:8px;border-bottom:1px solid rgba(255,255,255,0.03);text-align:left}
    .badge{padding:4px 8px;border-radius:6px;color:#fff;font-size:12px}
    .badge-phishing{background:#ef4444}
    .badge-malware{background:#f97316}
    .badge-suspicious{background:#f59e0b}
    .badge-benign{background:#10b981}
    </style>
    '''
    st.markdown(custom_css, unsafe_allow_html=True)

    # Header
    st.markdown(
        """
        <div class='custom-header'>
          <div class='brand-pill'>TI Integrator</div>
          <div>
            <div style='font-size:18px;font-weight:700'>🔒 Threat Intelligence Feed Integrator</div>
            <div class='subtle'>Consolidated indicators • AbuseIPDB • VirusTotal • AlienVault OTX</div>
          </div>
        </div>
        <hr />
        """,
        unsafe_allow_html=True,
    )

    # Database and auth
    db = ThreatDatabase()

    if 'user' not in st.session_state:
        st.session_state['user'] = None

    # Sidebar user area
    if st.session_state.get('user'):
        with st.sidebar:
            st.header('User')
            st.write(f"Signed in as: {st.session_state['user']}")
            if st.button('Logout'):
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
                        if db.verify_user(email, password):
                            st.session_state['user'] = email
                            st.success('Logged in')
                            rerun = getattr(st, 'experimental_rerun', None)
                            if callable(rerun):
                                rerun()
                            else:
                                try:
                                    existing = dict(getattr(st, 'query_params', {}) or {})
                                    existing['_login'] = str(int(__import__('time').time()))
                                    if hasattr(st, 'query_params'):
                                        st.query_params = existing
                                        return
                                    set_qp = getattr(st, 'experimental_set_query_params', None)
                                    if callable(set_qp):
                                        set_qp(_login=existing['_login'])
                                        return
                                except Exception:
                                    return
                        else:
                            st.error('Invalid credentials')

            else:
                with st.form('register_form'):
                    r_email = st.text_input('Email', key='r_email')
                    r_password = st.text_input('Password', type='password', key='r_password')
                    r_password2 = st.text_input('Confirm Password', type='password', key='r_password2')
                    reg_sub = st.form_submit_button('Register')
                    if reg_sub:
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

    # Load data
    data = db.get_all_threats()
    if not data:
        st.warning("⚠️ No threat data available. Please run the analysis first.")
        st.info("Run: `python main.py` to analyze indicators")
        return

    df = pd.DataFrame(data)

    import ipaddress

    # Search box
    search_cols = st.columns([3, 1])
    with search_cols[0]:
        search = st.text_input("Search", placeholder="enter IP, domain, or email (or free text)")
    with search_cols[1]:
        search_type = st.selectbox("Type", options=["Any", "IP", "Domain", "Email"])    

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
        if inferred in {'IP', 'Email', 'Domain'}:
            exact = df[df['indicator'].astype(str).str.lower().str.strip() == s_low]
            st.markdown("### Quick verdict")
            if len(exact):
                row = exact.sort_values('timestamp', ascending=False).iloc[0]
                verdict, emoji = verdict_from_row(row)
                st.success(f"{emoji} {inferred} detected. Verdict: {verdict} | Score: {row.get('threat_score', 0)} | Class: {row.get('classification', 'Unknown')} | Category: {row.get('category', 'unknown')}")
            else:
                st.info(f"No exact {inferred.lower()} match found in database for '{s_raw}'.")
                if inferred == 'IP':
                    load_dotenv()
                    if st.button('Analyze now (IP only)'):
                        with st.spinner('Analyzing via AbuseIPDB / VirusTotal / OTX ...'):
                            api = ThreatIntelAPI(
                                abuse_key=os.getenv('ABUSEIPDB_KEY'),
                                vt_key=os.getenv('VIRUSTOTAL_KEY'),
                                otx_key=os.getenv('OTX_KEY')
                            )
                            processor = ThreatProcessor()
                            results = api.fetch_all_sources(s_raw)
                            analysis = processor.calculate_consensus(results)
                            enriched = processor.enrich_data(s_raw, analysis)
                            db.insert_threat(enriched)
                        rerun = getattr(st, 'experimental_rerun', None)
                        if callable(rerun):
                            rerun()
                        else:
                            try:
                                existing = dict(getattr(st, 'query_params', {}) or {})
                                existing['_analyze'] = str(int(__import__('time').time()))
                                if hasattr(st, 'query_params'):
                                    st.query_params = existing
                                else:
                                    set_qp = getattr(st, 'experimental_set_query_params', None)
                                    if callable(set_qp):
                                        set_qp(_analyze=existing['_analyze'])
                            except Exception:
                                pass

    # Sidebar filters
    st.sidebar.header("🔧 Filters")

    # Reset filters button
    if st.sidebar.button('Reset Filters'):
        try:
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
        except Exception:
            pass

    classification_options = st.sidebar.multiselect(
        "Classification",
        options=df['classification'].unique().tolist(),
        default=df['classification'].unique().tolist()
    )

    canonical_categories = [
        'Phishing', 'Credential Harvest', 'Typosquatting', 'Scam', 'Spam',
        'Malware', 'Ransomware', 'C2', 'Botnet', 'Exploit', 'Privacy Leak',
        'Suspicious', 'Unknown'
    ]

    category_options = st.sidebar.multiselect(
        "Category",
        options=canonical_categories,
        default=canonical_categories
    )

    score_range = st.sidebar.slider(
        "Threat Score Range",
        min_value=0,
        max_value=100,
        value=(0, 100)
    )

    # Build mask in a robust way (avoid mixing Python bool with pandas StringMethods)
    mask = pd.Series([True] * len(df), index=df.index)
    if search and search.strip():
        s = search.strip()
        if search_type == 'IP':
            try:
                ipaddress.ip_address(s)
                mask = df['indicator'].astype(str) == s
            except ValueError:
                st.error('Invalid IP address format')
                mask = pd.Series([False] * len(df), index=df.index)
        elif search_type == 'Domain':
            s_low = s.lower()
            m = pd.Series([False] * len(df), index=df.index)
            m |= df['indicator'].astype(str).str.lower().str.contains(s_low, na=False)
            m |= df['indicator'].astype(str).str.lower().str.endswith('.' + s_low)
            m |= df['indicator'].astype(str).str.lower() == s_low
            m |= df['isp'].astype(str).str.lower().str.contains(s_low, na=False)
            mask = m
        elif search_type == 'Email':
            s_low = s.lower()
            m = pd.Series([False] * len(df), index=df.index)
            m |= df['indicator'].astype(str).str.lower().str.strip() == s_low
            m |= df['indicator'].astype(str).str.lower().str.contains(s_low, na=False)
            m |= df['usage_type'].astype(str).str.lower().str.contains(s_low, na=False)
            mask = m
        else:
            s_low = s.lower()
            m = pd.Series([False] * len(df), index=df.index)
            m |= df['indicator'].astype(str).str.lower().str.contains(s_low, na=False)
            m |= df['country'].astype(str).str.lower().str.contains(s_low, na=False)
            m |= df['isp'].astype(str).str.lower().str.contains(s_low, na=False)
            m |= df['usage_type'].astype(str).str.lower().str.contains(s_low, na=False)
            m |= df['classification'].astype(str).str.lower().str.contains(s_low, na=False)
            m |= df.get('tags', pd.Series([''] * len(df))).astype(str).str.lower().str.contains(s_low, na=False)
            m |= df.get('source', pd.Series([''] * len(df))).astype(str).str.lower().str.contains(s_low, na=False)
            m |= df.get('category', pd.Series([''] * len(df))).astype(str).str.lower().str.contains(s_low, na=False)
            mask = m

    # Combine filters
    cat_series = df['category'].fillna('unknown').astype(str).str.replace('_', ' ').str.strip().str.title()
    selected_lower = [c.lower() for c in category_options]
    filtered_df = df[
        (mask) &
        (df['classification'].isin(classification_options)) &
        (cat_series.str.lower().isin(selected_lower)) &
        (df['threat_score'] >= score_range[0]) &
        (df['threat_score'] <= score_range[1])
    ].copy()

    filtered_df['category_display'] = filtered_df['category'].fillna('unknown').astype(str).str.replace('_', ' ').str.strip().str.title()

    if search and search.strip() and len(filtered_df) == 0:
        st.info(f"No results found for '{search.strip()}'. Try adjusting the search type or widening the score range.")

    # Metrics
    st.subheader("📊 Overview Metrics")
    col1, col2, col3, col4 = st.columns(4)

    def metric_card(label, value, hint=''):
        return f"""
        <div class='metric-card'>
          <div class='metric-value'>{value}</div>
          <div class='metric-label'>{label} {hint}</div>
        </div>
        """

    with col1:
        components.html(metric_card('Total Indicators', len(filtered_df)), height=70)
    with col2:
        malicious_count = len(filtered_df[filtered_df['classification'] == 'Malicious'])
        components.html(metric_card('Malicious', malicious_count), height=70)
    with col3:
        suspicious_count = len(filtered_df[filtered_df['classification'] == 'Suspicious'])
        components.html(metric_card('Suspicious', suspicious_count), height=70)
    with col4:
        avg_score = filtered_df['threat_score'].mean() if len(filtered_df) else 0.0
        components.html(metric_card('Avg Threat Score', f"{avg_score:.1f}"), height=70)

    st.markdown("---")

    # Charts
    col_left, col_right = st.columns(2)
    with col_left:
        st.subheader("🎯 Threat Classification Distribution")
        classification_counts = df['classification'].value_counts()
        fig1 = px.pie(
            values=classification_counts.values,
            names=classification_counts.index,
            title='Threat Categories',
            color=classification_counts.index,
            color_discrete_map={
                'Malicious': '#ff4444',
                'Suspicious': '#ffaa00',
                'Benign': '#44ff44'
            }
        )
        fig1.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig1, use_container_width=True)

    with col_right:
        st.subheader("📈 Threat Score Distribution")
        fig2 = px.histogram(df, x='threat_score', nbins=20, title='Distribution of Threat Scores', color_discrete_sequence=['#636EFA'])
        fig2.update_layout(xaxis_title="Threat Score", yaxis_title="Count", showlegend=False)
        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")

    # Source comparison
    st.subheader("🔍 Multi-Source Score Comparison")
    score_df = df[['indicator', 'abuseipdb_score', 'virustotal_score', 'otx_score']].head(10)
    fig3 = go.Figure()
    fig3.add_trace(go.Bar(name='AbuseIPDB', x=score_df['indicator'], y=score_df['abuseipdb_score'], marker_color='#FF6B6B'))
    fig3.add_trace(go.Bar(name='VirusTotal', x=score_df['indicator'], y=score_df['virustotal_score'], marker_color='#4ECDC4'))
    fig3.add_trace(go.Bar(name='AlienVault OTX', x=score_df['indicator'], y=score_df['otx_score'], marker_color='#95E1D3'))
    fig3.update_layout(barmode='group', xaxis_title="Indicator", yaxis_title="Threat Score", hovermode='x unified')
    st.plotly_chart(fig3, use_container_width=True)

    st.markdown("---")

    # Detailed table
    st.subheader("📋 Detailed Threat Intelligence Data")
    st.sidebar.markdown(f"**Showing {len(filtered_df)} of {len(df)} indicators**")

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
