import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from database import ThreatDatabase
import streamlit_authenticator as stauth
import sqlite3
import hashlib

def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        email TEXT PRIMARY KEY,
        password TEXT NOT NULL
    )''')
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(email, password):
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def authenticate_user(email, password):
    conn = get_db_connection()
    cursor = conn.execute("SELECT password FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    if row and row[0] == hash_password(password):
        return True
    return False

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_email" not in st.session_state:
    st.session_state["user_email"] = None

authenticated = st.session_state["authenticated"]
user_email = st.session_state["user_email"]

if not authenticated:
    st.title("Login or Register")
    menu = st.sidebar.selectbox("Menu", ["Login", "Register"], key="menu_select")
    if menu == "Register":
        st.subheader("Create a new account")
        email = st.text_input("Email", key="register_email")
        password = st.text_input("Password", type="password", key="register_password")
        if st.button("Register", key="register_btn"):
            if register_user(email, password):
                st.success("Registration successful! You can now log in.")
                st.session_state["authenticated"] = False
                st.session_state["user_email"] = None
                st.rerun()
            else:
                st.error("Email already registered.")
    elif menu == "Login":
        st.subheader("Login to your account")
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login", key="login_btn"):
            if authenticate_user(email, password):
                st.success(f"Welcome, {email}!")
                st.session_state["authenticated"] = True
                st.session_state["user_email"] = email
                st.rerun()
            else:
                st.error("Invalid email or password.")

if authenticated:
    st.set_page_config(
        page_title="Threat Intel Dashboard", 
        layout="wide",
        page_icon="🔒"
    )
    st.title("🔒 Threat Intelligence Feed Integrator")
    st.markdown("---")

    # Load data
    db = ThreatDatabase()
    data = db.get_all_threats()

    if not data:
        st.warning("⚠️ No threat data available. Please run the analysis first.")
        st.info("Run: `python main.py` to analyze indicators")
    else:
        df = pd.DataFrame(data)

        st.title("Threat Intelligence Dashboard")

        # Search and filter widgets
        indicator = st.text_input("Search by Indicator")
        email_search = st.text_input("Search for Malicious Activity by Email")
        classification = st.selectbox("Filter by Classification", ["All"] + (df["classification"].unique().tolist() if not df.empty else []))
        min_score, max_score = st.slider("Threat Score Range", 0, 100, (0, 100))

        # Apply filters
        filtered_df = df.copy()
        if indicator:
            filtered_df = filtered_df[filtered_df["indicator"].str.contains(indicator, case=False)]
        if email_search:
            email_results = filtered_df[filtered_df["indicator"].str.contains(email_search, case=False)]
            st.subheader(f"Malicious Activity for Email: {email_search}")
            if not email_results.empty:
                st.dataframe(email_results)
            else:
                st.info("No malicious activity found for this email.")
        if classification != "All" and not filtered_df.empty:
            filtered_df = filtered_df[filtered_df["classification"] == classification]
        if not filtered_df.empty:
            filtered_df = filtered_df[(filtered_df["threat_score"] >= min_score) & (filtered_df["threat_score"] <= max_score)]

        st.subheader("Filtered Threats")
        st.dataframe(filtered_df)

        # Visualization
        if not filtered_df.empty:
            fig = px.line(filtered_df, x="timestamp", y="threat_score", title="Threat Score Over Time")
            st.plotly_chart(fig)

            pie_fig = px.pie(filtered_df, names="classification", title="Classification Breakdown")
            st.plotly_chart(pie_fig)

            # Threat Score Distribution
            fig2 = px.histogram(
                filtered_df, 
                x='threat_score',
                nbins=20,
                title='Distribution of Threat Scores',
                color_discrete_sequence=['#636EFA']
            )
            fig2.update_layout(
                xaxis_title="Threat Score",
                yaxis_title="Count",
                showlegend=False
            )
            st.plotly_chart(fig2, use_container_width=True)

            st.markdown("---")

            # Source comparison
            st.subheader("🔍 Multi-Source Score Comparison")
            score_df = filtered_df[['indicator', 'abuseipdb_score', 'virustotal_score', 'otx_score']].head(10)
            fig3 = go.Figure()
            fig3.add_trace(go.Bar(
                name='AbuseIPDB',
                x=score_df['indicator'],
                y=score_df['abuseipdb_score'],
                marker_color='#FF6B6B'
            ))
            fig3.add_trace(go.Bar(
                name='VirusTotal',
                x=score_df['indicator'],
                y=score_df['virustotal_score'],
                marker_color='#4ECDC4'
            ))
            fig3.add_trace(go.Bar(
                name='AlienVault OTX',
                x=score_df['indicator'],
                y=score_df['otx_score'],
                marker_color='#95E1D3'
            ))
            fig3.update_layout(
                barmode='group',
                xaxis_title="Indicator",
                yaxis_title="Threat Score",
                hovermode='x unified'
            )
            st.plotly_chart(fig3, use_container_width=True)

            st.markdown("---")

            # Detailed data table
            st.subheader("📋 Detailed Threat Intelligence Data")
            st.sidebar.header("🔧 Filters")
            classification_options = st.sidebar.multiselect(
                "Classification",
                options=df['classification'].unique().tolist(),
                default=df['classification'].unique().tolist()
            )
            score_range = st.sidebar.slider(
                "Threat Score Range",
                min_value=0,
                max_value=100,
                value=(0, 100)
            )
            filtered_df_sidebar = df[
                (df['classification'].isin(classification_options)) &
                (df['threat_score'] >= score_range[0]) &
                (df['threat_score'] <= score_range[1])
            ]
            st.sidebar.markdown(f"**Showing {len(filtered_df_sidebar)} of {len(df)} indicators**")
            display_df = filtered_df_sidebar[[
                'indicator', 'timestamp', 'threat_score', 'classification',
                'country', 'isp', 'abuseipdb_score', 'virustotal_score', 'otx_score'
            ]].sort_values('threat_score', ascending=False)
            st.dataframe(
                display_df,
                use_container_width=True,
                height=400
            )
            csv = display_df.to_csv(index=False)
            st.download_button(
                label="📥 Download Data as CSV",
                data=csv,
                file_name="threat_intel_data.csv",
                mime="text/csv"
            )
            st.markdown("---")
            st.markdown("*Dashboard created with Streamlit | Data sources: AbuseIPDB, VirusTotal, AlienVault OTX*")
        else:
            st.write("No data to visualize.")