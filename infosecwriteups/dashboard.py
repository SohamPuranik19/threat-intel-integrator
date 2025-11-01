import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from database import ThreatDatabase

def run_dashboard():
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
        return
    
    df = pd.DataFrame(data)
    
    # Top Metrics
    st.subheader("📊 Overview Metrics")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Indicators", len(df))
    with col2:
        malicious_count = len(df[df['classification'] == 'Malicious'])
        st.metric("Malicious", malicious_count, delta_color="inverse")
    with col3:
        suspicious_count = len(df[df['classification'] == 'Suspicious'])
        st.metric("Suspicious", suspicious_count, delta_color="off")
    with col4:
        avg_score = df['threat_score'].mean()
        st.metric("Avg Threat Score", f"{avg_score:.1f}")
    
    st.markdown("---")
    
    # Charts section
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
        fig2 = px.histogram(
            df, 
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
    
    # Prepare data for comparison
    score_df = df[['indicator', 'abuseipdb_score', 'virustotal_score', 'otx_score']].head(10)
    
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
    
    # Sidebar filters
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
    
    # Apply filters
    filtered_df = df[
        (df['classification'].isin(classification_options)) &
        (df['threat_score'] >= score_range[0]) &
        (df['threat_score'] <= score_range[1])
    ]
    
    st.sidebar.markdown(f"**Showing {len(filtered_df)} of {len(df)} indicators**")
    
    # Display filtered table
    display_df = filtered_df[[
        'indicator', 'timestamp', 'threat_score', 'classification',
        'country', 'isp', 'abuseipdb_score', 'virustotal_score', 'otx_score'
    ]].sort_values('threat_score', ascending=False)
    
    st.dataframe(
        display_df,
        use_container_width=True,
        height=400
    )
    
    # Download button
    csv = display_df.to_csv(index=False)
    st.download_button(
        label="📥 Download Data as CSV",
        data=csv,
        file_name="threat_intel_data.csv",
        mime="text/csv"
    )
    
    # Footer
    st.markdown("---")
    st.markdown("*Dashboard created with Streamlit | Data sources: AbuseIPDB, VirusTotal, AlienVault OTX*")

if __name__ == "__main__":
    run_dashboard()
