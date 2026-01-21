"""
ExposureGraph Streamlit Dashboard.

Provides visual interface for exploring security assets and risk data.
"""

import json
import sys
from pathlib import Path

import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.graph.client import Neo4jClient
from src.graph.models import WebService
from src.ai.graph_agent import GraphQueryAgent
from src.ai.llm_client import LLMClient, LLMConnectionError

# =============================================================================
# Page Configuration
# =============================================================================

st.set_page_config(
    page_title="ExposureGraph",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =============================================================================
# Custom CSS for Professional Styling
# =============================================================================

st.markdown(
    """
    <style>
    /* Main container */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }

    /* Metric cards */
    div[data-testid="metric-container"] {
        background-color: rgba(28, 131, 225, 0.1);
        border: 1px solid rgba(28, 131, 225, 0.2);
        border-radius: 0.5rem;
        padding: 1rem;
    }

    /* Headers */
    h1 {
        color: #1f77b4;
    }

    /* Risk score badges */
    .risk-critical {
        background-color: #dc3545;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-weight: bold;
    }
    .risk-high {
        background-color: #fd7e14;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-weight: bold;
    }
    .risk-medium {
        background-color: #ffc107;
        color: black;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-weight: bold;
    }
    .risk-low {
        background-color: #28a745;
        color: white;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-weight: bold;
    }

    /* Expander styling */
    .streamlit-expanderHeader {
        font-weight: 600;
    }

    /* Table styling */
    .dataframe {
        font-size: 0.9rem;
    }

    /* Chat message styling */
    .chat-message {
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 0.75rem;
        max-width: 85%;
    }
    .chat-message.user {
        background-color: #1f77b4;
        color: white;
        margin-left: auto;
        text-align: right;
    }
    .chat-message.assistant {
        background-color: #f0f2f6;
        color: #1f1f1f;
        margin-right: auto;
    }
    .chat-container {
        display: flex;
        flex-direction: column;
    }
    .suggested-question {
        margin: 0.25rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =============================================================================
# Helper Functions
# =============================================================================


@st.cache_resource
def get_neo4j_client() -> Neo4jClient:
    """Get cached Neo4j client connection."""
    client = Neo4jClient()
    client.connect()
    return client


def get_risk_level(score: int | None) -> tuple[str, str]:
    """Get risk level label and color from score.

    Args:
        score: Risk score 0-100.

    Returns:
        Tuple of (level_name, color_hex).
    """
    if score is None:
        return ("Unknown", "#6c757d")
    if score >= 70:
        return ("Critical", "#dc3545")
    if score >= 50:
        return ("High", "#fd7e14")
    if score >= 30:
        return ("Medium", "#ffc107")
    return ("Low", "#28a745")


def get_risk_distribution(services: list[WebService]) -> dict[str, int]:
    """Calculate risk distribution from services.

    Args:
        services: List of web services.

    Returns:
        Dict with counts for each risk level.
    """
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
    for svc in services:
        level, _ = get_risk_level(svc.risk_score)
        distribution[level] += 1
    return distribution


def get_technology_counts(services: list[WebService]) -> dict[str, int]:
    """Count technology occurrences across services.

    Args:
        services: List of web services.

    Returns:
        Dict mapping technology names to counts.
    """
    tech_counts: dict[str, int] = {}
    for svc in services:
        for tech in svc.technologies:
            tech_name = tech.strip()
            if tech_name:
                tech_counts[tech_name] = tech_counts.get(tech_name, 0) + 1
    return tech_counts


def parse_risk_factors(risk_factors_json: str | None) -> list[dict]:
    """Parse risk factors from JSON string.

    Args:
        risk_factors_json: JSON string of risk factors.

    Returns:
        List of risk factor dicts.
    """
    if not risk_factors_json:
        return []
    try:
        return json.loads(risk_factors_json)
    except json.JSONDecodeError:
        return []


# =============================================================================
# Sidebar Navigation
# =============================================================================

st.sidebar.title("🛡️ ExposureGraph")
st.sidebar.markdown("---")

page = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Assets", "Chat"],
    label_visibility="collapsed",
)

st.sidebar.markdown("---")
st.sidebar.markdown(
    """
    **ExposureGraph** transforms security
    reconnaissance into actionable insights.

    Built with Neo4j + Streamlit
    """
)


# =============================================================================
# Dashboard Page
# =============================================================================

def render_dashboard():
    """Render the main dashboard page."""
    st.title("📊 Security Dashboard")
    st.markdown("Overview of your attack surface and risk posture.")

    try:
        client = get_neo4j_client()
    except Exception as e:
        st.error(f"❌ Failed to connect to Neo4j: {e}")
        st.info("Make sure Neo4j is running: `docker-compose up -d`")
        return

    # Get data
    try:
        stats = client.get_stats()
        all_services = client.get_webservices_by_risk(min_score=0, limit=1000)
        top_risky = client.get_webservices_by_risk(min_score=0, limit=5)
    except Exception as e:
        st.error(f"❌ Failed to query data: {e}")
        return

    # Calculate average risk score
    scores = [s.risk_score for s in all_services if s.risk_score is not None]
    avg_risk = sum(scores) / len(scores) if scores else 0

    # ----- Metric Cards -----
    st.markdown("### Key Metrics")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            label="🌐 Domains",
            value=stats["domains"],
        )

    with col2:
        st.metric(
            label="🔗 Subdomains",
            value=stats["subdomains"],
        )

    with col3:
        st.metric(
            label="🖥️ Services",
            value=stats["webservices"],
        )

    with col4:
        risk_level, risk_color = get_risk_level(int(avg_risk) if avg_risk else None)
        st.metric(
            label="⚠️ Avg Risk Score",
            value=f"{avg_risk:.1f}",
            delta=risk_level,
            delta_color="inverse" if avg_risk >= 50 else "normal",
        )

    st.markdown("---")

    # ----- Charts Row -----
    col_left, col_right = st.columns(2)

    with col_left:
        st.markdown("### Risk Distribution")

        if all_services:
            distribution = get_risk_distribution(all_services)
            # Remove Unknown if 0
            if distribution.get("Unknown", 0) == 0:
                distribution.pop("Unknown", None)

            colors = {
                "Critical": "#dc3545",
                "High": "#fd7e14",
                "Medium": "#ffc107",
                "Low": "#28a745",
                "Unknown": "#6c757d",
            }

            fig = go.Figure(
                data=[
                    go.Pie(
                        labels=list(distribution.keys()),
                        values=list(distribution.values()),
                        hole=0.4,
                        marker_colors=[colors.get(k, "#6c757d") for k in distribution.keys()],
                        textinfo="label+value",
                        textposition="outside",
                    )
                ]
            )
            fig.update_layout(
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.2),
                margin=dict(t=20, b=20, l=20, r=20),
                height=350,
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No services found. Run a scan first.")

    with col_right:
        st.markdown("### Technologies Detected")

        if all_services:
            tech_counts = get_technology_counts(all_services)

            if tech_counts:
                # Sort and take top 10
                sorted_tech = sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                tech_names = [t[0] for t in sorted_tech]
                tech_values = [t[1] for t in sorted_tech]

                fig = go.Figure(
                    data=[
                        go.Bar(
                            x=tech_values,
                            y=tech_names,
                            orientation="h",
                            marker_color="#1f77b4",
                        )
                    ]
                )
                fig.update_layout(
                    xaxis_title="Count",
                    yaxis=dict(autorange="reversed"),
                    margin=dict(t=20, b=40, l=20, r=20),
                    height=350,
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No technologies detected yet.")
        else:
            st.info("No services found. Run a scan first.")

    st.markdown("---")

    # ----- Top 5 Riskiest Assets Table -----
    st.markdown("### 🔥 Top 5 Riskiest Assets")

    if top_risky:
        for svc in top_risky:
            level, color = get_risk_level(svc.risk_score)

            col1, col2, col3 = st.columns([1, 4, 1])

            with col1:
                st.markdown(
                    f'<span style="background-color:{color};color:white;'
                    f'padding:0.3rem 0.6rem;border-radius:0.25rem;font-weight:bold;">'
                    f'{svc.risk_score}</span>',
                    unsafe_allow_html=True,
                )

            with col2:
                st.markdown(f"**{svc.url}**")
                if svc.server:
                    st.caption(f"Server: {svc.server}")

            with col3:
                st.caption(f"Status: {svc.status_code}")

            # Show risk factors in expander
            factors = parse_risk_factors(svc.risk_factors)
            if factors:
                with st.expander("View Risk Factors"):
                    for factor in factors:
                        st.markdown(
                            f"**+{factor['contribution']}** - {factor['name']}"
                        )
                        st.caption(factor.get("explanation", ""))

            st.markdown("---")
    else:
        st.info("No services found. Run a scan to populate the graph.")


# =============================================================================
# Assets Page
# =============================================================================

def render_assets():
    """Render the assets exploration page."""
    st.title("🖥️ Assets Explorer")
    st.markdown("Search and explore all discovered web services.")

    try:
        client = get_neo4j_client()
    except Exception as e:
        st.error(f"❌ Failed to connect to Neo4j: {e}")
        st.info("Make sure Neo4j is running: `docker-compose up -d`")
        return

    # Get all services
    try:
        all_services = client.get_webservices_by_risk(min_score=0, limit=1000)
    except Exception as e:
        st.error(f"❌ Failed to query data: {e}")
        return

    if not all_services:
        st.info("No services found. Run a scan first: `python scripts/run_scan.py scan scanme.sh`")
        return

    # ----- Filters -----
    st.markdown("### Filters")
    col1, col2, col3 = st.columns(3)

    with col1:
        search_query = st.text_input(
            "🔍 Search URL",
            placeholder="Filter by URL...",
        )

    with col2:
        risk_filter = st.selectbox(
            "⚠️ Risk Level",
            ["All", "Critical (70+)", "High (50-69)", "Medium (30-49)", "Low (<30)"],
        )

    with col3:
        status_filter = st.selectbox(
            "📡 Status Code",
            ["All", "200 OK", "301/302 Redirect", "403 Forbidden", "404 Not Found", "Other"],
        )

    # Apply filters
    filtered_services = all_services

    if search_query:
        filtered_services = [
            s for s in filtered_services
            if search_query.lower() in s.url.lower()
        ]

    if risk_filter != "All":
        if risk_filter == "Critical (70+)":
            filtered_services = [s for s in filtered_services if s.risk_score and s.risk_score >= 70]
        elif risk_filter == "High (50-69)":
            filtered_services = [s for s in filtered_services if s.risk_score and 50 <= s.risk_score < 70]
        elif risk_filter == "Medium (30-49)":
            filtered_services = [s for s in filtered_services if s.risk_score and 30 <= s.risk_score < 50]
        elif risk_filter == "Low (<30)":
            filtered_services = [s for s in filtered_services if s.risk_score is None or s.risk_score < 30]

    if status_filter != "All":
        if status_filter == "200 OK":
            filtered_services = [s for s in filtered_services if s.status_code == 200]
        elif status_filter == "301/302 Redirect":
            filtered_services = [s for s in filtered_services if s.status_code in (301, 302)]
        elif status_filter == "403 Forbidden":
            filtered_services = [s for s in filtered_services if s.status_code == 403]
        elif status_filter == "404 Not Found":
            filtered_services = [s for s in filtered_services if s.status_code == 404]
        elif status_filter == "Other":
            filtered_services = [s for s in filtered_services if s.status_code not in (200, 301, 302, 403, 404)]

    st.markdown(f"**Showing {len(filtered_services)} of {len(all_services)} services**")
    st.markdown("---")

    # ----- Services List -----
    for svc in filtered_services:
        level, color = get_risk_level(svc.risk_score)

        # Header row
        header_col1, header_col2, header_col3, header_col4 = st.columns([1, 5, 2, 2])

        with header_col1:
            score_display = svc.risk_score if svc.risk_score is not None else "—"
            st.markdown(
                f'<div style="background-color:{color};color:white;'
                f'padding:0.4rem 0.6rem;border-radius:0.25rem;'
                f'font-weight:bold;text-align:center;font-size:1.1rem;">'
                f'{score_display}</div>',
                unsafe_allow_html=True,
            )

        with header_col2:
            st.markdown(f"**{svc.url}**")

        with header_col3:
            st.caption(f"Status: {svc.status_code}")
            if svc.title:
                st.caption(f"Title: {svc.title[:30]}...")

        with header_col4:
            if svc.server:
                st.caption(f"Server: {svc.server}")
            if svc.technologies:
                st.caption(f"Tech: {', '.join(svc.technologies[:3])}")

        # Expandable details
        with st.expander("📋 View Full Details"):
            detail_col1, detail_col2 = st.columns(2)

            with detail_col1:
                st.markdown("**Service Information**")
                st.write(f"- **URL:** {svc.url}")
                st.write(f"- **Status Code:** {svc.status_code}")
                st.write(f"- **Title:** {svc.title or 'N/A'}")
                st.write(f"- **Server:** {svc.server or 'N/A'}")
                st.write(f"- **Discovered:** {svc.discovered_at.strftime('%Y-%m-%d %H:%M')}")

                if svc.technologies:
                    st.markdown("**Technologies:**")
                    for tech in svc.technologies:
                        st.write(f"  - {tech}")

            with detail_col2:
                st.markdown("**Risk Analysis**")
                st.write(f"- **Risk Score:** {svc.risk_score or 'Not calculated'}")
                st.write(f"- **Risk Level:** {level}")

                factors = parse_risk_factors(svc.risk_factors)
                if factors:
                    st.markdown("**Contributing Factors:**")
                    for factor in factors:
                        factor_html = (
                            f"<div style='background-color:rgba(255,255,255,0.1);"
                            f"padding:0.5rem;border-radius:0.25rem;margin-bottom:0.5rem;"
                            f"border-left:3px solid {color};'>"
                            f"<strong>+{factor['contribution']}</strong> — {factor['name']}<br/>"
                            f"<small style='color:#888;'>{factor.get('explanation', '')}</small>"
                            f"</div>"
                        )
                        st.markdown(factor_html, unsafe_allow_html=True)
                else:
                    st.info("No risk factors calculated for this service.")

        st.markdown("---")


# =============================================================================
# Main Router
# =============================================================================

if page == "Dashboard":
    render_dashboard()
elif page == "Assets":
    render_assets()
