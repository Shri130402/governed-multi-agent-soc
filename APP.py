from db_store import (
    save_investigation,
    save_decision,
    load_investigations,
    load_audit_logs
)
import requests
import streamlit as st
import pandas as pd
from datetime import datetime
from agent_engine import generate_investigation

N8N_WEBHOOK_URL = "http://localhost:5678/webhook-test/soc-alert"
N8N_DECISION_WEBHOOK_URL = "http://localhost:5678/webhook-test/soc-decision"

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="SOC Command Center",
    page_icon="",
    layout="wide"
)

# ---------------- CUSTOM STYLING ----------------
st.markdown("""
<style>
.stApp {
    background-color: #0b1120;
    color: #e5e7eb;
}
[data-testid="stSidebar"] {
    background-color: #111827;
}
.block-container {
    padding-top: 1.5rem;
}
h1, h2, h3 {
    color: #f8fafc !important;
}
div[data-testid="stMetric"] {
    background: #151f32;
    border: 1px solid #263449;
    padding: 18px;
    border-radius: 12px;
}
div[data-testid="stMetricLabel"] {
    color: #9ca3af;
}
div[data-testid="stMetricValue"] {
    color: #f8fafc;
}
.stButton > button {
    background-color: #2563eb;
    color: white;
    border: none;
    border-radius: 8px;
    padding: 0.55rem 1rem;
    font-weight: 600;
}
.stButton > button:hover {
    background-color: #1d4ed8;
    color: white;
}
div[data-testid="stForm"] {
    background-color: #111b2e;
    padding: 20px;
    border: 1px solid #263449;
    border-radius: 12px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- SESSION DATA ----------------

# ---------------- SESSION DATA ----------------
if "alerts" not in st.session_state:
    st.session_state.alerts = [
        {
            "Alert ID": "SOC-1001",
            "Alert Type": "Suspicious Login",
            "Asset": "Production Server",
            "Severity": "High",
            "Status": "Under Investigation",
            "Time": "09:15"
        },
        {
            "Alert ID": "SOC-1002",
            "Alert Type": "Malware Detection",
            "Asset": "Employee Laptop",
            "Severity": "Critical",
            "Status": "Open",
            "Time": "09:32"
        },
        {
            "Alert ID": "SOC-1003",
            "Alert Type": "Suspicious Network Traffic",
            "Asset": "Web Server",
            "Severity": "Medium",
            "Status": "Under Investigation",
            "Time": "10:05"
        },
        {
            "Alert ID": "SOC-1004",
            "Alert Type": "Privilege Escalation",
            "Asset": "Database Server",
            "Severity": "High",
            "Status": "Resolved",
            "Time": "10:20"
        }
    ]

if "investigations" not in st.session_state:
    st.session_state.investigations = {}

if "review_decisions" not in st.session_state:
    st.session_state.review_decisions = {}

# Load database records once per session
if "db_loaded" not in st.session_state:
    records = load_investigations()

    for record in records:
        alert = record["alert"]
        alert_id = record["alert_id"]

        if not any(
            a["Alert ID"] == alert_id
            for a in st.session_state.alerts
        ):
            st.session_state.alerts.append(alert)

        st.session_state.investigations[alert_id] = record["result"]

        if record["decision"] != "Awaiting review":
            st.session_state.review_decisions[alert_id] = {
                "decision": record["decision"],
                "note": record["note"],
                "time": record["reviewed_at"]
            }

    st.session_state.db_loaded = True


# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.title("SOC Center")
    st.caption("Security Operations")
    st.divider()

    page = st.radio(
        "Navigation",
        ["Overview", "Submit Alert", "Investigation History", "Audit Log"],
        label_visibility="collapsed"
    )

    st.divider()
    st.caption("Governed Multi-Agent AI System")
    st.caption("SOC Alert Triage & Investigation")



# ---------------- HEADER ----------------
st.title("SOC Command Center")
st.write("Centralized alert monitoring, triage, and incident investigation.")
st.divider()

alerts = st.session_state.alerts
df = pd.DataFrame(alerts)

# ---------------- OVERVIEW ----------------
if page == "Overview":
    st.subheader("Security Operations Overview")

    total = len(alerts)
    critical = sum(a["Severity"] == "Critical" for a in alerts)
    high = sum(a["Severity"] == "High" for a in alerts)
    open_alerts = sum(a["Status"] == "Open" for a in alerts)
    investigating = sum(
        a["Status"] == "Under Investigation" for a in alerts
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Alerts", total)
    c2.metric("Critical Alerts", critical)
    c3.metric("High Severity", high)
    c4.metric("Open Alerts", open_alerts)

    st.divider()

    left, right = st.columns([1.4, 1])

    with left:
        st.subheader("Alert Queue")
        st.caption("Latest alerts received by the SOC")

        st.dataframe(
            df[["Alert ID", "Alert Type", "Asset", "Severity", "Status", "Time"]],
            use_container_width=True,
            hide_index=True
        )

    with right:
        st.subheader("Investigation Status")
        st.metric("Under Investigation", investigating)
        resolved = sum(a["Status"] == "Resolved" for a in alerts)
        st.metric("Resolved Alerts", resolved)

        st.subheader("Severity Distribution")
        severity_counts = (
            df["Severity"]
            .value_counts()
            .reindex(["Critical", "High", "Medium", "Low"], fill_value=0)
        )
        severity_df = severity_counts.rename_axis("Severity").reset_index(name="Count")
        st.bar_chart(severity_df.set_index("Severity"))

    st.divider()
    st.caption(
        "Note: The dashboard currently uses demonstration data. "
        "Automated triage and agent-based investigation will be integrated later."
    )

# ---------------- ALERT SUBMISSION ----------------

elif page == "Submit Alert":
    st.subheader("Submit a Security Alert")
    st.write("Enter the alert details to initiate an investigation.")

    with st.form("alert_submission", clear_on_submit=True):
        col1, col2 = st.columns(2)

        with col1:
            alert_type = st.selectbox(
                "Alert Type",
                [
                    "Suspicious Login",
                    "Malware Detection",
                    "Suspicious Network Traffic",
                    "Privilege Escalation",
                    "Unauthorized Access",
                    "Data Exfiltration"
                ]
            )

            asset = st.text_input(
                "Affected Asset",
                placeholder="e.g. Production Server"
            )

        with col2:
            severity = st.selectbox(
                "Severity",
                ["Critical", "High", "Medium", "Low"]
            )

            source = st.text_input(
                "Alert Source",
                placeholder="e.g. Firewall, SIEM, EDR"
            )

        description = st.text_area(
            "Alert Details",
            placeholder="Describe the suspicious activity..."
        )

        submitted = st.form_submit_button(
            "Start Investigation",
            use_container_width=True
        )

    if submitted:
        if not asset.strip() or not description.strip():
            st.warning("Please provide the affected asset and alert details.")
        else:
            next_id = 1001 + len(st.session_state.alerts)

            new_alert = {
                "Alert ID": f"SOC-{next_id}",
                "Alert Type": alert_type,
                "Asset": asset.strip(),
                "Severity": severity,
                "Status": "Under Investigation",
                "Time": datetime.now().strftime("%H:%M"),
                "Details": description.strip(),
                "Source": source.strip()
            }

            # Run the multi-agent investigation
            with st.spinner("Agents are investigating the alert..."):
                result = generate_investigation(new_alert)

                            # Send investigation result to n8n
            n8n_payload = {
                "alert": new_alert,
                "risk": result["risk"],
                "analysis": result["analysis"],
                "threat_intelligence": result["threat_intelligence"],
                "asset_context": result["asset_context"],
                "recommendations": result["recommendations"],
                "retrieved_knowledge": result.get(
                    "retrieved_knowledge", []
                ),
                "status": result["status"]
            }

            try:
                n8n_response = requests.post(
                    N8N_WEBHOOK_URL,
                    json=n8n_payload,
                    timeout=10
                )

                if n8n_response.ok:
                    st.success("Investigation sent to n8n successfully.")
                else:
                    st.warning(
                        f"n8n returned HTTP {n8n_response.status_code}."
                    )

            except requests.RequestException as e:
                st.warning(
                    f"Could not connect to n8n: {e}"
                )

            # Update status based on the investigation
            new_alert["Status"] = result["status"]

            # Save alert and investigation result in session
            st.session_state.alerts.append(new_alert)
            st.session_state.investigations[new_alert["Alert ID"]] = result
            save_investigation(new_alert, result)

            st.success(
                f"Investigation completed for {new_alert['Alert ID']}."
            )

            # Display investigation results
            st.divider()
            st.subheader("Multi-Agent Investigation Results")

            risk = result["risk"]
            c1, c2, c3 = st.columns(3)

            c1.metric("Risk Score", f"{risk['risk_score']}/100")
            c2.metric("Priority", risk["priority"])
            c3.metric(
                "Asset Criticality",
                result["asset_context"]["criticality"]
            )

            st.info(f"Status: {result['status']}")

            st.subheader("Agent Findings")

            with st.expander("Alert Analysis Agent", expanded=True):
                st.write(result["analysis"]["observation"])
                for item in result["analysis"]["indicators"]:
                    st.markdown(f"- {item}")

            with st.expander("Threat Intelligence Agent"):
                st.write(
                    "Status:",
                    result["threat_intelligence"]["status"]
                )
                for item in result["threat_intelligence"]["findings"]:
                    st.markdown(f"- {item}")

            with st.expander("Asset Context Agent"):
                st.write(
                    "Asset:",
                    result["asset_context"]["asset"]
                )
                st.write(
                    "Criticality:",
                    result["asset_context"]["criticality"]
                )
                st.caption(result["asset_context"]["note"])

            with st.expander("Risk Prioritisation Agent", expanded=True):
                st.write(f"Risk score: {risk['risk_score']}/100")
                st.write(f"Priority: {risk['priority']}")
                st.write(
                    "Human review required:",
                    "Yes" if risk["requires_human_review"] else "No"
                )


            st.subheader("Evidence & Explainability")

            agent_details = [
                ("Alert Analysis Agent", result["analysis"]),
                ("Threat Intelligence Agent", result["threat_intelligence"]),
                ("Asset Context Agent", result["asset_context"]),
                ("Risk Prioritisation Agent", result["risk"])
            ]

            for agent_name, agent_data in agent_details:
                with st.expander(agent_name + " - Evidence"):
                    st.write("**Reasoning:**")
                    st.write(
                        agent_data.get(
                            "reasoning",
                            "Reasoning not available for this record."
                        )
                    )

                    st.write("**Supporting Evidence:**")
                    evidence = agent_data.get("evidence", [])

                    if evidence:
                        for item in evidence:
                            st.markdown(f"- {item}")
                    else:
                        st.info("No direct evidence matched.")

                    confidence = agent_data.get("confidence")
                    if confidence is not None:
                        st.write(f"**Rule-based confidence: {confidence}%**")
                        st.progress(int(confidence))

            st.subheader("Risk Score Breakdown")
            risk_factors = risk.get("risk_factors", [])

            if risk_factors:
                st.dataframe(
                    pd.DataFrame(risk_factors),
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("Risk breakdown is unavailable for this record.")


        st.subheader("Knowledge Base References")

        knowledge = result.get("retrieved_knowledge", [])

        if knowledge:
            for i, item in enumerate(knowledge, start=1):
                with st.expander(
                    f"Reference {i}: {item.get('source', 'Knowledge document')}"
                ):
                    st.write(item.get("text", "No text available"))
                    st.caption(
                        f"Similarity distance: "
                        f"{item.get('distance', 0):.4f}"
                    )
        else:
            st.info(
                "No knowledge references are available for this investigation."
            )



            st.subheader("Recommended Actions")
            for i, recommendation in enumerate(
                result["recommendations"], start=1
            ):
                st.markdown(f"{i}. {recommendation}")

            st.caption(result["disclaimer"])



elif page == "Investigation History":
    st.subheader("Investigation History")
    st.write("Review investigated alerts and record analyst decisions.")

    alerts = st.session_state.alerts
    investigations = st.session_state.investigations

    if not investigations:
        st.info("No investigations available. Submit an alert first.")
    else:
        alert_ids = list(investigations.keys())

        history_rows = []
        for alert_id in alert_ids:
            alert = next(
                (a for a in alerts if a["Alert ID"] == alert_id),
                {}
            )
            result = investigations[alert_id]
            decision = st.session_state.review_decisions.get(alert_id, {})

            history_rows.append({
                "Alert ID": alert_id,
                "Alert Type": alert.get("Alert Type", "Unknown"),
                "Asset": alert.get("Asset", "Unknown"),
                "Priority": result["risk"]["priority"],
                "Risk Score": result["risk"]["risk_score"],
                "Status": decision.get(
                    "decision", result.get("status", "Awaiting review")
                )
            })

        st.dataframe(
            pd.DataFrame(history_rows),
            use_container_width=True,
            hide_index=True
        )

        st.divider()
        st.subheader("Analyst Review")

        selected_id = st.selectbox("Select an alert", alert_ids)

        result = investigations[selected_id]
        alert = next(
            (a for a in alerts if a["Alert ID"] == selected_id),
            {}
        )
        risk = result["risk"]

        st.write("**Alert Type:**", alert.get("Alert Type", "Unknown"))
        st.write("**Affected Asset:**", alert.get("Asset", "Unknown"))
        st.write("**Severity:**", alert.get("Severity", "Unknown"))
        st.write("**Details:**", alert.get("Details", "Not available"))

        c1, c2, c3 = st.columns(3)
        c1.metric("Risk Score", f"{risk['risk_score']}/100")
        c2.metric("Priority", risk["priority"])
        c3.metric(
            "Asset Criticality",
            result["asset_context"]["criticality"]
        )

        st.subheader("Agent Findings")

        with st.expander("Alert Analysis"):
            st.write(result["analysis"]["observation"])
            for finding in result["analysis"]["indicators"]:
                st.markdown(f"- {finding}")

        with st.expander("Threat Intelligence"):
            st.write(result["threat_intelligence"]["status"])
            for finding in result["threat_intelligence"]["findings"]:
                st.markdown(f"- {finding}")

        with st.expander("Recommendations"):
            for recommendation in result["recommendations"]:
                st.markdown(f"- {recommendation}")


        st.subheader("Evidence & Explainability")

        agent_details = [
            ("Alert Analysis Agent", result["analysis"]),
            ("Threat Intelligence Agent", result["threat_intelligence"]),
            ("Asset Context Agent", result["asset_context"]),
            ("Risk Prioritisation Agent", result["risk"])
        ]

        for agent_name, agent_data in agent_details:
            with st.expander(agent_name + " - Evidence"):
                st.write("**Reasoning:**")
                st.write(
                    agent_data.get(
                        "reasoning",
                        "Reasoning not available for this record."
                    )
                )

                st.write("**Supporting Evidence:**")
                evidence = agent_data.get("evidence", [])

                if evidence:
                    for item in evidence:
                        st.markdown(f"- {item}")
                else:
                    st.info("No direct evidence matched.")

                confidence = agent_data.get("confidence")
                if confidence is not None:
                    st.write(
                        f"**Rule-based confidence: {confidence}%**"
                    )
                    st.progress(int(confidence))

        st.subheader("Risk Score Breakdown")
        risk_factors = risk.get("risk_factors", [])

        if risk_factors:
            st.dataframe(
                pd.DataFrame(risk_factors),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("Risk breakdown is unavailable for this record.")


        previous = st.session_state.review_decisions.get(selected_id)
        if previous:
            st.info(
                f"Previous decision: {previous['decision']} "
                f"({previous['time']})"
            )

        st.subheader("Record Analyst Decision")

        note = st.text_area(
            "Analyst comments",
            placeholder="Explain the reason for your decision...",
            key=f"note_{selected_id}"
        )

        c1, c2, c3 = st.columns(3)

        with c1:
            approve = st.button("Approve", key=f"approve_{selected_id}")

        with c2:
            escalate = st.button("Escalate", key=f"escalate_{selected_id}")

        with c3:
            false_positive = st.button(
                "False Positive", key=f"fp_{selected_id}"
            )

        if approve or escalate or false_positive:
            if not note.strip():
                st.warning("Please enter analyst comments.")
            else:
                if approve:
                    decision = "Approved by Analyst"
                elif escalate:
                    decision = "Escalated for Further Review"
                else:
                    decision = "Marked as False Positive"

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                st.session_state.review_decisions[selected_id] = {
                    "decision": decision,
                    "note": note.strip(),
                    "time": timestamp
                }
                save_decision(selected_id, decision, note.strip())
            decision_payload = {
                "alert_id": selected_id,
                "decision": decision,
                "analyst_note": note.strip(),
                "reviewed_at": datetime.now().isoformat(timespec="seconds")
            }

            try:
                decision_response = requests.post(
                    N8N_DECISION_WEBHOOK_URL,
                    json=decision_payload,
                    timeout=10
                )

                if decision_response.ok:
                    st.success(
                        "Analyst decision sent to n8n successfully."
                    )
                else:
                    st.warning(
                        f"n8n decision webhook returned "
                        f"HTTP {decision_response.status_code}."
                    )

            except requests.RequestException as e:
                st.warning(
                    f"Could not send analyst decision to n8n: {e}"
                )

                for item in st.session_state.alerts:
                    if item["Alert ID"] == selected_id:
                        item["Status"] = decision
                        break

                st.success(f"Decision recorded: {decision}")
                st.rerun()



elif page == "Audit Log":
    st.subheader("Audit Log")
    st.write("Review recorded investigation and analyst activity.")

    logs = load_audit_logs()

    if logs:
        st.dataframe(
            pd.DataFrame(logs),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No audit events have been recorded yet.")


