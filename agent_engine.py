
# agent_engine.py
# Evidence-backed simulated multi-agent investigation engine
# Uses Python rules, not an actual LLM or live threat intelligence.
from rag_engine import retrieve_knowledge
def find_evidence(details, keywords):
    """Return matched phrases from the alert details."""
    matches = []
    text = details.lower()

    for keyword in keywords:
        if keyword in text:
            start = text.find(keyword)
            matches.append(details[start:start + len(keyword)])

    return matches


def alert_analysis_agent(alert):
    """Identifies suspicious indicators and supporting evidence."""
    details = alert.get("Details", "")
    alert_type = alert.get("Alert Type", "Unknown")

    keywords = {
        "multiple failed login": "Possible brute-force activity",
        "unusual login": "Unusual authentication behaviour",
        "malware": "Possible malware activity",
        "ransomware": "Possible ransomware activity",
        "privilege escalation": "Possible privilege misuse",
        "data exfiltration": "Possible unauthorised data transfer",
        "suspicious ip": "Suspicious IP address mentioned",
        "unauthorized access": "Possible unauthorised access"
    }

    indicators = []
    evidence = []

    for keyword, finding in keywords.items():
        matches = find_evidence(details, [keyword])
        if matches:
            indicators.append(finding)
            evidence.extend(matches)

    if not indicators:
        indicators.append(
            "No specific indicator matched the simulated detection rules"
        )
        confidence = 35
        reasoning = (
            "No configured keyword was found in the alert details. "
            "This does not prove the alert is benign."
        )
    else:
        confidence = min(70 + (len(indicators) - 1) * 10, 90)
        reasoning = (
            "One or more configured keywords matched the alert details. "
            "These matches indicate activity that may need further review."
        )

    return {
        "agent": "Alert Analysis Agent",
        "alert_type": alert_type,
        "indicators": indicators,
        "observation": (
            f"Alert classified as {alert_type}. "
            "Review the listed indicators against supporting evidence."
        ),
        "evidence": evidence,
        "reasoning": reasoning,
        "confidence": confidence
    }


def threat_intel_agent(alert):
    """Checks alert details against illustrative threat indicators."""
    details = alert.get("Details", "")

    simulated_indicators = [
        "known malicious ip",
        "command and control",
        "c2 server",
        "malicious domain"
    ]

    matches = find_evidence(details, simulated_indicators)

    if matches:
        status = "Potential match"
        findings = matches
        confidence = 80
        reasoning = (
            "The alert details contain a phrase in the demonstration "
            "threat indicator list. This is not a verified threat match."
        )
    else:
        status = "No simulated match"
        findings = [
            "No match found in the demonstration indicator list"
        ]
        confidence = 40
        reasoning = (
            "No configured demonstration indicator matched. "
            "This does not establish that the activity is safe."
        )

    return {
        "agent": "Threat Intel Agent",
        "status": status,
        "findings": findings,
        "evidence": matches,
        "reasoning": reasoning,
        "confidence": confidence
    }


def asset_context_agent(alert):
    """Estimates asset criticality using its name."""
    asset_name = alert.get("Asset", "Unknown")
    asset = asset_name.lower()

    if any(word in asset for word in [
        "production", "database", "payment", "domain controller"
    ]):
        criticality = "Critical"
        matched_terms = [
            word for word in [
                "production", "database", "payment", "domain controller"
            ] if word in asset
        ]
        confidence = 75
    elif any(word in asset for word in [
        "server", "application", "web"
    ]):
        criticality = "High"
        matched_terms = [
            word for word in ["server", "application", "web"]
            if word in asset
        ]
        confidence = 70
    elif any(word in asset for word in [
        "employee", "laptop", "workstation"
    ]):
        criticality = "Medium"
        matched_terms = [
            word for word in ["employee", "laptop", "workstation"]
            if word in asset
        ]
        confidence = 65
    else:
        criticality = "Unclassified"
        matched_terms = []
        confidence = 30

    return {
        "agent": "Asset Context Agent",
        "asset": asset_name,
        "criticality": criticality,
        "note": (
            "Criticality is estimated from the asset name for this demo. "
            "A real system should use an approved asset inventory."
        ),
        "evidence": matched_terms,
        "reasoning": (
            f"Asset name '{asset_name}' was checked against configured "
            "asset-name rules to estimate its criticality."
        ),
        "confidence": confidence
    }


def risk_prioritisation_agent(alert, analysis, threat, asset_context):

    

    """Calculates an illustrative risk score with explainable factors."""
    severity_scores = {
        "Critical": 40,
        "High": 30,
        "Medium": 20,
        "Low": 10
    }

    criticality_scores = {
        "Critical": 30,
        "High": 20,
        "Medium": 10,
        "Unclassified": 5
    }


    severity = alert.get("Severity", "Low")
    criticality = asset_context["criticality"]

    severity_points = severity_scores.get(severity, 10)
    asset_points = criticality_scores.get(criticality, 5)
    threat_points = 20 if threat["status"] == "Potential match" else 0
    indicator_points = 10 if len(analysis["evidence"]) > 1 else 0

    score = min(
        severity_points + asset_points + threat_points + indicator_points,
        100
    )

    if score >= 75:
        priority = "Critical"
    elif score >= 55:
        priority = "High"
    elif score >= 35:
        priority = "Medium"
    else:
        priority = "Low"

    risk_factors = [
        {"factor": "Alert severity", "value": severity,
         "points": severity_points},
        {"factor": "Asset criticality", "value": criticality,
         "points": asset_points},
        {"factor": "Threat indicator match",
         "value": threat["status"], "points": threat_points},
        {"factor": "Multiple evidence matches",
         "value": "Yes" if indicator_points else "No",
         "points": indicator_points}
    ]

    confidence = round(
        (analysis["confidence"] + threat["confidence"]
         + asset_context["confidence"]) / 3
    )

    return {
        "agent": "Risk Prioritisation Agent",
        "risk_score": score,
        "priority": priority,
        "requires_human_review": priority in ["Critical", "High"],
        "risk_factors": risk_factors,
        "reasoning": (
            "Risk score is the sum of configured severity, asset "
            "criticality, threat-match and evidence-match points. "
            "It is capped at 100."
        ),
        "confidence": confidence
    }


def generate_investigation(alert):
    """Runs the simulated agents and combines their outputs."""
    analysis = alert_analysis_agent(alert)
    threat = threat_intel_agent(alert)
    asset = asset_context_agent(alert)

    risk = risk_prioritisation_agent(
        alert, analysis, threat, asset
    )

    # Retrieve relevant guidance from the SOC knowledge base
    query = (
        f"Alert type: {alert.get('Alert Type', 'Unknown')}. "
        f"Severity: {alert.get('Severity', 'Unknown')}. "
        f"Details: {alert.get('Details', '')}"
    )

    knowledge = retrieve_knowledge(query, top_k=3)


    recommendations = []

    if risk["priority"] in ["Critical", "High"]:
        recommendations.append(
            "Escalate to the SOC analyst for prompt review."
        )

    if "login" in alert.get("Alert Type", "").lower():
        recommendations.append(
            "Review authentication logs and verify the user's activity."
        )

    if "malware" in alert.get("Alert Type", "").lower():
        recommendations.append(
            "Review endpoint detection evidence and isolate only "
            "if authorised under incident procedures."
        )

    if threat["status"] == "Potential match":
        recommendations.append(
            "Validate the threat indicator using an approved "
            "threat intelligence source."
        )

    recommendations.append(
        "Preserve relevant logs and document the investigation."
    )

    return {
        "alert_id": alert.get("Alert ID", "Unassigned"),
        "analysis": analysis,
        "threat_intelligence": threat,
        "asset_context": asset,
        "risk": risk,
        "recommendations": recommendations,
        "retrieved_knowledge": knowledge,
        "status": "Awaiting human review"
        if risk["requires_human_review"]
        else "Analyst review recommended",
        "disclaimer": (
            "Demonstration output based on simulated rules. "
            "Confidence values are illustrative, not calibrated "
            "probabilities or verified security determinations."
        )
    }
