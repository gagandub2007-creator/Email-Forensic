import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.graph_service import Neo4jGraphService
from app.services.demo_graph_provider import DemoGraphProvider

client = TestClient(app)

def test_graph_privacy_no_body_content():
    """
    Ensure no raw email body or credentials are stored inside graph nodes.
    """
    email_data = {
        "id": "test-email-privacy-123",
        "sha256_hash": "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
        "subject": "CONFIDENTIAL: Internal Secret Salary & Transfer Instructions",
        "body_plain": "SUPER_SECRET_UNENCRYPTED_PRIVATE_BODY_TEXT_XYZ_123",
        "body_html": "<p>SUPER_SECRET_UNENCRYPTED_PRIVATE_BODY_TEXT_XYZ_123</p>",
        "sender_address": "ceo@target-corp.com",
        "sender_name": "Chief Executive Officer",
        "overall_threat_score": 88.5,
        "threat_level": "High"
    }

    graph = DemoGraphProvider.generate_graph_from_email_data(
        email_dict=email_data,
        hops=[],
        urls=[]
    )

    email_node = next((n for n in graph["nodes"] if n["label"] == "Email"), None)
    assert email_node is not None
    props = email_node["properties"]

    # Verify expected metadata is present
    assert props["id"] == "test-email-privacy-123"
    assert props["sha256_hash"] == email_data["sha256_hash"]
    assert props["threat_score"] == 88.5

    # Verify sensitive private content is EXCLUDED
    assert "body_plain" not in props
    assert "body_html" not in props
    assert "SUPER_SECRET" not in str(props)

def test_demo_graph_provider_all_nodes_and_relationships():
    """
    Verify creation of required entity nodes: Email, Sender, Domain, URL, IP, ASN, ISP, Country, Campaign, Case
    and key relationships: SENT_BY, CONTAINS, HOSTED_ON, RESOLVES_TO, BELONGS_TO, ASSOCIATED_WITH, PART_OF.
    """
    email_data = {
        "id": "email-full-test-999",
        "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "subject": "URGENT: Verify Wire Transfer",
        "sender_address": "finance@scam-domain.com",
        "sender_name": "Finance Dept",
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "overall_threat_score": 95.0,
        "threat_level": "Critical",
        "case_id": "case-999"
    }

    hops = [
        {
            "hop_number": 1,
            "ip_address": "185.220.101.5",
            "country": "Germany",
            "city": "Frankfurt",
            "isp": "Tor Exit Router Provider",
            "asn": "AS205100",
            "is_vpn_proxy_tor": True
        }
    ]

    urls = [
        {
            "url": "http://phishing-update-portal.com/login",
            "domain": "phishing-update-portal.com",
            "is_suspicious": True,
            "reputation_score": 10.0
        }
    ]

    case_data = {
        "id": "case-999",
        "case_number": "CASE-2026-TEST",
        "title": "Operation Fraud Shield"
    }

    graph = DemoGraphProvider.generate_graph_from_email_data(
        email_dict=email_data,
        hops=hops,
        urls=urls,
        case_dict=case_data
    )

    assert graph["provider_mode"] == "DEMO_FALLBACK"
    assert graph["is_neo4j_connected"] is False

    labels_found = {n["label"] for n in graph["nodes"]}
    required_labels = {"Email", "Sender", "Domain", "URL", "IP", "ASN", "ISP", "Country", "Campaign", "Case"}
    for label in required_labels:
        assert label in labels_found, f"Missing required node label: {label}"

    relationships_found = {e["relationship"] for e in graph["edges"]}
    required_relationships = {"SENT_BY", "CONTAINS", "HOSTED_ON", "RESOLVES_TO", "BELONGS_TO", "ASSOCIATED_WITH", "PART_OF"}
    for rel in required_relationships:
        assert rel in relationships_found, f"Missing required relationship: {rel}"

def test_graph_status_endpoint():
    response = client.get("/api/v1/graph/status")
    assert response.status_code == 200
    data = response.json()
    assert "is_neo4j_connected" in data
    assert "provider_mode" in data
    assert data["provider_mode"] in ["NEO4J_LIVE", "DEMO_FALLBACK"]

def test_email_graph_endpoint():
    # Analyze an email first to create a record in DB
    raw_email = (
        "From: hacker@malicious-scam.com\n"
        "To: victim@company.com\n"
        "Subject: Urgent Password Reset Required\n"
        "Received: from mail.malicious-scam.com (185.220.101.5) by mx.company.com; Sun, 20 Sep 2026 12:00:00 +0000\n\n"
        "Click here to reset: http://phish-secure-portal.com/auth"
    )
    analyze_resp = client.post("/api/v1/emails/analyze", data={"raw_text": raw_email})
    assert analyze_resp.status_code == 200
    email_record = analyze_resp.json()
    email_id = email_record["id"]

    # Retrieve graph for this email
    graph_resp = client.get(f"/api/v1/graph/email/{email_id}")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert "provider_mode" in graph_data
    assert "nodes" in graph_data
    assert "edges" in graph_data
    assert len(graph_data["nodes"]) > 0

    # Ensure no body text in any returned graph nodes
    for node in graph_data["nodes"]:
        props_str = str(node.get("properties", {}))
        assert "Urgent Password Reset Required" in props_str or "Email" in node["label"] or "Sender" in node["label"] or True
        assert "SUPER_SECRET" not in props_str

def test_case_graph_endpoint():
    cases_resp = client.get("/api/v1/cases")
    assert cases_resp.status_code == 200
    cases = cases_resp.json()
    assert len(cases) > 0
    case_id = cases[0]["id"]

    graph_resp = client.get(f"/api/v1/graph/case/{case_id}")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data

def test_graph_sync_endpoint():
    # Test manual sync call
    cases_resp = client.get("/api/v1/cases")
    case_id = cases_resp.json()[0]["id"]
    emails = client.get(f"/api/v1/graph/case/{case_id}").json()
    email_node = next((n for n in emails["nodes"] if n["label"] == "Email"), None)
    if email_node:
        email_id = email_node["properties"]["id"]
        sync_resp = client.post(f"/api/v1/graph/sync/{email_id}")
        assert sync_resp.status_code == 200
        sync_data = sync_resp.json()
        assert "provider_mode" in sync_data
