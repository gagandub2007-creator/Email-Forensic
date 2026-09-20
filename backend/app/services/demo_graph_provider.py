from typing import Dict, List, Any, Optional

class DemoGraphProvider:
    """
    Clearly separated fallback graph provider used when Neo4j database is unavailable.
    Constructs the threat relationship graph from relational database models or input dictionaries.
    Excludes raw email body text to ensure privacy compliance.
    Does NOT fake live Neo4j connectivity.
    """

    @staticmethod
    def generate_graph_from_email_data(
        email_dict: Dict[str, Any],
        hops: List[Dict[str, Any]],
        urls: List[Dict[str, Any]],
        case_dict: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        node_ids_seen = set()

        def add_node(node_id: str, label: str, properties: Dict[str, Any]):
            if node_id not in node_ids_seen:
                node_ids_seen.add(node_id)
                nodes.append({
                    "id": node_id,
                    "label": label,
                    "properties": properties
                })

        def add_edge(edge_id: str, source: str, target: str, relationship: str, properties: Optional[Dict[str, Any]] = None):
            edges.append({
                "id": edge_id,
                "source": source,
                "target": target,
                "relationship": relationship,
                "properties": properties or {}
            })

        # 1. Email Node
        email_id = str(email_dict.get("id", "email-001"))
        email_node_id = f"Email:{email_id}"
        subject_str = str(email_dict.get("subject") or "No Subject")
        
        add_node(
            node_id=email_node_id,
            label="Email",
            properties={
                "id": email_id,
                "sha256_hash": str(email_dict.get("sha256_hash", "")),
                "subject_summary": subject_str[:120],
                "threat_score": float(email_dict.get("overall_threat_score", 0.0)),
                "threat_level": str(email_dict.get("threat_level", "Low")),
                "email_date": str(email_dict.get("email_date") or ""),
                "spf_status": str(email_dict.get("spf_status", "UNKNOWN")),
                "dkim_status": str(email_dict.get("dkim_status", "UNKNOWN")),
                "dmarc_status": str(email_dict.get("dmarc_status", "UNKNOWN"))
            }
        )

        # 2. Sender Node & Email -> SENT_BY -> Sender
        sender_addr = str(email_dict.get("sender_address") or "unknown@domain.com").lower().strip()
        sender_node_id = f"Sender:{sender_addr}"
        add_node(
            node_id=sender_node_id,
            label="Sender",
            properties={
                "address": sender_addr,
                "display_name": str(email_dict.get("sender_name") or sender_addr),
                "spf_status": str(email_dict.get("spf_status", "UNKNOWN")),
                "dkim_status": str(email_dict.get("dkim_status", "UNKNOWN")),
                "dmarc_status": str(email_dict.get("dmarc_status", "UNKNOWN"))
            }
        )
        add_edge(
            edge_id=f"edge-{email_node_id}-SENT_BY-{sender_node_id}",
            source=email_node_id,
            target=sender_node_id,
            relationship="SENT_BY"
        )

        # Sender Domain & Sender -> USES_DOMAIN -> Domain
        sender_domain = sender_addr.split("@")[-1] if "@" in sender_addr else "domain.com"
        sender_dom_node_id = f"Domain:{sender_domain}"
        add_node(
            node_id=sender_dom_node_id,
            label="Domain",
            properties={
                "name": sender_domain,
                "is_suspicious": email_dict.get("spf_status") == "FAIL" or email_dict.get("dmarc_status") == "FAIL",
                "reputation_score": 40.0 if email_dict.get("spf_status") == "FAIL" else 90.0
            }
        )
        add_edge(
            edge_id=f"edge-{sender_node_id}-USES_DOMAIN-{sender_dom_node_id}",
            source=sender_node_id,
            target=sender_dom_node_id,
            relationship="USES_DOMAIN"
        )

        # 3. Case Node & Email -> ASSOCIATED_WITH -> Case
        case_id = str(email_dict.get("case_id") or (case_dict.get("id") if case_dict else "CASE-DEFAULT"))
        case_number = case_dict.get("case_number", f"CASE-{case_id[:8].upper()}") if case_dict else f"CASE-{case_id[:8].upper()}"
        case_title = case_dict.get("title", "Forensic Threat Investigation") if case_dict else "Forensic Threat Investigation"
        case_node_id = f"Case:{case_id}"

        add_node(
            node_id=case_node_id,
            label="Case",
            properties={
                "id": case_id,
                "case_number": case_number,
                "title": case_title
            }
        )
        add_edge(
            edge_id=f"edge-{email_node_id}-ASSOCIATED_WITH-{case_node_id}",
            source=email_node_id,
            target=case_node_id,
            relationship="ASSOCIATED_WITH"
        )

        # 4. Campaign Node & Domain -> PART_OF -> Campaign
        campaign_id = "CMP-2026-BEC-GLOBAL"
        campaign_node_id = f"Campaign:{campaign_id}"
        add_node(
            node_id=campaign_node_id,
            label="Campaign",
            properties={
                "id": campaign_id,
                "name": "Global BEC & CEO Impersonation Campaign",
                "threat_type": "Executive Impersonation / Credential Harvesting"
            }
        )

        if email_dict.get("overall_threat_score", 0) > 50:
            add_edge(
                edge_id=f"edge-{sender_dom_node_id}-PART_OF-{campaign_node_id}",
                source=sender_dom_node_id,
                target=campaign_node_id,
                relationship="PART_OF"
            )

        # 5. URLs & Domains: Email -> CONTAINS -> URL -> HOSTED_ON -> Domain
        for idx, u in enumerate(urls or []):
            raw_url = str(u.get("url") if isinstance(u, dict) else getattr(u, "url", ""))
            domain_name = str(u.get("domain") if isinstance(u, dict) else getattr(u, "domain", "unknown-domain.com"))
            if not raw_url:
                continue

            url_node_id = f"URL:{raw_url}"
            is_susp = bool(u.get("is_suspicious") if isinstance(u, dict) else getattr(u, "is_suspicious", False))
            rep_score = float(u.get("reputation_score") if isinstance(u, dict) else getattr(u, "reputation_score", 80.0))

            add_node(
                node_id=url_node_id,
                label="URL",
                properties={
                    "url": raw_url,
                    "domain": domain_name,
                    "is_suspicious": is_susp,
                    "reputation_score": rep_score
                }
            )
            add_edge(
                edge_id=f"edge-{email_node_id}-CONTAINS-{url_node_id}",
                source=email_node_id,
                target=url_node_id,
                relationship="CONTAINS"
            )

            url_dom_node_id = f"Domain:{domain_name}"
            add_node(
                node_id=url_dom_node_id,
                label="Domain",
                properties={
                    "name": domain_name,
                    "is_suspicious": is_susp,
                    "reputation_score": rep_score
                }
            )
            add_edge(
                edge_id=f"edge-{url_node_id}-HOSTED_ON-{url_dom_node_id}",
                source=url_node_id,
                target=url_dom_node_id,
                relationship="HOSTED_ON"
            )

            if is_susp:
                add_edge(
                    edge_id=f"edge-{url_dom_node_id}-PART_OF-{campaign_node_id}",
                    source=url_dom_node_id,
                    target=campaign_node_id,
                    relationship="PART_OF"
                )

        # 6. Hops -> IP -> ASN -> ISP -> Country
        for idx, hop in enumerate(hops or []):
            ip_addr = str(hop.get("ip_address") if isinstance(hop, dict) else getattr(hop, "ip_address", ""))
            if not ip_addr or ip_addr == "0.0.0.0":
                continue

            country_name = str(hop.get("country") if isinstance(hop, dict) else getattr(hop, "country", "Unknown"))
            isp_name = str(hop.get("isp") if isinstance(hop, dict) else getattr(hop, "isp", "Global Transit Provider"))
            asn_val = str(hop.get("asn") if isinstance(hop, dict) else getattr(hop, "asn", "AS15169"))
            is_vpn = bool(hop.get("is_vpn_proxy_tor") if isinstance(hop, dict) else getattr(hop, "is_vpn_proxy_tor", False))

            ip_node_id = f"IP:{ip_addr}"
            add_node(
                node_id=ip_node_id,
                label="IP",
                properties={
                    "address": ip_addr,
                    "is_vpn_proxy_tor": is_vpn,
                    "reputation": "malicious" if is_vpn else "normal",
                    "hop_number": hop.get("hop_number") if isinstance(hop, dict) else getattr(hop, "hop_number", idx + 1)
                }
            )

            # Link Domain to IP (Domain -> RESOLVES_TO -> IP) if first hop or matching sender domain
            if idx == 0:
                add_edge(
                    edge_id=f"edge-{sender_dom_node_id}-RESOLVES_TO-{ip_node_id}",
                    source=sender_dom_node_id,
                    target=ip_node_id,
                    relationship="RESOLVES_TO"
                )

            # Country Node & IP -> ASSOCIATED_WITH -> Country
            country_node_id = f"Country:{country_name}"
            add_node(
                node_id=country_node_id,
                label="Country",
                properties={
                    "name": country_name,
                    "code": country_name[:3].upper()
                }
            )
            add_edge(
                edge_id=f"edge-{ip_node_id}-ASSOCIATED_WITH-{country_node_id}",
                source=ip_node_id,
                target=country_node_id,
                relationship="ASSOCIATED_WITH"
            )

            # ISP Node & IP -> BELONGS_TO -> ISP
            isp_node_id = f"ISP:{isp_name}"
            add_node(
                node_id=isp_node_id,
                label="ISP",
                properties={
                    "name": isp_name
                }
            )
            add_edge(
                edge_id=f"edge-{ip_node_id}-BELONGS_TO-{isp_node_id}",
                source=ip_node_id,
                target=isp_node_id,
                relationship="BELONGS_TO"
            )

            # ASN Node & IP -> BELONGS_TO -> ASN
            asn_node_id = f"ASN:{asn_val}"
            add_node(
                node_id=asn_node_id,
                label="ASN",
                properties={
                    "asn": asn_val,
                    "name": f"Autonomous System {asn_val}"
                }
            )
            add_edge(
                edge_id=f"edge-{ip_node_id}-BELONGS_TO-{asn_node_id}",
                source=ip_node_id,
                target=asn_node_id,
                relationship="BELONGS_TO"
            )

        return {
            "provider_mode": "DEMO_FALLBACK",
            "is_neo4j_connected": False,
            "note": "Neo4j database is offline. Serving threat graph via Demo Graph Provider.",
            "nodes": nodes,
            "edges": edges
        }
