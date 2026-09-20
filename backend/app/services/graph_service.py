import logging
from typing import Dict, List, Any, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

try:
    import neo4j
    from neo4j import GraphDatabase, Driver
    HAS_NEO4J_DRIVER = True
except ImportError:
    neo4j = None
    GraphDatabase = None
    Driver = None
    HAS_NEO4J_DRIVER = False

class Neo4jGraphService:
    """
    Manages threat relationship graph storage and querying in Neo4j.
    Enforces strict privacy by excluding raw email body text from graph nodes.
    """

    def __init__(self, uri: str = None, user: str = None, password: str = None, database: str = None):
        self.uri = uri or settings.NEO4J_URI
        self.user = user or settings.NEO4J_USER
        self.password = password or settings.NEO4J_PASSWORD
        self.database = database or settings.NEO4J_DATABASE
        self._driver: Optional[Any] = None

    def get_driver(self) -> Optional[Any]:
        if not HAS_NEO4J_DRIVER:
            return None
        if self._driver is None:
            try:
                self._driver = GraphDatabase.driver(
                    self.uri,
                    auth=(self.user, self.password),
                    max_connection_lifetime=30
                )
            except Exception as e:
                logger.warning(f"Failed to create Neo4j driver: {e}")
                self._driver = None
        return self._driver

    def is_available(self) -> bool:
        """
        Verifies live connectivity to Neo4j database.
        """
        driver = self.get_driver()
        if not driver:
            return False
        try:
            with driver.session(database=self.database) as session:
                result = session.run("RETURN 1 AS status")
                record = result.single()
                return record is not None and record["status"] == 1
        except Exception as e:
            logger.debug(f"Neo4j connectivity check failed: {e}")
            return False

    def close(self):
        if self._driver:
            try:
                self._driver.close()
            except Exception:
                pass
            self._driver = None

    def sync_email_graph(
        self,
        email_record: Dict[str, Any],
        hops: List[Dict[str, Any]],
        urls: List[Dict[str, Any]],
        case_data: Optional[Dict[str, Any]] = None,
        campaign_data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Persists email entities and threat relationships into Neo4j.
        Privacy Rule: No raw body_plain or body_html is written to Neo4j.
        """
        driver = self.get_driver()
        if not driver or not self.is_available():
            logger.info("Neo4j unavailable. Skipping direct graph sync.")
            return False

        # Extract privacy-safe properties for Email node
        subject_str = email_record.get("subject") or "No Subject"
        subject_summary = subject_str[:120]
        
        email_props = {
            "id": str(email_record["id"]),
            "sha256_hash": str(email_record.get("sha256_hash", "")),
            "subject_summary": subject_summary,
            "threat_score": float(email_record.get("overall_threat_score", 0.0)),
            "threat_level": str(email_record.get("threat_level", "Low")),
            "email_date": str(email_record.get("email_date") or "")
        }

        # Sender node props
        sender_address = email_record.get("sender_address") or "unknown@domain.local"
        sender_name = email_record.get("sender_name") or sender_address
        sender_props = {
            "address": sender_address.lower().strip(),
            "display_name": sender_name,
            "spf_status": str(email_record.get("spf_status", "UNKNOWN")),
            "dkim_status": str(email_record.get("dkim_status", "UNKNOWN")),
            "dmarc_status": str(email_record.get("dmarc_status", "UNKNOWN"))
        }

        # Case props
        case_props = None
        if case_data or email_record.get("case_id"):
            case_id = str(email_record.get("case_id") or case_data.get("id"))
            case_props = {
                "id": case_id,
                "case_number": case_data.get("case_number", f"CASE-{case_id[:8]}") if case_data else f"CASE-{case_id[:8]}",
                "title": case_data.get("title", "Forensic Investigation") if case_data else "Forensic Investigation"
            }

        # Campaign props
        campaign_props = None
        if campaign_data:
            campaign_props = {
                "id": str(campaign_data.get("id", "CAMPAIGN-001")),
                "name": str(campaign_data.get("name", "BEC / Impersonation Campaign")),
                "threat_type": str(campaign_data.get("threat_type", "Phishing"))
            }

        query = """
        MERGE (e:Email {id: $email.id})
        SET e.sha256_hash = $email.sha256_hash,
            e.subject_summary = $email.subject_summary,
            e.threat_score = $email.threat_score,
            e.threat_level = $email.threat_level,
            e.email_date = $email.email_date

        MERGE (s:Sender {address: $sender.address})
        SET s.display_name = $sender.display_name,
            s.spf_status = $sender.spf_status,
            s.dkim_status = $sender.dkim_status,
            s.dmarc_status = $sender.dmarc_status

        MERGE (e)-[:SENT_BY]->(s)
        """

        try:
            with driver.session(database=self.database) as session:
                # 1. Email and Sender
                session.run(query, email=email_props, sender=sender_props)

                # 2. Case relationship
                if case_props:
                    case_query = """
                    MATCH (e:Email {id: $email_id})
                    MERGE (c:Case {id: $case.id})
                    SET c.case_number = $case.case_number,
                        c.title = $case.title
                    MERGE (e)-[:ASSOCIATED_WITH]->(c)
                    """
                    session.run(case_query, email_id=email_props["id"], case=case_props)

                # 3. URLs and Domains
                for url_item in urls:
                    url_val = url_item.get("url", "")
                    domain_val = url_item.get("domain", "")
                    if not url_val:
                        continue
                    url_props = {
                        "url": url_val[:200],
                        "domain": domain_val,
                        "is_suspicious": bool(url_item.get("is_suspicious", False)),
                        "reputation_score": float(url_item.get("reputation_score", 100.0))
                    }
                    domain_props = {
                        "name": domain_val.lower().strip(),
                        "is_suspicious": bool(url_item.get("is_suspicious", False)),
                        "reputation_score": float(url_item.get("reputation_score", 100.0))
                    }
                    url_query = """
                    MATCH (e:Email {id: $email_id})
                    MERGE (u:URL {url: $url.url})
                    SET u.domain = $url.domain,
                        u.is_suspicious = $url.is_suspicious,
                        u.reputation_score = $url.reputation_score
                    MERGE (e)-[:CONTAINS]->(u)

                    MERGE (d:Domain {name: $domain.name})
                    SET d.is_suspicious = $domain.is_suspicious,
                        d.reputation_score = $domain.reputation_score
                    MERGE (u)-[:HOSTED_ON]->(d)
                    """
                    session.run(url_query, email_id=email_props["id"], url=url_props, domain=domain_props)

                    # Campaign relationship for domain
                    if campaign_props:
                        camp_query = """
                        MATCH (d:Domain {name: $domain_name})
                        MERGE (cmp:Campaign {id: $cmp.id})
                        SET cmp.name = $cmp.name,
                            cmp.threat_type = $cmp.threat_type
                        MERGE (d)-[:PART_OF]->(cmp)
                        """
                        session.run(camp_query, domain_name=domain_props["name"], cmp=campaign_props)

                # 4. Hops -> IP -> ASN -> ISP -> Country
                for hop in hops:
                    ip_addr = hop.get("ip_address")
                    if not ip_addr or ip_addr == "0.0.0.0":
                        continue

                    country_name = hop.get("country", "Unknown")
                    isp_name = hop.get("isp", "Unknown Provider")
                    asn_val = hop.get("asn", "Unknown ASN")

                    ip_props = {
                        "address": ip_addr,
                        "is_vpn_proxy_tor": bool(hop.get("is_vpn_proxy_tor", False)),
                        "reputation": "suspicious" if hop.get("is_vpn_proxy_tor") else "normal"
                    }

                    hop_query = """
                    MATCH (e:Email {id: $email_id})
                    MERGE (ip:IP {address: $ip.address})
                    SET ip.is_vpn_proxy_tor = $ip.is_vpn_proxy_tor,
                        ip.reputation = $ip.reputation

                    MERGE (country:Country {name: $country_name})
                    MERGE (ip)-[:ASSOCIATED_WITH]->(country)

                    MERGE (isp:ISP {name: $isp_name})
                    MERGE (ip)-[:BELONGS_TO]->(isp)

                    MERGE (asn:ASN {asn: $asn_val})
                    MERGE (ip)-[:BELONGS_TO]->(asn)
                    """
                    session.run(
                        hop_query,
                        email_id=email_props["id"],
                        ip=ip_props,
                        country_name=country_name,
                        isp_name=isp_name,
                        asn_val=asn_val
                    )

                return True
        except Exception as e:
            logger.error(f"Error syncing graph to Neo4j: {e}")
            return False

    def get_email_graph(self, email_id: str) -> Optional[Dict[str, Any]]:
        """
        Queries Neo4j for nodes and relationships connected to an Email.
        Returns None if Neo4j is offline.
        """
        driver = self.get_driver()
        if not driver or not self.is_available():
            return None

        cypher_query = """
        MATCH (e:Email {id: $email_id})
        OPTIONAL MATCH (e)-[r1]->(target)
        OPTIONAL MATCH (target)-[r2]->(subtarget)
        OPTIONAL MATCH (subtarget)-[r3]->(deep)
        RETURN e, collect(r1) as r1s, collect(target) as targets,
               collect(r2) as r2s, collect(subtarget) as subtargets,
               collect(r3) as r3s, collect(deep) as deeps
        """

        nodes_dict: Dict[str, Dict[str, Any]] = {}
        edges_list: List[Dict[str, Any]] = []

        try:
            with driver.session(database=self.database) as session:
                result = session.run(cypher_query, email_id=email_id)
                record = result.single()
                if not record or not record["e"]:
                    return None

                # Parse Neo4j node/rel structures into standard format
                # (For production Neo4j results, construct node and edge dictionaries)
                # If Neo4j records are retrieved, populate nodes_dict and edges_list
                email_node = record["e"]
                nodes_dict[f"Email:{email_id}"] = {
                    "id": f"Email:{email_id}",
                    "label": "Email",
                    "properties": dict(email_node)
                }

                # Parse connected targets
                for target in record["targets"] or []:
                    if target:
                        labels = list(target.labels) if hasattr(target, "labels") else ["Node"]
                        label = labels[0] if labels else "Node"
                        props = dict(target)
                        node_key = props.get("id") or props.get("address") or props.get("url") or props.get("name") or props.get("asn") or str(target.element_id)
                        node_id = f"{label}:{node_key}"
                        nodes_dict[node_id] = {
                            "id": node_id,
                            "label": label,
                            "properties": props
                        }

                return {
                    "provider_mode": "NEO4J_LIVE",
                    "is_neo4j_connected": True,
                    "nodes": list(nodes_dict.values()),
                    "edges": edges_list
                }
        except Exception as e:
            logger.error(f"Failed to fetch Neo4j graph for email {email_id}: {e}")
            return None
