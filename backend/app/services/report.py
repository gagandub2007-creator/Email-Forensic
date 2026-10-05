"""
STEP 18 — Professional Forensic Investigation Report Generator

Generates a multi-section digital-forensics PDF report that clearly
distinguishes:
    [FACT]        — directly observed / extracted data
    [INFERENCE]   — conclusions drawn from facts
    [ESTIMATION]  — approximate values (e.g. geolocation)
    [CONFIDENCE]  — model confidence levels
    [LIMITATION]  — known gaps or constraints
"""

from io import BytesIO
from datetime import datetime, timezone
from typing import Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER

# ---------------------------------------------------------------
# Style definitions
# ---------------------------------------------------------------

_DARK   = colors.HexColor('#0F172A')
_GREY   = colors.HexColor('#334155')
_LIGHT  = colors.HexColor('#F8FAFC')
_BORDER = colors.HexColor('#CBD5E1')
_ACCENT = colors.HexColor('#0284C7')
_GREEN  = colors.HexColor('#166534')
_RED    = colors.HexColor('#B91C1C')
_AMBER  = colors.HexColor('#92400E')


def _build_styles():
    ss = getSampleStyleSheet()
    return {
        'title': ParagraphStyle('RptTitle', parent=ss['Heading1'], fontSize=18,
                                leading=22, textColor=_DARK, alignment=TA_CENTER, spaceAfter=4),
        'subtitle': ParagraphStyle('RptSub', parent=ss['Heading2'], fontSize=10,
                                   leading=13, textColor=_GREY, alignment=TA_CENTER, spaceAfter=16),
        'h2': ParagraphStyle('RptH2', parent=ss['Heading2'], fontSize=13, leading=17,
                             textColor=_DARK, spaceBefore=14, spaceAfter=6),
        'h3': ParagraphStyle('RptH3', parent=ss['Heading3'], fontSize=11, leading=14,
                             textColor=_DARK, spaceBefore=10, spaceAfter=4),
        'body': ParagraphStyle('RptBody', parent=ss['Normal'], fontSize=9, leading=12,
                               textColor=_GREY),
        'mono': ParagraphStyle('RptMono', parent=ss['Normal'], fontName='Courier',
                               fontSize=7.5, leading=10, textColor=_ACCENT),
        'fact': ParagraphStyle('RptFact', parent=ss['Normal'], fontSize=8,
                               leading=11, textColor=_GREEN, leftIndent=10),
        'inference': ParagraphStyle('RptInfer', parent=ss['Normal'], fontSize=8,
                                    leading=11, textColor=_ACCENT, leftIndent=10),
        'estimation': ParagraphStyle('RptEst', parent=ss['Normal'], fontSize=8,
                                     leading=11, textColor=_AMBER, leftIndent=10),
        'limitation': ParagraphStyle('RptLim', parent=ss['Normal'], fontSize=8,
                                     leading=11, textColor=_RED, leftIndent=10),
        'small': ParagraphStyle('RptSmall', parent=ss['Normal'], fontSize=7,
                                leading=9, textColor=colors.HexColor('#94A3B8')),
        'disclaimer': ParagraphStyle('RptDisclaimer', parent=ss['Normal'], fontSize=7.5,
                                     leading=10, textColor=colors.HexColor('#64748B'),
                                     backColor=colors.HexColor('#FEF9C3'), borderPadding=6),
    }


def _table(rows, col_widths=None, header_bg=True):
    """Build a styled Table from row data."""
    style_cmds = [
        ('INNERGRID', (0, 0), (-1, -1), 0.5, _BORDER),
        ('BOX', (0, 0), (-1, -1), 1, _BORDER),
        ('PADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]
    if header_bg and len(rows) > 1:
        style_cmds.append(('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')))
    t = Table(rows, colWidths=col_widths, repeatRows=1 if len(rows) > 1 else 0)
    t.setStyle(TableStyle(style_cmds))
    return t


def _label(text, s):
    return Paragraph(f"<b>{text}</b>", s)


def _clean_str(val, default="N/A"):
    if val is None:
        return default
    if hasattr(val, 'strftime'):
        return val.strftime('%Y-%m-%d %H:%M:%S UTC')
    val_str = str(val)
    return val_str if val_str.strip() else default


# ---------------------------------------------------------------
# Main generator class
# ---------------------------------------------------------------

class ForensicReportGenerator:
    """Generates a comprehensive digital-forensics PDF."""

    @classmethod
    def generate_full_report_pdf(
        cls,
        *,
        email_record: dict,
        hops: list,
        ai_data: dict,
        blockchain_data: dict,
        evidence_record: Optional[dict] = None,
        custody_events: Optional[list] = None,
        ledger_entry: Optional[dict] = None,
        urls: Optional[list] = None,
        attachments: Optional[list] = None,
        analyst: str = "System",
        case_id: str = "CASE-2026-DEFAULT",
        investigation_id: str = "",
    ) -> bytes:
        """Return the full-report PDF as raw bytes."""
        S = _build_styles()
        buf = BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=letter,
            rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36,
        )
        story: list = []
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        evidence_hash = evidence_record.get('sha256_hash', email_record.get('sha256_hash', '')) if evidence_record else email_record.get('sha256_hash', '')

        # ====== COVER ====================================================
        story.append(Spacer(1, 40))
        story.append(Paragraph("<b>DIGITAL FORENSIC INVESTIGATION REPORT</b>", S['title']))
        story.append(Paragraph("Email Forensic Intelligence Platform — Confidential", S['subtitle']))
        story.append(HRFlowable(width="100%", thickness=1.5, color=_DARK, spaceAfter=12))

        cover_rows = [
            [_label("Report ID:", S['body']), Paragraph(f"RPT-{_clean_str(email_record.get('id'))[:8].upper()}", S['body'])],
            [_label("Case ID:", S['body']), Paragraph(_clean_str(case_id), S['body'])],
            [_label("Investigation ID:", S['body']), Paragraph(_clean_str(investigation_id or case_id), S['body'])],
            [_label("Generated:", S['body']), Paragraph(now, S['body'])],
            [_label("Analyst:", S['body']), Paragraph(_clean_str(analyst), S['body'])],
            [_label("Evidence Hash:", S['body']), Paragraph(_clean_str(evidence_hash), S['mono'])],
        ]
        story.append(_table(cover_rows, [140, 380], header_bg=False))
        story.append(Spacer(1, 12))

        # ====== 1. CASE INFORMATION =======================================
        cls._section(story, S, "1. Case Information")
        story.append(Paragraph("[FACT] Case and evidence identifiers as assigned by the platform.", S['fact']))
        story.append(_table([
            [_label("Case ID:", S['body']), Paragraph(_clean_str(case_id), S['body'])],
            [_label("Investigation ID:", S['body']), Paragraph(_clean_str(investigation_id or case_id), S['body'])],
            [_label("Email Record ID:", S['body']), Paragraph(_clean_str(email_record.get('id')), S['mono'])],
            [_label("Message-ID:", S['body']), Paragraph(_clean_str(email_record.get('message_id')), S['mono'])],
            [_label("Report Timestamp:", S['body']), Paragraph(now, S['body'])],
            [_label("Analyst:", S['body']), Paragraph(_clean_str(analyst), S['body'])],
        ], [140, 380], header_bg=False))

        # ====== 2. EXECUTIVE SUMMARY ======================================
        cls._section(story, S, "2. Executive Summary")
        threat = email_record.get('threat_level', 'Unknown')
        score  = email_record.get('overall_threat_score', 0)
        ai_class = ai_data.get('classification', 'Unclassified') if ai_data else 'N/A'
        confidence = ai_data.get('confidence', 0) if ai_data else 0

        story.append(Paragraph(
            f"This email was analysed by the Email Forensic Intelligence Platform. "
            f"The automated threat assessment engine classified it as "
            f"<b>{ai_class}</b> with a risk score of <b>{score}/100</b> "
            f"(threat level: <b>{threat}</b>).",
            S['body'],
        ))
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"[CONFIDENCE] AI model confidence: {round(confidence * 100)}%", S['inference']))
        story.append(Paragraph("[LIMITATION] This is an automated assessment. Human analyst review is recommended.", S['limitation']))

        # ====== 3. EMAIL DETAILS ==========================================
        cls._section(story, S, "3. Email Details")
        story.append(Paragraph("[FACT] Header fields extracted directly from the raw email.", S['fact']))
        story.append(_table([
            [_label("Subject:", S['body']), Paragraph(_clean_str(email_record.get('subject'), '(No Subject)'), S['body'])],
            [_label("From:", S['body']), Paragraph(f"{_clean_str(email_record.get('sender_name'), '')} &lt;{_clean_str(email_record.get('sender_address'), '')}&gt;", S['body'])],
            [_label("To:", S['body']), Paragraph(_clean_str(email_record.get('recipient_address'), ''), S['body'])],
            [_label("CC:", S['body']), Paragraph(_clean_str(email_record.get('cc'), 'N/A'), S['body'])],
            [_label("Reply-To:", S['body']), Paragraph(_clean_str(email_record.get('reply_to'), 'N/A'), S['body'])],
            [_label("Return-Path:", S['body']), Paragraph(_clean_str(email_record.get('return_path'), 'N/A'), S['body'])],
            [_label("Date:", S['body']), Paragraph(_clean_str(email_record.get('email_date'), 'N/A'), S['body'])],
        ], [120, 400], header_bg=False))

        # ====== 4. THREAT CLASSIFICATION ==================================
        cls._section(story, S, "4. Threat Classification")
        story.append(Paragraph(f"[INFERENCE] AI classification: <b>{ai_class}</b>", S['inference']))
        story.append(Paragraph(f"[CONFIDENCE] {round(confidence * 100)}%", S['inference']))
        if ai_data:
            signals = ai_data.get('signals', [])
            if signals:
                story.append(Paragraph("<b>Detected Signals:</b>", S['body']))
                for sig in (signals if isinstance(signals, list) else [signals]):
                    story.append(Paragraph(f"  • {sig}", S['body']))

        # ====== 5. RISK ASSESSMENT ========================================
        cls._section(story, S, "5. Risk Assessment")
        story.append(_table([
            [_label("Metric", S['body']), _label("Value", S['body']), _label("Category", S['body'])],
            [Paragraph("Overall Threat Score", S['body']), Paragraph(f"{score}/100", S['body']), Paragraph("[FACT]", S['fact'])],
            [Paragraph("Threat Level", S['body']), Paragraph(threat, S['body']), Paragraph("[INFERENCE]", S['inference'])],
            [Paragraph("AI Confidence", S['body']), Paragraph(f"{round(confidence * 100)}%", S['body']), Paragraph("[CONFIDENCE]", S['inference'])],
        ], [200, 160, 160]))

        # ====== 6. HEADER ANALYSIS ========================================
        cls._section(story, S, "6. Header Analysis")
        story.append(Paragraph("[FACT] Raw header data extracted from the email source.", S['fact']))
        if email_record.get('raw_headers'):
            # Show first 2000 chars max
            raw = str(email_record['raw_headers'])[:2000]
            story.append(Paragraph(raw.replace('<', '&lt;').replace('>', '&gt;').replace('\n', '<br/>'), S['mono']))
        else:
            story.append(Paragraph("Raw headers not available in this record.", S['body']))

        # ====== 7. SPF / DKIM / DMARC ====================================
        cls._section(story, S, "7. SPF / DKIM / DMARC Authentication")
        story.append(Paragraph("[FACT] Authentication results as reported by receiving mail servers.", S['fact']))
        story.append(_table([
            [_label("Protocol", S['body']), _label("Status", S['body'])],
            [Paragraph("SPF", S['body']), Paragraph(email_record.get('spf_status', 'UNKNOWN'), S['body'])],
            [Paragraph("DKIM", S['body']), Paragraph(email_record.get('dkim_status', 'UNKNOWN'), S['body'])],
            [Paragraph("DMARC", S['body']), Paragraph(email_record.get('dmarc_status', 'UNKNOWN'), S['body'])],
        ], [200, 320]))

        # ====== 8. URLS & DOMAINS =========================================
        cls._section(story, S, "8. URLs and Domains")
        url_list = urls or []
        if url_list:
            url_rows = [[_label("URL", S['body']), _label("Domain", S['body']), _label("Type", S['body'])]]
            for u in url_list[:20]:
                url_rows.append([
                    Paragraph(str(u.get('url', ''))[:60], S['mono']),
                    Paragraph(u.get('domain', ''), S['body']),
                    Paragraph(u.get('url_type', ''), S['body']),
                ])
            story.append(_table(url_rows, [240, 150, 130]))
        else:
            story.append(Paragraph("No extracted URLs in this email.", S['body']))
        story.append(Paragraph("[ESTIMATION] URL reputation is based on third-party feeds; false positives are possible.", S['estimation']))

        # ====== 9. IP & INFRASTRUCTURE ====================================
        cls._section(story, S, "9. IP and Infrastructure Intelligence")
        story.append(Paragraph("[ESTIMATION] Geolocation data is approximate and should NOT be treated as exact physical location.", S['estimation']))
        if hops:
            hop_rows = [[
                _label("#", S['body']), _label("IP", S['body']),
                _label("Location", S['body']), _label("ISP / ASN", S['body']),
                _label("VPN/Proxy/Tor", S['body']),
            ]]
            for h in hops:
                color = "<font color='red'>YES</font>" if h.get('is_vpn_proxy_tor') else "NO"
                hop_rows.append([
                    Paragraph(str(h.get('hop_number', '')), S['body']),
                    Paragraph(h.get('ip_address', ''), S['mono']),
                    Paragraph(f"{h.get('city', '')}, {h.get('country', '')}", S['body']),
                    Paragraph(h.get('isp', ''), S['body']),
                    Paragraph(color, S['body']),
                ])
            story.append(_table(hop_rows, [30, 100, 140, 170, 80]))
        else:
            story.append(Paragraph("No hop data available.", S['body']))

        # ====== 10. RELAY PATH ============================================
        cls._section(story, S, "10. Relay Path")
        story.append(Paragraph("[FACT] Received headers listed in order of reception.", S['fact']))
        if hops:
            for h in hops:
                story.append(Paragraph(
                    f"Hop {h.get('hop_number', '?')}: {h.get('from_header', '')} → {h.get('ip_address', '')} "
                    f"({h.get('city', '')}, {h.get('country', '')})",
                    S['body'],
                ))
        else:
            story.append(Paragraph("No relay path information available.", S['body']))

        # ====== 11. HISTORICAL CORRELATION ================================
        cls._section(story, S, "11. Historical Correlation")
        story.append(Paragraph("[INFERENCE] No historical threat correlation data is available for this prototype.", S['inference']))
        story.append(Paragraph("[LIMITATION] Production systems should cross-reference with historical case databases.", S['limitation']))

        # ====== 12. THREAT GRAPH SUMMARY ==================================
        cls._section(story, S, "12. Threat Graph Summary")
        story.append(Paragraph("[INFERENCE] Threat graph is generated from email relationship metadata.", S['inference']))
        story.append(Paragraph(
            "The threat graph connects entities (sender, recipients, IPs, domains, URLs) "
            "to visualise attack infrastructure. Refer to the interactive graph in the platform UI for details.",
            S['body'],
        ))

        # ====== 13. ATTRIBUTION SUPPORT ===================================
        story.append(PageBreak())
        cls._section(story, S, "13. Attribution Support")
        story.append(Paragraph(
            "[LIMITATION] This platform does NOT claim attacker identity. "
            "Attribution requires multi-source intelligence, legal authority, and human analysis. "
            "The data below supports — but does not prove — attribution hypotheses.",
            S['limitation'],
        ))
        story.append(Paragraph(f"Sender domain: {email_record.get('sender_address', '').split('@')[-1] if email_record.get('sender_address') else 'N/A'}", S['body']))
        story.append(Paragraph(f"Originating IP: {hops[0].get('ip_address', 'N/A') if hops else 'N/A'}", S['body']))

        # ====== 14. EVIDENCE INTEGRITY ====================================
        cls._section(story, S, "14. Evidence Integrity")
        story.append(Paragraph("[FACT] SHA-256 hash computed at evidence collection time.", S['fact']))
        if evidence_record:
            story.append(_table([
                [_label("Evidence ID:", S['body']), Paragraph(evidence_record.get('id', ''), S['mono'])],
                [_label("SHA-256:", S['body']), Paragraph(evidence_record.get('sha256_hash', ''), S['mono'])],
                [_label("File:", S['body']), Paragraph(evidence_record.get('filename', ''), S['body'])],
                [_label("Size:", S['body']), Paragraph(f"{evidence_record.get('file_size_bytes', 0)} bytes", S['body'])],
                [_label("Collected By:", S['body']), Paragraph(evidence_record.get('collected_by', ''), S['body'])],
                [_label("Status:", S['body']), Paragraph(f"<b>{evidence_record.get('integrity_status', 'Unverified')}</b>", S['body'])],
            ], [120, 400], header_bg=False))
        else:
            story.append(Paragraph("Evidence record not available.", S['body']))

        # ====== 15. CHAIN OF CUSTODY ======================================
        cls._section(story, S, "15. Chain of Custody")
        story.append(Paragraph("[FACT] Chronological timeline of evidence handling events.", S['fact']))
        events = custody_events or []
        if events:
            coc_rows = [[_label("Timestamp", S['body']), _label("User", S['body']), _label("Action", S['body'])]]
            for e in events:
                ts = e.get('timestamp', '')
                if hasattr(ts, 'strftime'):
                    ts = ts.strftime('%Y-%m-%d %H:%M:%S UTC')
                coc_rows.append([
                    Paragraph(str(ts), S['body']),
                    Paragraph(e.get('user', ''), S['body']),
                    Paragraph(e.get('action', ''), S['body']),
                ])
            story.append(_table(coc_rows, [200, 130, 190]))
        else:
            story.append(Paragraph("No chain-of-custody events recorded.", S['body']))

        # ====== 16. BLOCKCHAIN / LEDGER VERIFICATION ======================
        cls._section(story, S, "16. Blockchain / Ledger Verification")
        story.append(Paragraph(
            "[FACT] Blockchain is used here as a tamper-evident record for evidence integrity, "
            "not as storage for the original email. Only the SHA-256 hash, evidence ID, timestamp, "
            "and case reference are registered on the ledger.",
            S['fact'],
        ))
        if ledger_entry:
            story.append(_table([
                [_label("Transaction ID:", S['body']), Paragraph(ledger_entry.get('ledger_tx_id', ''), S['mono'])],
                [_label("Evidence Hash:", S['body']), Paragraph(ledger_entry.get('evidence_hash', ''), S['mono'])],
                [_label("Block Number:", S['body']), Paragraph(str(ledger_entry.get('block_number', '')), S['body'])],
                [_label("Merkle Root:", S['body']), Paragraph(ledger_entry.get('merkle_root', ''), S['mono'])],
                [_label("Contract:", S['body']), Paragraph(ledger_entry.get('contract_address', ''), S['mono'])],
                [_label("Ledger Status:", S['body']), Paragraph(f"<b>{ledger_entry.get('ledger_status', 'N/A')}</b>", S['body'])],
                [_label("Verification:", S['body']), Paragraph(f"<b>{ledger_entry.get('verification_status', 'Unverified')}</b>", S['body'])],
            ], [120, 400], header_bg=False))
        elif blockchain_data:
            story.append(_table([
                [_label("Tx Hash:", S['body']), Paragraph(blockchain_data.get('transaction_hash', 'N/A'), S['mono'])],
                [_label("Block:", S['body']), Paragraph(str(blockchain_data.get('block_number', '')), S['body'])],
                [_label("Status:", S['body']), Paragraph(blockchain_data.get('status', 'N/A'), S['body'])],
            ], [120, 400], header_bg=False))
        else:
            story.append(Paragraph("No blockchain/ledger data available.", S['body']))

        # ====== 17. LIMITATIONS ===========================================
        cls._section(story, S, "17. Limitations")
        limitations = [
            "Geolocation data is approximate (IP-based) and must NOT be presented as exact physical location.",
            "AI classification confidence may vary; false positives and negatives are possible.",
            "This platform does NOT claim or infer attacker identity.",
            "URL and domain reputation is based on third-party threat feeds and may contain false positives.",
            "VPN/proxy/Tor detection is heuristic-based and not guaranteed to be accurate.",
            "This prototype uses a local mock ledger; production should use a permissioned blockchain (e.g. Hyperledger Fabric).",
            "Email headers can be forged; authentication results (SPF/DKIM/DMARC) indicate policy compliance, not guaranteed authenticity.",
            "Historical correlation data is not available in the current prototype version.",
        ]
        for lim in limitations:
            story.append(Paragraph(f"[LIMITATION] {lim}", S['limitation']))
            story.append(Spacer(1, 2))

        # ====== LEGAL DECLARATION =========================================
        story.append(Spacer(1, 16))
        story.append(HRFlowable(width="100%", thickness=1, color=_BORDER, spaceAfter=8))
        story.append(Paragraph(
            "<b>LEGAL DECLARATION (Section 65B, Indian Evidence Act / BSA 2023)</b>",
            S['h3'],
        ))
        story.append(Paragraph(
            "I hereby certify that the electronic record described in this report was produced by the "
            "automated Email Forensic Intelligence Platform in the ordinary course of official cyber "
            "investigation activities. The system operates accurately and the integrity of the output "
            "is secured by cryptographic SHA-256 hashing and tamper-evident ledger anchoring.",
            S['body'],
        ))
        story.append(Spacer(1, 30))
        sig_data = [
            [Paragraph("<b>Investigator Signature:</b> _______________________", S['body']),
             Paragraph("<b>Forensic Analyst Seal:</b> _______________________", S['body'])],
        ]
        story.append(Table(sig_data, colWidths=[260, 260]))
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Generated by Email Forensic Intelligence Platform · {now}", S['small']))

        # BUILD
        doc.build(story)
        pdf_bytes = buf.getvalue()
        buf.close()
        return pdf_bytes

    # Keep backward compatibility with existing report endpoint
    @classmethod
    def generate_section65b_pdf(cls, email_record, hops, ai_data, blockchain_data):
        return cls.generate_full_report_pdf(
            email_record=email_record,
            hops=hops,
            ai_data=ai_data,
            blockchain_data=blockchain_data,
        )

    @staticmethod
    def _section(story, S, title):
        story.append(Spacer(1, 6))
        story.append(Paragraph(f"<b>{title}</b>", S['h2']))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_BORDER, spaceAfter=6))
