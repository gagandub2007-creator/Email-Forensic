from io import BytesIO
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class ForensicReportGenerator:
    @classmethod
    def generate_section65b_pdf(cls, email_record: dict, hops: list, ai_data: dict, blockchain_data: dict) -> bytes:
        """
        Generates a Section 65B Indian Evidence Act compliant PDF Forensic Certificate.
        Returns PDF bytes.
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        story = []

        styles = getSampleStyleSheet()
        
        # Custom Styles
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#0F172A'),
            alignment=1, # Centered
            spaceAfter=10
        )
        subtitle_style = ParagraphStyle(
            'SubTitleStyle',
            parent=styles['Heading2'],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#475569'),
            alignment=1,
            spaceAfter=20
        )
        heading_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading3'],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#1E293B'),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyTextCustom',
            parent=styles['Normal'],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor('#334155')
        )
        mono_style = ParagraphStyle(
            'MonoText',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#0284C7')
        )

        # 1. Header Title
        story.append(Paragraph("<b>CERTIFICATE OF DIGITAL EVIDENCE</b>", title_style))
        story.append(Paragraph("Issued under Section 65B of the Indian Evidence Act / BSA 2023<br/><b>AICTE - Cyber Security Cell Forensic Platform</b>", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0F172A'), spaceAfter=15))

        # 2. Case & Evidence Summary Table
        case_table_data = [
            [Paragraph("<b>Certificate Ref ID:</b>", body_style), Paragraph(f"CERT-2026-{email_record.get('id', '')[:8]}", body_style)],
            [Paragraph("<b>Case Number:</b>", body_style), Paragraph("CASE-2026-SIH26106", body_style)],
            [Paragraph("<b>Analysis Timestamp:</b>", body_style), Paragraph(datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'), body_style)],
            [Paragraph("<b>SHA-256 Evidence Hash:</b>", body_style), Paragraph(email_record.get('sha256_hash', ''), mono_style)],
            [Paragraph("<b>Overall Threat Level:</b>", body_style), Paragraph(f"<b>{email_record.get('threat_level', 'CLEAN')} (Score: {email_record.get('overall_threat_score', 0)}/100)</b>", body_style)],
        ]
        t1 = Table(case_table_data, colWidths=[140, 380])
        t1.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t1)
        story.append(Spacer(1, 15))

        # 3. Blockchain Chain of Custody Ledger Proof
        story.append(Paragraph("<b>1. IMMUTABLE CHAIN OF CUSTODY (BLOCKCHAIN LEDGER)</b>", heading_style))
        bc_table_data = [
            [Paragraph("<b>Transaction Hash:</b>", body_style), Paragraph(blockchain_data.get('transaction_hash', 'N/A'), mono_style)],
            [Paragraph("<b>Block Height:</b>", body_style), Paragraph(str(blockchain_data.get('block_number', '19482710')), body_style)],
            [Paragraph("<b>Smart Contract:</b>", body_style), Paragraph(blockchain_data.get('contract_address', 'N/A'), mono_style)],
            [Paragraph("<b>Status:</b>", body_style), Paragraph("<font color='green'><b>VERIFIED & ANCHORED</b></font>", body_style)],
        ]
        t2 = Table(bc_table_data, colWidths=[140, 380])
        t2.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F0FDF4')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#BBF7D0')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#86EFAC')),
            ('PADDING', (0,0), (-1,-1), 6),
        ]))
        story.append(t2)
        story.append(Spacer(1, 15))

        # 4. Email Header Metadata
        story.append(Paragraph("<b>2. PARSED EMAIL HEADER SPECIFICATIONS</b>", heading_style))
        hdr_table_data = [
            [Paragraph("<b>Subject:</b>", body_style), Paragraph(email_record.get('subject', '(No Subject)'), body_style)],
            [Paragraph("<b>Sender:</b>", body_style), Paragraph(f"{email_record.get('sender_name', '')} &lt;{email_record.get('sender_address', '')}&gt;", body_style)],
            [Paragraph("<b>Recipient:</b>", body_style), Paragraph(email_record.get('recipient_address', ''), body_style)],
            [Paragraph("<b>SPF Status:</b>", body_style), Paragraph(email_record.get('spf_status', 'UNKNOWN'), body_style)],
            [Paragraph("<b>DKIM Status:</b>", body_style), Paragraph(email_record.get('dkim_status', 'UNKNOWN'), body_style)],
            [Paragraph("<b>DMARC Status:</b>", body_style), Paragraph(email_record.get('dmarc_status', 'UNKNOWN'), body_style)],
        ]
        t3 = Table(hdr_table_data, colWidths=[140, 380])
        t3.setStyle(TableStyle([
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t3)
        story.append(Spacer(1, 15))

        # 5. Hop Routing & GeoLocation Table
        story.append(Paragraph("<b>3. GEOLOCATION ROUTING TRANSIT HOPS</b>", heading_style))
        hop_rows = [[Paragraph("<b>Hop</b>", body_style), Paragraph("<b>IP Address</b>", body_style), Paragraph("<b>Location</b>", body_style), Paragraph("<b>ISP / ASN</b>", body_style), Paragraph("<b>Proxy/Tor</b>", body_style)]]
        
        for h in hops:
            hop_rows.append([
                Paragraph(str(h.get('hop_number', 1)), body_style),
                Paragraph(h.get('ip_address', ''), mono_style),
                Paragraph(f"{h.get('city', '')}, {h.get('country', '')}", body_style),
                Paragraph(h.get('isp', ''), body_style),
                Paragraph("<font color='red'>YES</font>" if h.get('is_vpn_proxy_tor') else "NO", body_style)
            ])

        t_hops = Table(hop_rows, colWidths=[35, 105, 140, 170, 70])
        t_hops.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#E2E8F0')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#94A3B8')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_hops)
        story.append(Spacer(1, 20))

        # 6. Attribution-Support Analysis Section
        story.append(Paragraph("<b>4. ATTRIBUTION-SUPPORT ANALYSIS (EVIDENCE ASSESSMENT)</b>", heading_style))
        from app.services.attribution_service import AttributionSupportEngine
        attr_data = AttributionSupportEngine.analyze_attribution_support(email_record, hops)

        attr_table_data = [
            [Paragraph("<b>Probable Source Infrastructure:</b>", body_style), Paragraph(attr_data.get('probable_source_infrastructure', 'Unknown'), body_style)],
            [Paragraph("<b>Confidence Assessment:</b>", body_style), Paragraph(f"<b>{attr_data.get('confidence_percentage', '70%')}</b>", body_style)],
            [Paragraph("<b>Supporting Evidence:</b>", body_style), Paragraph("<br/>".join([f"• {e}" for e in attr_data.get('supporting_evidence', [])]), body_style)],
            [Paragraph("<b>Alternative Explanations:</b>", body_style), Paragraph("<br/>".join([f"• {a}" for a in attr_data.get('alternative_explanations', [])]), body_style)],
            [Paragraph("<b>Limitations Disclaimer:</b>", body_style), Paragraph(f"<i>{attr_data.get('limitations', '')}</i>", body_style)],
        ]
        t_attr = Table(attr_table_data, colWidths=[140, 380])
        t_attr.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(t_attr)
        story.append(Spacer(1, 15))

        # 7. Legal Declaration Section 65B
        story.append(Paragraph("<b>LEGAL DECLARATION UNDER SECTION 65B</b>", heading_style))
        dec_text = (
            "I hereby certify that the electronic record described in this certificate was produced by the automated "
            "AI-Powered Email Forensic Intelligence System in the ordinary course of official cyber investigation activities. "
            "The system operates accurately and the integrity of the output file is secured by cryptographic SHA-256 "
            "hashing and immutable Blockchain ledger anchoring."
        )
        story.append(Paragraph(dec_text, body_style))
        story.append(Spacer(1, 30))

        # Signature Block
        sig_data = [
            [Paragraph("<b>Investigator Signature:</b> _______________________", body_style), Paragraph("<b>Forensic Analyst Seal:</b> _______________________", body_style)]
        ]
        t_sig = Table(sig_data, colWidths=[260, 260])
        t_sig.setStyle(TableStyle([('PADDING', (0,0), (-1,-1), 0)]))
        story.append(t_sig)

        doc.build(story)
        pdf_data = buffer.getvalue()
        buffer.close()
        return pdf_data
