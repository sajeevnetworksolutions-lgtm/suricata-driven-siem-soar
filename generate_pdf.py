import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "PROJECT SYNOPSIS: Suricata-Driven SIEM with SOAR Integration")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(54, 744, 558, 744)

        # Footer
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 36, footer_text)
        self.drawString(54, 36, "Confidential - Academic & Research Project Submission")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 48, 558, 48)
        self.restoreState()

def create_synopsis_pdf(output_paths):
    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        alignment=TA_CENTER,
        textColor=colors.HexColor('#2563EB'),
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=10,
        spaceAfter=5
    )

    body_style = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        alignment=TA_JUSTIFY,
        textColor=colors.HexColor('#334155'),
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'BulletCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        leftIndent=12,
        textColor=colors.HexColor('#334155'),
        spaceAfter=3
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor('#1E293B')
    )

    table_hdr_style = ParagraphStyle(
        'TableHdr',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    story = []

    # Title Block
    story.append(Spacer(1, 10))
    story.append(Paragraph("PROJECT SYNOPSIS", title_style))
    story.append(Paragraph("Suricata-Driven SIEM with Automated Incident Response and SOAR Integration", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563EB'), spaceBefore=2, spaceAfter=10))

    # 1. Domain & Area of Study
    story.append(Paragraph("1. DOMAIN & AREA OF STUDY", h1_style))
    story.append(Paragraph("<b>Primary Domain:</b> Cyber Security, Threat Intelligence & Network Defense", bullet_style))
    story.append(Paragraph("<b>Specialization:</b> Network Security Monitoring (NSM), SIEM (Security Information and Event Management), SOAR (Security Orchestration, Automation, and Response), Detection Engineering.", bullet_style))
    story.append(Spacer(1, 4))

    # 2. Abstract
    story.append(Paragraph("2. ABSTRACT", h1_style))
    abstract_text = (
        "Modern enterprise IT environments face an unprecedented volume of complex cyber threats ranging from stealthy "
        "reconnaissance and credential brute-forcing to sophisticated web exploits, Command-and-Control (C2) botnets, and "
        "data exfiltration. Traditional Intrusion Detection Systems (IDS) operate primarily in silos: they generate alerts without "
        "centralized correlation, visual analytics, or rapid automated containment capabilities, causing severe alert fatigue among "
        "Security Operations Center (SOC) analysts. This project delivers an end-to-end, lightweight, open-source <b>Network Security "
        "Monitoring and SOAR framework</b>. The proposed architecture unifies <b>Suricata IDS</b> for multi-threaded deep packet inspection, "
        "<b>EVE JSON</b> structured security telemetry, <b>Filebeat</b> with Elastic Common Schema (ECS) normalization, <b>Elasticsearch & "
        "Kibana</b> for centralized storage and interactive visual analytics, and an <b>Autonomous SOAR Engine</b>. The system autonomously "
        "detects cyber attacks, queries live Threat Intelligence feeds (AbuseIPDB/GeoIP), enforces dynamic IP quarantines with Time-To-Live (TTL) "
        "cooling-off timers, generates structured forensic evidence dossiers, and streams real-time telemetry to security analysts."
    )
    story.append(Paragraph(abstract_text, body_style))
    story.append(Spacer(1, 4))

    # 3. Problem Statement & Research Gap
    story.append(Paragraph("3. PROBLEM STATEMENT & RESEARCH GAP", h1_style))
    story.append(Paragraph("• <b>Tool Fragmentation & Silos:</b> Standalone firewalls, IDSs, and application logs operate independently, hindering end-to-end incident correlation.", bullet_style))
    story.append(Paragraph("• <b>Alert Fatigue & Inaction:</b> Traditional IDSs alert on threats but do not actively mitigate them, leaving networks vulnerable during off-hours.", bullet_style))
    story.append(Paragraph("• <b>High Mean Time to Respond (MTTR):</b> Manual analyst triage takes hours to days, allowing attackers to exfiltrate assets before containment.", bullet_style))
    story.append(Paragraph("• <b>Risks of Rigid Firewall Lockouts:</b> Legacy blocking scripts permanently ban IPs, leading to accidental denial of service for benign users due to IP reuse or spoofing.", bullet_style))
    story.append(Paragraph("<b>Research Gap Addressed:</b> The lack of an open-source, reproducible, lightweight pipeline connecting <i>Deep Packet Inspection &rarr; Centralized SIEM Analytics &rarr; Dynamic, Reversible SOAR Containment &rarr; Automated Forensic Evidence Collection</i>.", body_style))
    story.append(Spacer(1, 4))

    # 4. Objectives of the Project
    story.append(Paragraph("4. OBJECTIVES OF THE PROJECT", h1_style))
    story.append(Paragraph("1. <b>Real-Time Threat Detection:</b> Deploy Suricata 7.x with custom signatures mapped to the <b>MITRE ATT&CK</b> framework across 6 major threat vectors.", bullet_style))
    story.append(Paragraph("2. <b>ECS Standardization:</b> Ingest multi-protocol telemetry (HTTP, TLS, DNS, SSH, Flow) into standardized Elastic Common Schema fields via Filebeat.", bullet_style))
    story.append(Paragraph("3. <b>Centralized SOC Analytics:</b> Design interactive Kibana dashboards tracking threat distributions, attacker geographic origins, and protocol anomalies.", bullet_style))
    story.append(Paragraph("4. <b>Autonomous Incident Response:</b> Build an event-driven SOAR engine executing sub-second containment (IP Quarantine, Threat Intel scoring, Forensics capture).", bullet_style))
    story.append(Paragraph("5. <b>Safe Cooling-off Mitigation:</b> Implement auto-expiring TTL timers (e.g. 300s) to eliminate accidental permanent lockouts.", bullet_style))
    story.append(Paragraph("6. <b>Interactive Simulation & Canary Lab:</b> Build a multi-vector attack simulator and honeypot canary tokens to validate detection efficacy and latency.", bullet_style))
    story.append(Spacer(1, 4))

    # 5. Modular Breakdown Table
    story.append(Paragraph("5. SYSTEM MODULES & THREAT VECTORS", h1_style))
    
    table_data = [
        [
            Paragraph("<b>Module</b>", table_hdr_style),
            Paragraph("<b>Core Functionality</b>", table_hdr_style),
            Paragraph("<b>Threat Vectors Covered</b>", table_hdr_style)
        ],
        [
            Paragraph("<b>Module 1: Detection Engine</b>", table_cell_style),
            Paragraph("Suricata 7.x Multi-threaded Deep Packet Inspection & Custom Signatures", table_cell_style),
            Paragraph("• Port Scanning / Recon (T1595)<br/>• Auth Brute-Force (T1110)<br/>• Web Attacks: SQLi, XSS, LFI (T1190)<br/>• Malware C2 Beacons (T1071)<br/>• DNS Tunneling Exfil (T1048)<br/>• Data Exfiltration (T1048)", table_cell_style)
        ],
        [
            Paragraph("<b>Module 2: SIEM Ingestion</b>", table_cell_style),
            Paragraph("Filebeat Shipper + Elasticsearch + Kibana Visual Dashboards", table_cell_style),
            Paragraph("• EVE JSON ingestion & ECS mapping<br/>• Centralized log indexing & search<br/>• Real-time SOC visualizations", table_cell_style)
        ],
        [
            Paragraph("<b>Module 3: SOAR Automation</b>", table_cell_style),
            Paragraph("FastAPI Orchestrator + WebSocket Real-Time Alert Stream", table_cell_style),
            Paragraph("• Dynamic IP Quarantine (300s TTL)<br/>• Threat Intel Enrichment (AbuseIPDB)<br/>• Forensic Case Dossier Generator<br/>• Discord/Slack Webhook Dispatcher", table_cell_style)
        ],
        [
            Paragraph("<b>Module 4: Attack Simulator</b>", table_cell_style),
            Paragraph("Python CLI Suite + Interactive Threat Portal & Canary Trap Lab (:8080)", table_cell_style),
            Paragraph("• 6 automated attack scenarios<br/>• Click-to-trigger web testbed<br/>• Restricted canary file honeypot traps", table_cell_style)
        ]
    ]

    t = Table(table_data, colWidths=[120, 160, 224])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#F8FAFC')]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 6))

    # 6. Technical Specifications
    story.append(Paragraph("6. TECHNICAL SPECIFICATIONS", h1_style))
    story.append(Paragraph("• <b>Technologies:</b> Suricata 7.x, Elasticsearch 8.x, Kibana 8.x, Filebeat 8.x, FastAPI, WebSockets, Python 3.11+, Docker.", bullet_style))
    story.append(Paragraph("• <b>Supported OS:</b> Windows 10/11, Linux (Ubuntu 22.04+), macOS. Minimum 8 GB RAM (16 GB for full cluster).", bullet_style))
    story.append(Spacer(1, 4))

    # 7. Key Contributions & Novelty
    story.append(Paragraph("7. KEY CONTRIBUTIONS & NOVELTY", h1_style))
    story.append(Paragraph("1. <b>Sub-Second Threat Containment:</b> Reduces Mean Time to Respond (MTTR) from hours to sub-second automated isolation.", bullet_style))
    story.append(Paragraph("2. <b>Safe Reversible Containment:</b> Auto-expiring TTL timers prevent permanent accidental denial-of-service lockouts.", bullet_style))
    story.append(Paragraph("3. <b>Automated Forensic Evidentiary Dossiers:</b> Generates structured JSON case files with decoded payloads and headers for fast triage.", bullet_style))
    story.append(Paragraph("4. <b>100% Open-Source & Reproducible:</b> Eliminates costly enterprise software licenses using a modular, containerized architecture.", bullet_style))
    story.append(Spacer(1, 4))

    # 8. Conclusion & Future Scope
    story.append(Paragraph("8. CONCLUSION & FUTURE SCOPE", h1_style))
    story.append(Paragraph(
        "The <b>Suricata-Driven SIEM with SOAR Integration</b> demonstrates that enterprise-grade threat detection, analytical visibility, "
        "and automated incident response can be successfully unified into an accessible, open-source cyber defense framework. "
        "<b>Future enhancements</b> include integrating Machine Learning (Isolation Forests) for zero-day behavioral anomaly detection, "
        "cloud-native expansion with Kubernetes DaemonSets, and STIX/TAXII threat intelligence sharing.",
        body_style
    ))

    # Build PDF for each target path
    for path in output_paths:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        doc = SimpleDocTemplate(
            path,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )
        doc.build(story, canvasmaker=NumberedCanvas)
        print(f"[OK] Successfully generated PDF at: {path}")

if __name__ == "__main__":
    downloads_pdf = r"C:\Users\91990\Downloads\Suricata_SIEM_SOAR_Project_Synopsis.pdf"
    docs_pdf = os.path.join(os.path.dirname(__file__), "docs", "Suricata_SIEM_SOAR_Project_Synopsis.pdf")
    create_synopsis_pdf([downloads_pdf, docs_pdf])
