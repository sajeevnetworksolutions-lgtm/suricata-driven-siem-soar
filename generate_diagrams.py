import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches

def create_architecture_diagram(output_path):
    fig, ax = plt.subplots(figsize=(10, 5.2), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Color Palette
    c_bg_layer = '#F8FAFC'
    c_traffic = '#E0E7FF'
    c_traffic_border = '#4338CA'
    c_ids = '#FEF3C7'
    c_ids_border = '#B45309'
    c_siem = '#DCFCE7'
    c_siem_border = '#15803D'
    c_soar = '#FEE2E2'
    c_soar_border = '#B91C1C'
    c_soc = '#F3E8FF'
    c_soc_border = '#7E22CE'

    # 1. Traffic Layer
    rect_traffic = patches.FancyBboxPatch((2, 60), 20, 32, boxstyle="round,pad=1.5", fc=c_traffic, ec=c_traffic_border, lw=2)
    ax.add_patch(rect_traffic)
    ax.text(12, 85, "1. TRAFFIC SOURCE", weight='bold', fontsize=9, ha='center', color=c_traffic_border)
    ax.text(12, 75, "• Live NIC Traffic\n• Web Application (:8080)\n• Attack Simulator\n• Canary Token Traps", fontsize=7.5, ha='center', color='#1E1B4B')

    # 2. IDS Layer
    rect_ids = patches.FancyBboxPatch((26, 60), 22, 32, boxstyle="round,pad=1.5", fc=c_ids, ec=c_ids_border, lw=2)
    ax.add_patch(rect_ids)
    ax.text(37, 85, "2. SURICATA IDS 7.x", weight='bold', fontsize=9, ha='center', color=c_ids_border)
    ax.text(37, 73, "• Multi-threaded Sniffer\n• Custom .rules Engine\n• MITRE ATT&CK Signatures\n• Protocol Parsers (L3-L7)\n• EVE JSON Structured Logs", fontsize=7.5, ha='center', color='#78350F')

    # 3. SIEM Ingestion Layer
    rect_siem = patches.FancyBboxPatch((52, 60), 22, 32, boxstyle="round,pad=1.5", fc=c_siem, ec=c_siem_border, lw=2)
    ax.add_patch(rect_siem)
    ax.text(63, 85, "3. CENTRAL SIEM", weight='bold', fontsize=9, ha='center', color=c_siem_border)
    ax.text(63, 73, "• Filebeat Log Shipper\n• ECS Normalization\n• Elasticsearch 8.x Cluster\n• Index Lifecycle Mgt\n• Fast JSON Aggregation", fontsize=7.5, ha='center', color='#14532D')

    # 4. SOC UI Layer
    rect_soc = patches.FancyBboxPatch((78, 60), 20, 32, boxstyle="round,pad=1.5", fc=c_soc, ec=c_soc_border, lw=2)
    ax.add_patch(rect_soc)
    ax.text(88, 85, "4. KIBANA SOC UI", weight='bold', fontsize=9, ha='center', color=c_soc_border)
    ax.text(88, 73, "• Visual Dashboards\n• Threat Hunting Timelines\n• Geographic Attacker Map\n• Protocol Distribution\n• SIEM Detection Rules", fontsize=7.5, ha='center', color='#581C87')

    # 5. SOAR Automated Engine (Bottom Span)
    rect_soar = patches.FancyBboxPatch((15, 8), 70, 38, boxstyle="round,pad=2", fc=c_soar, ec=c_soar_border, lw=2)
    ax.add_patch(rect_soar)
    ax.text(50, 40, "5. AUTOMATED SOAR INCIDENT RESPONSE ENGINE (:8000)", weight='bold', fontsize=10, ha='center', color=c_soar_border)

    # SOAR Playbook Sub-boxes
    pb_boxes = [
        (18, 14, 15, 20, "IP Quarantine", "• Dynamic Drop Rule\n• 300s TTL Auto-Unban\n• Anti-Lockout Safe"),
        (35, 14, 15, 20, "Threat Intel", "• AbuseIPDB Lookup\n• GeoIP & ASN Origin\n• Score: 0 - 100"),
        (52, 14, 15, 20, "Forensics", "• Case JSON Dossier\n• Raw Payload Capture\n• L4-L7 Protocol Dump"),
        (69, 14, 14, 20, "SOC Alerting", "• Live WebSockets\n• Discord / Slack\n• One-Click Pardon")
    ]
    for x, y, w, h, title, text in pb_boxes:
        pb_p = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.8", fc='#FFFFFF', ec='#FCA5A5', lw=1.2)
        ax.add_patch(pb_p)
        ax.text(x + w/2, y + h - 4, title, weight='bold', fontsize=7.5, ha='center', color='#991B1B')
        ax.text(x + w/2, y + 4, text, fontsize=6.2, ha='center', color='#334155')

    # Arrows
    arrow_style = dict(arrowstyle="->", lw=2, color="#475569")
    # Traffic -> IDS
    ax.annotate("", xy=(26, 76), xytext=(22, 76), arrowprops=arrow_style)
    # IDS -> SIEM
    ax.annotate("", xy=(52, 76), xytext=(48, 76), arrowprops=arrow_style)
    # SIEM -> SOC
    ax.annotate("", xy=(78, 76), xytext=(74, 76), arrowprops=arrow_style)
    # IDS -> SOAR
    ax.annotate("", xy=(40, 48), xytext=(37, 60), arrowprops=dict(arrowstyle="->", lw=2, color="#B91C1C", ls="--"))
    # SOAR -> SOC UI
    ax.annotate("", xy=(85, 60), xytext=(65, 48), arrowprops=dict(arrowstyle="->", lw=2, color="#7E22CE", ls="--"))

    plt.tight_layout()
    plt.savefig(output_path, bbox_inches='tight')
    plt.close()
    print(f"[OK] Created Architecture Diagram: {output_path}")

def create_workflow_diagram(output_path):
    fig, ax = plt.subplots(figsize=(10, 4.2), dpi=300)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    steps = [
        (3, 35, 14, 30, "1. Inbound Attack", "Malicious Packet\n(SQLi / Brute-Force /\nC2 Beacon / Exfil)", "#EEF2FF", "#4F46E5"),
        (20, 35, 14, 30, "2. Suricata IDS", "Matches Signature\nExtracts L3-L7 Info\nWrites eve.json", "#FEF3C7", "#D97706"),
        (37, 35, 14, 30, "3. SOAR Trigger", "Event Tailing\nEvaluates Severity\n(Sev 1 = Critical)", "#FEE2E2", "#DC2626"),
        (54, 35, 14, 30, "4. Containment", "Dynamic IP Ban\nStarts 300s TTL\nEnriches Threat Intel", "#DCFCE7", "#16A34A"),
        (71, 35, 14, 30, "5. Forensics", "Generates Case File\nDumps Raw Payload\nAttaches MITRE Tag", "#F3E8FF", "#9333EA"),
        (88, 35, 10, 30, "6. SOC Alert", "WebSocket Push\nDiscord/Slack\nAnalyst Unban", "#E0F2FE", "#0284C7")
    ]

    for x, y, w, h, title, text, fc, ec in steps:
        patch = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=1", fc=fc, ec=ec, lw=1.8)
        ax.add_patch(patch)
        ax.text(x + w/2, y + h - 6, title, weight='bold', fontsize=8, ha='center', color=ec)
        ax.text(x + w/2, y + 6, text, fontsize=6.8, ha='center', color='#1E293B')

    for i in range(len(steps) - 1):
        x_start = steps[i][0] + steps[i][2]
        x_end = steps[i+1][0]
        ax.annotate("", xy=(x_end, 50), xytext=(x_start, 50), arrowprops=dict(arrowstyle="->", lw=2, color="#64748B"))

    # Return loop for TTL Unban
    ax.annotate("Auto-Unban (TTL Expired / Analyst Pardon)", xy=(10, 32), xytext=(61, 15),
                arrowprops=dict(arrowstyle="->", lw=1.5, color="#16A34A", connectionstyle="arc3,rad=0.2"),
                fontsize=7.5, weight='bold', color="#16A34A", ha='center')

    plt.tight_layout()
    plt.savefig(output_path, bbox_inches='tight')
    plt.close()
    print(f"[OK] Created Workflow Diagram: {output_path}")

if __name__ == "__main__":
    assets_dir = os.path.join(os.path.dirname(__file__), "docs", "assets")
    os.makedirs(assets_dir, exist_ok=True)
    create_architecture_diagram(os.path.join(assets_dir, "architecture_diagram.png"))
    create_workflow_diagram(os.path.join(assets_dir, "workflow_diagram.png"))
