"""
report_generator.py — Incident Report Generator for AI-NIDS
Generates structured incident reports from alerts and AI analysis data.
"""

from datetime import datetime


def generate_incident_report(alert, ai_analysis=None):
    """
    Generate a full incident report for a single alert.
    Returns a formatted report string.
    """
    report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    severity_map = {1: 'CRITICAL', 2: 'HIGH', 3: 'MEDIUM', 4: 'LOW'}
    severity_label = severity_map.get(alert.get('severity', 3), 'UNKNOWN')

    report = f"""
{'='*70}
          AI-NIDS INCIDENT REPORT
{'='*70}

Report Generated: {report_time}
Report Type: Security Incident

{'─'*70}
ALERT DETAILS
{'─'*70}

  Alert ID      : {alert.get('id', 'N/A')}
  Timestamp     : {alert.get('timestamp', 'N/A')}
  Signature     : {alert.get('signature', 'N/A')}
  Signature ID  : {alert.get('signature_id', 'N/A')}
  Severity      : {severity_label} ({alert.get('severity', 'N/A')})
  Category      : {alert.get('category', 'N/A')}

{'─'*70}
NETWORK INFORMATION
{'─'*70}

  Source IP      : {alert.get('src_ip', 'N/A')}
  Source Port    : {alert.get('src_port', 'N/A')}
  Destination IP : {alert.get('dest_ip', 'N/A')}
  Dest. Port     : {alert.get('dest_port', 'N/A')}
  Protocol       : {alert.get('protocol', 'N/A')}
"""

    if ai_analysis:
        analysis_text = ai_analysis.get('analysis_text', '')
        threat_level = ai_analysis.get('threat_level', 'N/A')

        report += f"""
{'─'*70}
AI THREAT ANALYSIS
{'─'*70}

  AI Risk Level : {threat_level}
  Analyzed At   : {ai_analysis.get('analyzed_at', 'N/A')}

{analysis_text}
"""
    else:
        report += f"""
{'─'*70}
AI THREAT ANALYSIS
{'─'*70}

  No AI analysis has been performed for this alert.
  Use the AI Analysis page to analyze this alert with Llama 3.
"""

    report += f"""
{'─'*70}
RESPONSE ACTIONS
{'─'*70}

  [ ] Investigate source IP: {alert.get('src_ip', 'N/A')}
  [ ] Check destination service on port: {alert.get('dest_port', 'N/A')}
  [ ] Review related alerts from same source
  [ ] Update firewall rules if necessary
  [ ] Escalate to security team if severity is HIGH or CRITICAL

{'='*70}
         END OF REPORT — AI-NIDS
{'='*70}
"""

    return report


def generate_summary_report(stats, top_ips=None, recent_alerts=None):
    """
    Generate an aggregate summary report.
    """
    report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    report = f"""
{'='*70}
          AI-NIDS SUMMARY REPORT
{'='*70}

Report Generated: {report_time}
Report Type: Summary

{'─'*70}
ALERT STATISTICS
{'─'*70}

  Total Alerts   : {stats.get('total', 0)}
  Alerts Today   : {stats.get('today', 0)}

  By Severity:
    Critical     : {stats.get('by_severity', {}).get('critical', 0)}
    High         : {stats.get('by_severity', {}).get('high', 0)}
    Medium       : {stats.get('by_severity', {}).get('medium', 0)}
    Low          : {stats.get('by_severity', {}).get('low', 0)}
"""

    if stats.get('by_category'):
        report += f"\n{'─'*70}\nATTACK CATEGORIES\n{'─'*70}\n\n"
        for cat in stats['by_category']:
            report += f"  {cat['category']:40s} : {cat['count']}\n"

    if top_ips:
        report += f"\n{'─'*70}\nTOP SOURCE IPs\n{'─'*70}\n\n"
        for ip_data in top_ips:
            report += f"  {ip_data['src_ip']:40s} : {ip_data['count']} alerts\n"

    if recent_alerts:
        report += f"\n{'─'*70}\nRECENT ALERTS (Last 10)\n{'─'*70}\n\n"
        for alert in recent_alerts[:10]:
            sev = {1: 'CRIT', 2: 'HIGH', 3: 'MED ', 4: 'LOW '}.get(alert.get('severity', 3), '??? ')
            report += f"  [{sev}] {alert.get('timestamp', '')[:19]}  {alert.get('signature', '')[:50]}\n"
            report += f"         {alert.get('src_ip', '')} → {alert.get('dest_ip', '')}\n"

    report += f"""
{'='*70}
         END OF REPORT — AI-NIDS
{'='*70}
"""

    return report
