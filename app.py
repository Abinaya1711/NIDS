"""
app.py — Flask Application for AI-NIDS
Main entry point: serves the SOC dashboard, API endpoints, and coordinates
the Suricata monitor and AI analysis engine.
"""

import os
from flask import Flask, render_template, jsonify, request, Response
from database import (
    init_db, get_alerts, get_alert_by_id, get_alert_stats,
    get_top_source_ips, get_alerts_timeline, save_ai_analysis,
    get_ai_analysis, get_all_analyses, save_report, get_reports,
    get_report_by_id, get_total_alert_count
)
from ai_engine import AIEngine
from report_generator import generate_incident_report, generate_summary_report
from suricata_monitor import SuricataMonitor

app = Flask(__name__)

# Initialize AI engine
ai = AIEngine(model="llama3", base_url="http://localhost:11434")

# Initialize Suricata monitor
# Configure the eve.json path — defaults to local logs/eve.json in the workspace
DEFAULT_LOCAL_EVE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs', 'eve.json')
EVE_PATH = os.environ.get('EVE_PATH', DEFAULT_LOCAL_EVE)
monitor = SuricataMonitor(eve_path=EVE_PATH)


# ─────────────────────────────────────────
# Page Routes
# ─────────────────────────────────────────

@app.route('/')
def index():
    """Redirect to dashboard."""
    return render_template('dashboard.html')


@app.route('/dashboard')
def dashboard():
    """Main SOC dashboard."""
    return render_template('dashboard.html')


@app.route('/analytics')
def analytics():
    """Analytics and charts page."""
    return render_template('analytics.html')


@app.route('/analysis')
def analysis():
    """AI threat analysis page."""
    return render_template('analysis.html')


@app.route('/reports')
def reports():
    """Reports page."""
    return render_template('reports.html')


# ─────────────────────────────────────────
# API Routes — Data
# ─────────────────────────────────────────

@app.route('/api/alerts')
def api_alerts():
    """Get paginated alerts with optional severity filter."""
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    severity = request.args.get('severity', None, type=int)
    alerts = get_alerts(limit=limit, offset=offset, severity=severity)
    total = get_total_alert_count()
    return jsonify({'alerts': alerts, 'total': total})


@app.route('/api/alerts/<int:alert_id>')
def api_alert_detail(alert_id):
    """Get a single alert by ID."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    return jsonify(alert)


@app.route('/api/stats')
def api_stats():
    """Get aggregate alert statistics."""
    stats = get_alert_stats()
    return jsonify(stats)


@app.route('/api/top-ips')
def api_top_ips():
    """Get top source IPs."""
    limit = request.args.get('limit', 10, type=int)
    ips = get_top_source_ips(limit=limit)
    return jsonify(ips)


@app.route('/api/timeline')
def api_timeline():
    """Get alert timeline data."""
    days = request.args.get('days', 7, type=int)
    timeline = get_alerts_timeline(days=days)
    return jsonify(timeline)


# ─────────────────────────────────────────
# API Routes — AI Analysis
# ─────────────────────────────────────────

@app.route('/api/analyze/<int:alert_id>', methods=['POST'])
def api_analyze(alert_id):
    """Trigger AI analysis for a specific alert."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404

    # Run AI analysis
    result = ai.analyze_alert(alert)

    if result['success']:
        # Save to database
        save_ai_analysis(
            alert_id=alert_id,
            analysis_text=result['analysis_text'],
            threat_level=result.get('threat_level'),
            recommendations=result.get('recommendations')
        )
        return jsonify({
            'success': True,
            'analysis': result
        })
    else:
        return jsonify({
            'success': False,
            'error': result['error']
        }), 503


@app.route('/api/analysis/<int:alert_id>')
def api_get_analysis(alert_id):
    """Get stored AI analysis for an alert."""
    analysis = get_ai_analysis(alert_id)
    if not analysis:
        return jsonify({'error': 'No analysis found for this alert'}), 404
    return jsonify(analysis)


@app.route('/api/analyses')
def api_all_analyses():
    """Get all AI analyses."""
    analyses = get_all_analyses()
    return jsonify(analyses)


# ─────────────────────────────────────────
# API Routes — Reports
# ─────────────────────────────────────────

@app.route('/api/report/generate/<int:alert_id>', methods=['POST'])
def api_generate_report(alert_id):
    """Generate an incident report for an alert."""
    alert = get_alert_by_id(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404

    ai_analysis = get_ai_analysis(alert_id)
    report_content = generate_incident_report(alert, ai_analysis)

    report_id = save_report(
        alert_id=alert_id,
        report_content=report_content,
        report_type='incident'
    )

    return jsonify({'success': True, 'report_id': report_id})


@app.route('/api/report/summary', methods=['POST'])
def api_summary_report():
    """Generate a summary report."""
    stats = get_alert_stats()
    top_ips = get_top_source_ips()
    recent = get_alerts(limit=10)

    report_content = generate_summary_report(stats, top_ips, recent)
    report_id = save_report(
        alert_id=None,
        report_content=report_content,
        report_type='summary'
    )

    return jsonify({'success': True, 'report_id': report_id})


@app.route('/api/reports')
def api_reports():
    """Get all generated reports."""
    reports_list = get_reports()
    return jsonify(reports_list)


@app.route('/api/report/<int:report_id>')
def api_report_detail(report_id):
    """Get a single report."""
    report = get_report_by_id(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
    return jsonify(report)


@app.route('/api/report/<int:report_id>/download')
def api_download_report(report_id):
    """Download a report as a text file."""
    report = get_report_by_id(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404

    return Response(
        report['report_content'],
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename=report_{report_id}.txt'}
    )


# ─────────────────────────────────────────
# API Routes — System Status
# ─────────────────────────────────────────

@app.route('/api/status')
def api_status():
    """Get system component status."""
    return jsonify({
        'suricata': monitor.get_status(),
        'ollama': {
            'available': ai.is_available(),
            'model': ai.model,
            'base_url': ai.base_url
        }
    })


# ─────────────────────────────────────────
# Startup
# ─────────────────────────────────────────

if __name__ == '__main__':
    # Initialize database
    init_db()

    # Start Suricata monitor in background
    monitor.start()

    print("\n" + "=" * 60)
    print("  AI-NIDS — AI-Powered Network Intrusion Detection System")
    print("=" * 60)
    print(f"  Dashboard  : http://127.0.0.1:5000")
    print(f"  Suricata   : Monitoring {EVE_PATH}")
    print(f"  Ollama     : {'Connected' if ai.is_available() else 'Not available'}")
    print("=" * 60 + "\n")

    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
