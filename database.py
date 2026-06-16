"""
database.py — SQLite Database Module for AI-NIDS
Handles all database operations: schema creation, alert storage, queries, and AI analysis storage.
All queries use parameterized SQL to prevent injection.
"""

import sqlite3
import os
from datetime import datetime

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
DB_PATH = os.path.join(DB_DIR, 'alerts.db')


def get_connection():
    """Get a database connection with row factory enabled."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            src_port INTEGER,
            dest_port INTEGER,
            protocol TEXT,
            signature TEXT NOT NULL,
            signature_id INTEGER,
            severity INTEGER DEFAULT 3,
            category TEXT,
            raw_json TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ai_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            analysis_text TEXT NOT NULL,
            threat_level TEXT,
            recommendations TEXT,
            analyzed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER,
            report_type TEXT DEFAULT 'incident',
            report_content TEXT NOT NULL,
            generated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    ''')

    # Indexes for performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_ai_analyses_alert_id ON ai_analyses(alert_id)')

    conn.commit()
    conn.close()
    print("[DB] Database initialized successfully.")


def insert_alert(timestamp, src_ip, dest_ip, src_port, dest_port, protocol,
                 signature, signature_id, severity, category, raw_json=None):
    """Insert a new alert into the database. Returns the new alert ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (timestamp, src_ip, dest_ip, src_port, dest_port,
                          protocol, signature, signature_id, severity, category, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, src_ip, dest_ip, src_port, dest_port, protocol,
          signature, signature_id, severity, category, raw_json))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id


def get_alerts(limit=50, offset=0, severity=None):
    """Get alerts with optional severity filter, ordered by most recent."""
    conn = get_connection()
    cursor = conn.cursor()

    if severity is not None:
        cursor.execute('''
            SELECT * FROM alerts WHERE severity = ?
            ORDER BY timestamp DESC LIMIT ? OFFSET ?
        ''', (severity, limit, offset))
    else:
        cursor.execute('''
            SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ? OFFSET ?
        ''', (limit, offset))

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_alert_by_id(alert_id):
    """Get a single alert by ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts WHERE id = ?', (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_alert_stats():
    """Get aggregate statistics about alerts."""
    conn = get_connection()
    cursor = conn.cursor()

    stats = {}

    # Total alerts
    cursor.execute('SELECT COUNT(*) as total FROM alerts')
    stats['total'] = cursor.fetchone()['total']

    # By severity
    cursor.execute('''
        SELECT severity, COUNT(*) as count FROM alerts
        GROUP BY severity ORDER BY severity
    ''')
    severity_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'low'}
    stats['by_severity'] = {}
    for row in cursor.fetchall():
        label = severity_map.get(row['severity'], f"severity_{row['severity']}")
        stats['by_severity'][label] = row['count']

    # Ensure all severity levels exist
    for label in ['critical', 'high', 'medium', 'low']:
        if label not in stats['by_severity']:
            stats['by_severity'][label] = 0

    # By category
    cursor.execute('''
        SELECT category, COUNT(*) as count FROM alerts
        WHERE category IS NOT NULL
        GROUP BY category ORDER BY count DESC LIMIT 10
    ''')
    stats['by_category'] = [dict(row) for row in cursor.fetchall()]

    # Alerts today
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute('SELECT COUNT(*) as count FROM alerts WHERE timestamp LIKE ?', (f'{today}%',))
    stats['today'] = cursor.fetchone()['count']

    conn.close()
    return stats


def get_top_source_ips(limit=10):
    """Get the most frequent source IPs."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT src_ip, COUNT(*) as count FROM alerts
        GROUP BY src_ip ORDER BY count DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_alerts_timeline(days=7):
    """Get alert counts grouped by hour for the specified number of days."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, COUNT(*) as count
        FROM alerts
        WHERE timestamp >= datetime('now', ?)
        GROUP BY hour ORDER BY hour
    ''', (f'-{days} days',))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def save_ai_analysis(alert_id, analysis_text, threat_level=None, recommendations=None):
    """Store an AI analysis result."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO ai_analyses (alert_id, analysis_text, threat_level, recommendations)
        VALUES (?, ?, ?, ?)
    ''', (alert_id, analysis_text, threat_level, recommendations))
    conn.commit()
    conn.close()


def get_ai_analysis(alert_id):
    """Get the most recent AI analysis for an alert."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM ai_analyses WHERE alert_id = ?
        ORDER BY analyzed_at DESC LIMIT 1
    ''', (alert_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_analyses(limit=50):
    """Get all AI analyses with their associated alert info."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT a.*, al.signature, al.src_ip, al.dest_ip, al.severity
        FROM ai_analyses a
        JOIN alerts al ON a.alert_id = al.id
        ORDER BY a.analyzed_at DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def save_report(alert_id, report_content, report_type='incident'):
    """Save a generated report."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO reports (alert_id, report_type, report_content)
        VALUES (?, ?, ?)
    ''', (alert_id, report_type, report_content))
    report_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return report_id


def get_reports(limit=50):
    """Get all generated reports."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.*, a.signature, a.src_ip, a.dest_ip
        FROM reports r
        LEFT JOIN alerts a ON r.alert_id = a.id
        ORDER BY r.generated_at DESC LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_report_by_id(report_id):
    """Get a single report by ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reports WHERE id = ?', (report_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_total_alert_count():
    """Get total number of alerts for pagination."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) as count FROM alerts')
    count = cursor.fetchone()['count']
    conn.close()
    return count
