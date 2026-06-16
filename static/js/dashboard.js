/* ═══════════════════════════════════════════════
   AI-NIDS — Dashboard JavaScript
   Handles API calls, Chart.js rendering, and UI interactivity
   ═══════════════════════════════════════════════ */

// ── State ──
let currentPage = 0;
const PAGE_SIZE = 20;
let currentSeverityFilter = '';
let selectedAlertId = null;
let currentReportId = null;

// Chart instances (for cleanup on re-render)
let miniSeverityChart = null;
let severityChart = null;
let categoryChart = null;
let timelineChart = null;
let topIpsChart = null;

// ── Chart.js Global Config ──
Chart.defaults.color = '#8892a6';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.plugins.legend.labels.boxWidth = 12;
Chart.defaults.plugins.legend.labels.padding = 16;


/* ═══════════════════════════════════════════════
   DASHBOARD
   ═══════════════════════════════════════════════ */

async function loadDashboardData() {
    try {
        const [statsRes, alertsRes, ipsRes] = await Promise.all([
            fetch('/api/stats'),
            fetch(`/api/alerts?limit=${PAGE_SIZE}&offset=${currentPage * PAGE_SIZE}${currentSeverityFilter ? '&severity=' + currentSeverityFilter : ''}`),
            fetch('/api/top-ips?limit=8')
        ]);

        const stats = await statsRes.json();
        const alertsData = await alertsRes.json();
        const ips = await ipsRes.json();

        updateStatCards(stats);
        updateAlertsTable(alertsData.alerts, alertsData.total);
        updateTopIpsList(ips);
        renderMiniSeverityChart(stats.by_severity);
        updateSystemStatus();
    } catch (err) {
        console.error('Failed to load dashboard data:', err);
    }
}

function updateStatCards(stats) {
    animateCounter('stat-total', stats.total || 0);
    animateCounter('stat-today', stats.today || 0);
    animateCounter('stat-critical', stats.by_severity?.critical || 0);
    animateCounter('stat-high', stats.by_severity?.high || 0);
    animateCounter('stat-medium', stats.by_severity?.medium || 0);
    animateCounter('stat-low', stats.by_severity?.low || 0);
}

function animateCounter(elementId, target) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const start = parseInt(el.textContent) || 0;
    if (start === target) return;

    const duration = 600;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(start + (target - start) * eased);
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

function updateAlertsTable(alerts, total) {
    const tbody = document.getElementById('alerts-tbody');
    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="7">
                    <div class="empty-state">
                        <i class="bi bi-shield-check"></i>
                        <p>No alerts detected yet. Suricata is monitoring network traffic.</p>
                    </div>
                </td>
            </tr>`;
        return;
    }

    const severityLabels = { 1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low' };

    tbody.innerHTML = alerts.map(alert => `
        <tr>
            <td><span class="severity-badge severity-${alert.severity}">${severityLabels[alert.severity] || 'Unknown'}</span></td>
            <td>${formatTimestamp(alert.timestamp)}</td>
            <td title="${escapeHtml(alert.signature)}">${truncate(alert.signature, 45)}</td>
            <td class="ip-cell">${alert.src_ip}</td>
            <td class="ip-cell">${alert.dest_ip}:${alert.dest_port || ''}</td>
            <td>${alert.protocol || '-'}</td>
            <td><button class="btn-analyze" onclick="window.location.href='/analysis?alert_id=${alert.id}'"><i class="bi bi-robot"></i> Analyze</button></td>
        </tr>
    `).join('');

    // Pagination
    const totalPages = Math.ceil(total / PAGE_SIZE);
    const pageInfo = document.getElementById('page-info');
    const btnPrev = document.getElementById('btn-prev');
    const btnNext = document.getElementById('btn-next');

    if (pageInfo) pageInfo.textContent = `Page ${currentPage + 1} of ${Math.max(totalPages, 1)}`;
    if (btnPrev) btnPrev.disabled = currentPage === 0;
    if (btnNext) btnNext.disabled = currentPage >= totalPages - 1;
}

function changePage(delta) {
    currentPage = Math.max(0, currentPage + delta);
    loadDashboardData();
}

function filterAlerts() {
    const select = document.getElementById('severity-filter');
    currentSeverityFilter = select ? select.value : '';
    currentPage = 0;
    loadDashboardData();
}

function updateTopIpsList(ips) {
    const list = document.getElementById('top-ips-list');
    if (!list) return;

    if (!ips || ips.length === 0) {
        list.innerHTML = '<li class="empty-state-small">No data yet</li>';
        return;
    }

    list.innerHTML = ips.map(ip => `
        <li>
            <span class="ip-address">${ip.src_ip}</span>
            <span class="ip-count">${ip.count}</span>
        </li>
    `).join('');
}

function renderMiniSeverityChart(severity) {
    const canvas = document.getElementById('miniSeverityChart');
    if (!canvas) return;

    if (miniSeverityChart) miniSeverityChart.destroy();

    const data = severity || { critical: 0, high: 0, medium: 0, low: 0 };

    miniSeverityChart = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [data.critical, data.high, data.medium, data.low],
                backgroundColor: ['#ff1a4b', '#ff6b35', '#ffaa00', '#22d3ee'],
                borderWidth: 0,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { padding: 12, usePointStyle: true, pointStyleWidth: 8 }
                }
            }
        }
    });
}


/* ═══════════════════════════════════════════════
   ANALYTICS
   ═══════════════════════════════════════════════ */

async function loadAnalyticsData() {
    try {
        const [statsRes, ipsRes, timelineRes] = await Promise.all([
            fetch('/api/stats'),
            fetch('/api/top-ips?limit=10'),
            fetch('/api/timeline?days=7')
        ]);

        const stats = await statsRes.json();
        const ips = await ipsRes.json();
        const timeline = await timelineRes.json();

        renderSeverityChart(stats.by_severity);
        renderCategoryChart(stats.by_category);
        renderTimelineChart(timeline);
        renderTopIpsChart(ips);
        updateAnalyticsStats(stats, ips);
    } catch (err) {
        console.error('Failed to load analytics:', err);
    }
}

function renderSeverityChart(severity) {
    const canvas = document.getElementById('severityChart');
    if (!canvas) return;
    if (severityChart) severityChart.destroy();

    const data = severity || {};

    severityChart = new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [data.critical || 0, data.high || 0, data.medium || 0, data.low || 0],
                backgroundColor: ['#ff1a4b', '#ff6b35', '#ffaa00', '#22d3ee'],
                borderWidth: 0,
                hoverOffset: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: { padding: 16, usePointStyle: true, pointStyleWidth: 10, font: { size: 13 } }
                }
            }
        }
    });
}

function renderCategoryChart(categories) {
    const canvas = document.getElementById('categoryChart');
    if (!canvas) return;
    if (categoryChart) categoryChart.destroy();

    if (!categories || categories.length === 0) {
        categories = [{ category: 'No data', count: 0 }];
    }

    categoryChart = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: categories.map(c => truncate(c.category, 25)),
            datasets: [{
                label: 'Alerts',
                data: categories.map(c => c.count),
                backgroundColor: 'rgba(0, 212, 255, 0.3)',
                borderColor: '#00d4ff',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { stepSize: 1 }
                },
                y: {
                    grid: { display: false },
                    ticks: { font: { size: 11 } }
                }
            }
        }
    });
}

function renderTimelineChart(timeline) {
    const canvas = document.getElementById('timelineChart');
    if (!canvas) return;
    if (timelineChart) timelineChart.destroy();

    if (!timeline || timeline.length === 0) {
        timeline = [{ hour: 'No data', count: 0 }];
    }

    timelineChart = new Chart(canvas, {
        type: 'line',
        data: {
            labels: timeline.map(t => {
                if (t.hour === 'No data') return t.hour;
                const d = new Date(t.hour);
                return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit' });
            }),
            datasets: [{
                label: 'Alerts',
                data: timeline.map(t => t.count),
                borderColor: '#00d4ff',
                backgroundColor: 'rgba(0, 212, 255, 0.08)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 3,
                pointBackgroundColor: '#00d4ff',
                pointBorderWidth: 0,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    ticks: { maxRotation: 45, font: { size: 10 }, maxTicksLimit: 15 }
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    beginAtZero: true,
                    ticks: { stepSize: 1 }
                }
            }
        }
    });
}

function renderTopIpsChart(ips) {
    const canvas = document.getElementById('topIpsChart');
    if (!canvas) return;
    if (topIpsChart) topIpsChart.destroy();

    if (!ips || ips.length === 0) {
        ips = [{ src_ip: 'No data', count: 0 }];
    }

    const colors = ['#ff1a4b', '#ff6b35', '#ffaa00', '#22d3ee', '#a855f7',
                     '#00ff88', '#00d4ff', '#f472b6', '#818cf8', '#fbbf24'];

    topIpsChart = new Chart(canvas, {
        type: 'bar',
        data: {
            labels: ips.map(ip => ip.src_ip),
            datasets: [{
                label: 'Alerts',
                data: ips.map(ip => ip.count),
                backgroundColor: ips.map((_, i) => colors[i % colors.length] + '44'),
                borderColor: ips.map((_, i) => colors[i % colors.length]),
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { font: { family: "'JetBrains Mono', monospace", size: 10 }, maxRotation: 45 }
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.04)' },
                    beginAtZero: true,
                    ticks: { stepSize: 1 }
                }
            }
        }
    });
}

async function updateTimeline() {
    const select = document.getElementById('timeline-range');
    const days = select ? parseInt(select.value) : 7;
    try {
        const res = await fetch(`/api/timeline?days=${days}`);
        const timeline = await res.json();
        renderTimelineChart(timeline);
    } catch (err) {
        console.error('Failed to update timeline:', err);
    }
}

function updateAnalyticsStats(stats, ips) {
    const el = id => document.getElementById(id);
    if (el('analytics-total')) el('analytics-total').textContent = stats.total || 0;
    if (el('analytics-today')) el('analytics-today').textContent = stats.today || 0;
    if (el('analytics-categories')) el('analytics-categories').textContent = stats.by_category ? stats.by_category.length : 0;
    if (el('analytics-ips')) el('analytics-ips').textContent = ips ? ips.length : 0;
}


/* ═══════════════════════════════════════════════
   AI ANALYSIS
   ═══════════════════════════════════════════════ */

async function loadAlertsForAnalysis() {
    const filterEl = document.getElementById('analysis-severity-filter');
    const severity = filterEl ? filterEl.value : '';

    try {
        const res = await fetch(`/api/alerts?limit=100${severity ? '&severity=' + severity : ''}`);
        const data = await res.json();
        renderAlertListForAnalysis(data.alerts);
    } catch (err) {
        console.error('Failed to load alerts for analysis:', err);
    }
}

function renderAlertListForAnalysis(alerts) {
    const container = document.getElementById('alert-list-for-analysis');
    if (!container) return;

    if (!alerts || alerts.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="bi bi-inbox"></i>
                <p>No alerts available. Waiting for Suricata to detect threats.</p>
            </div>`;
        return;
    }

    const severityLabels = { 1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low' };

    // Check URL for pre-selected alert
    const urlParams = new URLSearchParams(window.location.search);
    const preSelectedId = urlParams.get('alert_id');

    container.innerHTML = alerts.map(alert => `
        <div class="alert-list-item ${alert.id == preSelectedId ? 'selected' : ''}"
             id="alert-item-${alert.id}"
             onclick="selectAlert(${alert.id})">
            <div class="alert-item-header">
                <span class="severity-badge severity-${alert.severity}">${severityLabels[alert.severity]}</span>
                <span class="alert-item-sig">${escapeHtml(alert.signature)}</span>
            </div>
            <div class="alert-item-meta">${alert.src_ip} → ${alert.dest_ip} | ${formatTimestamp(alert.timestamp)}</div>
            <div class="alert-item-actions">
                <button class="btn-analyze" onclick="event.stopPropagation(); analyzeAlert(${alert.id})">
                    <i class="bi bi-robot"></i> Analyze with AI
                </button>
            </div>
        </div>
    `).join('');

    if (preSelectedId) {
        selectedAlertId = parseInt(preSelectedId);
    }
}

function selectAlert(alertId) {
    // Deselect previous
    document.querySelectorAll('.alert-list-item.selected').forEach(el => el.classList.remove('selected'));
    // Select new
    const item = document.getElementById(`alert-item-${alertId}`);
    if (item) item.classList.add('selected');
    selectedAlertId = alertId;

    // Check if analysis already exists
    checkExistingAnalysis(alertId);
}

async function checkExistingAnalysis(alertId) {
    try {
        const res = await fetch(`/api/analysis/${alertId}`);
        if (res.ok) {
            const analysis = await res.json();
            displayAnalysisResult(analysis, alertId);
        }
    } catch (err) {
        // No existing analysis — that's fine
    }
}

async function analyzeAlert(alertId) {
    selectedAlertId = alertId;

    // Show loading
    showAnalysisState('loading');

    try {
        const res = await fetch(`/api/analyze/${alertId}`, { method: 'POST' });
        const data = await res.json();

        if (data.success) {
            displayAnalysisResult(data.analysis, alertId);
            loadAnalysisHistory();
        } else {
            showAnalysisError(data.error || 'Analysis failed');
        }
    } catch (err) {
        showAnalysisError('Failed to connect to the server. Please try again.');
    }
}

function displayAnalysisResult(analysis, alertId) {
    showAnalysisState('result');

    // Alert info
    const infoEl = document.getElementById('analyzed-alert-info');
    if (infoEl) infoEl.textContent = `Alert #${alertId}`;

    // Risk badge
    const badge = document.getElementById('risk-badge-large');
    if (badge) {
        const level = (analysis.threat_level || 'unknown').toLowerCase();
        badge.textContent = analysis.threat_level || 'Unknown';
        badge.className = 'risk-badge-large';
        if (['critical', 'high', 'medium', 'low'].includes(level)) {
            badge.classList.add(`risk-${level}`);
        }
    }

    // Sections
    setContent('threat-explanation', analysis.threat_explanation);
    setContent('attack-category', analysis.attack_category);
    setContent('potential-impact', analysis.potential_impact);
    setContent('recommendations', analysis.recommendations);
    setContent('incident-summary', analysis.incident_summary);

    // If we have raw text but no parsed sections, show the full text
    if (!analysis.threat_explanation && analysis.analysis_text) {
        setContent('threat-explanation', analysis.analysis_text);
    }
}

function setContent(elementId, text) {
    const el = document.getElementById(elementId);
    if (el) el.textContent = text || 'N/A';
}

function showAnalysisState(state) {
    const states = ['placeholder', 'loading', 'result', 'error'];
    states.forEach(s => {
        const el = document.getElementById(`analysis-${s}`);
        if (el) el.classList.toggle('hidden', s !== state);
    });
}

function showAnalysisError(message) {
    showAnalysisState('error');
    const msgEl = document.getElementById('error-message');
    if (msgEl) msgEl.textContent = message;
}

function retryAnalysis() {
    if (selectedAlertId) analyzeAlert(selectedAlertId);
}

async function generateReportFromAnalysis() {
    if (!selectedAlertId) return;

    try {
        const res = await fetch(`/api/report/generate/${selectedAlertId}`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            alert('Report generated successfully! View it on the Reports page.');
        }
    } catch (err) {
        alert('Failed to generate report.');
    }
}

async function loadAnalysisHistory() {
    const container = document.getElementById('analysis-history-list');
    if (!container) return;

    try {
        const res = await fetch('/api/analyses');
        const analyses = await res.json();

        if (!analyses || analyses.length === 0) {
            container.innerHTML = '<div class="empty-state-small">No analyses performed yet</div>';
            return;
        }

        container.innerHTML = analyses.map(a => `
            <div class="history-item" onclick="selectAlert(${a.alert_id}); checkExistingAnalysis(${a.alert_id});">
                <span class="severity-badge severity-${a.severity}">${getSeverityLabel(a.severity)}</span>
                <span class="history-sig">${escapeHtml(a.signature || 'Alert #' + a.alert_id)}</span>
                <span class="history-time">${formatTimestamp(a.analyzed_at)}</span>
            </div>
        `).join('');
    } catch (err) {
        console.error('Failed to load analysis history:', err);
    }
}


/* ═══════════════════════════════════════════════
   REPORTS
   ═══════════════════════════════════════════════ */

async function loadReportsList() {
    const container = document.getElementById('reports-list');
    if (!container) return;

    try {
        const res = await fetch('/api/reports');
        const reports = await res.json();

        if (!reports || reports.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="bi bi-folder"></i>
                    <p>No reports generated yet. Use the AI Analysis page to analyze alerts, then generate incident reports.</p>
                </div>`;
            return;
        }

        container.innerHTML = reports.map(r => `
            <div class="report-list-item">
                <div class="report-icon ${r.report_type || 'incident'}">
                    <i class="bi bi-${r.report_type === 'summary' ? 'clipboard-data' : 'file-earmark-text'}"></i>
                </div>
                <div class="report-info">
                    <div class="report-title">${r.report_type === 'summary' ? 'Summary Report' : 'Incident Report — ' + escapeHtml(r.signature || 'Alert')}</div>
                    <div class="report-meta">Generated ${formatTimestamp(r.generated_at)}</div>
                </div>
                <div class="report-actions">
                    <button class="btn-action btn-sm" onclick="previewReport(${r.id})">
                        <i class="bi bi-eye"></i> View
                    </button>
                    <button class="btn-action btn-sm btn-secondary" onclick="downloadReport(${r.id})">
                        <i class="bi bi-download"></i>
                    </button>
                </div>
            </div>
        `).join('');
    } catch (err) {
        console.error('Failed to load reports:', err);
    }
}

async function generateSummaryReport() {
    try {
        const res = await fetch('/api/report/summary', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            loadReportsList();
        }
    } catch (err) {
        alert('Failed to generate summary report.');
    }
}

async function previewReport(reportId) {
    currentReportId = reportId;
    try {
        const res = await fetch(`/api/report/${reportId}`);
        const report = await res.json();

        const previewEl = document.getElementById('report-preview-content');
        if (previewEl) previewEl.textContent = report.report_content;

        const modal = new bootstrap.Modal(document.getElementById('reportModal'));
        modal.show();
    } catch (err) {
        alert('Failed to load report.');
    }
}

function downloadReport(reportId) {
    window.open(`/api/report/${reportId}/download`, '_blank');
}

function downloadCurrentReport() {
    if (currentReportId) downloadReport(currentReportId);
}


/* ═══════════════════════════════════════════════
   SYSTEM STATUS
   ═══════════════════════════════════════════════ */

async function updateSystemStatus() {
    try {
        const res = await fetch('/api/status');
        const status = await res.json();

        const suricataDot = document.querySelector('#status-suricata .status-dot');
        const ollamaDot = document.querySelector('#status-ollama .status-dot');

        if (suricataDot) {
            suricataDot.className = 'status-dot ' + (status.suricata?.file_exists ? 'online' : 'offline');
        }
        if (ollamaDot) {
            ollamaDot.className = 'status-dot ' + (status.ollama?.available ? 'online' : 'offline');
        }
    } catch (err) {
        // Status check failed silently
    }
}


/* ═══════════════════════════════════════════════
   REFRESH & UTILITIES
   ═══════════════════════════════════════════════ */

function refreshData() {
    // Determine current page and reload appropriate data
    const path = window.location.pathname;
    if (path === '/' || path === '/dashboard') {
        loadDashboardData();
    } else if (path === '/analytics') {
        loadAnalyticsData();
    } else if (path === '/analysis') {
        loadAlertsForAnalysis();
        loadAnalysisHistory();
    } else if (path === '/reports') {
        loadReportsList();
    }

    // Always update system status
    updateSystemStatus();
}

function formatTimestamp(ts) {
    if (!ts) return '-';
    try {
        const d = new Date(ts);
        if (isNaN(d.getTime())) return ts.substring(0, 19);
        return d.toLocaleString('en-US', {
            month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
            hour12: false
        });
    } catch (e) {
        return ts.substring(0, 19);
    }
}

function truncate(str, len) {
    if (!str) return '';
    return str.length > len ? str.substring(0, len) + '…' : str;
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function getSeverityLabel(severity) {
    return { 1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low' }[severity] || 'Unknown';
}

// Update status on page load
document.addEventListener('DOMContentLoaded', function() {
    updateSystemStatus();
    // Refresh status every 60 seconds
    setInterval(updateSystemStatus, 60000);
});
