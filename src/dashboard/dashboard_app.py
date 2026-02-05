"""
Flask-based dashboard for the Simple IDS.

This module provides a lightweight web dashboard that reads the IDS alert
log and displays recent alerts along with summary statistics. It is
designed to be read‑only.

The dashboard exposes two JSON endpoints:
/api/alerts - Returns the most recent alerts.
/api/summary - Returns aggregated counts.

The root route / serves a "Cyberpunk" style HTML page.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Optional, Dict, Any, List

from flask import Flask, jsonify, render_template, render_template_string

# Local imports
from ..utils.config import load_config


def _load_alerts(alert_file: str) -> List[Dict[str, Any]]:
    """Load all alerts from the JSONL file."""
    alerts: List[Dict[str, Any]] = []
    if not os.path.exists(alert_file):
        return alerts
    try:
        with open(alert_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return alerts
    return alerts


def _build_summary(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build summary statistics from a list of alerts."""
    severity_counts = Counter()
    detection_counts = Counter()
    rule_counts = Counter()
    src_counts = Counter()

    for alert in alerts:
        severity_counts[alert.get('severity', 'UNKNOWN')] += 1
        detection_counts[alert.get('detection_type', 'UNKNOWN')] += 1
        rule_counts[alert.get('rule_id', 'N/A')] += 1
        src = alert.get('src', {})
        src_ip = src.get('ip', 'unknown')
        src_counts[src_ip] += 1

    return {
        'severity': dict(severity_counts),
        'detection_type': dict(detection_counts),
        'rule': dict(rule_counts),
        'src': dict(src_counts)
    }


# --- CYBERPUNK THEME HTML (FINAL RESPONSIVE VERSION) ---
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIMPLE IDS // CYBERWATCH</title>
    
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
    
    <style>
        /* --- Cyberpunk Aesthetics --- */
        body {
            background-color: #050505;
            color: #00ff41;
            font-family: 'Share Tech Mono', monospace;
            /* Allow scrolling on body */
            overflow-y: auto; 
            min-height: 100vh;
        }

        /* Neon Glow Effects */
        .neon-box {
            background: rgba(0, 20, 0, 0.85);
            border: 1px solid #00ff41;
            box-shadow: 0 0 5px rgba(0, 255, 65, 0.2), inset 0 0 10px rgba(0, 255, 65, 0.05);
            backdrop-filter: blur(4px);
        }
        
        .neon-text {
            text-shadow: 0 0 5px #00ff41;
        }

        /* Grid Background Pattern */
        .grid-bg {
            background-image: 
                linear-gradient(rgba(0, 255, 65, 0.05) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 65, 0.05) 1px, transparent 1px);
            background-size: 30px 30px;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            z-index: -1;
            pointer-events: none;
        }

        /* Scrollbar Styling */
        ::-webkit-scrollbar { width: 10px; height: 10px; }
        ::-webkit-scrollbar-track { background: #000; }
        ::-webkit-scrollbar-thumb { background: #003300; border: 1px solid #00ff41; }
        ::-webkit-scrollbar-thumb:hover { background: #00ff41; }

        /* Animations */
        .blink { animation: blinker 1.5s linear infinite; }
        @keyframes blinker { 50% { opacity: 0; } }
        
        .scanline {
            width: 100%;
            height: 2px;
            background: rgba(0, 255, 65, 0.1);
            position: fixed;
            top: 0; left: 0;
            animation: scan 6s linear infinite;
            pointer-events: none;
            z-index: 9999;
        }
        @keyframes scan { 0% {top: 0%} 100% {top: 100%} }
        
        table tbody tr:hover {
            background-color: rgba(0, 255, 65, 0.15);
            cursor: crosshair;
        }
    </style>
</head>
<body class="flex flex-col p-4 w-full">
    
    <div class="grid-bg"></div>
    <div class="scanline"></div>

    <header class="flex flex-col md:flex-row justify-between items-center mb-6 p-4 neon-box gap-4">
        <div class="flex items-center gap-4">
            <h1 class="text-3xl md:text-4xl font-bold tracking-widest neon-text text-center md:text-left">
                SIMPLE<span class="text-white">IDS</span>
            </h1>
            <span class="text-xs border border-green-500 px-2 py-0.5 text-green-300 hidden sm:inline-block">SYSTEM ACTIVE</span>
        </div>
        <div class="text-center md:text-right">
            <div class="text-xs text-gray-400">CURRENT TIME (IL)</div>
            <div id="clock" class="text-xl text-white">00:00:00</div>
        </div>
    </header>

    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
        <div class="neon-box p-6 text-center">
            <h3 class="text-xs text-gray-400 mb-2 tracking-wider">TOTAL THREATS</h3>
            <div id="totalAlerts" class="text-5xl font-bold text-white neon-text">0</div>
        </div>
        
        <div class="neon-box p-6 text-center border-orange-400" style="border-color: #ff9900; box-shadow: 0 0 5px rgba(255, 153, 0, 0.2);">
            <h3 class="text-xs text-gray-400 mb-2 tracking-wider">HIGH SEVERITY</h3>
            <div id="highAlerts" class="text-5xl font-bold text-orange-400" style="text-shadow: 0 0 5px #ff9900;">0</div>
        </div>
        
        <div class="neon-box p-6 flex flex-col justify-center items-center sm:col-span-2 lg:col-span-1">
            <h3 class="text-xs text-gray-400 mb-2 tracking-wider">STATUS</h3>
            <div class="text-2xl text-green-400 flex items-center gap-2">
                <span class="w-4 h-4 bg-green-500 rounded-full blink"></span> ONLINE
            </div>
            <div class="text-xs text-gray-500 mt-1">SYSTEM OPTIMAL</div>
        </div>
    </div>

    <div class="grid grid-cols-1 xl:grid-cols-3 gap-6 w-full">
        
        <div class="col-span-1 flex flex-col gap-6">
            <div class="neon-box p-4 h-80 flex flex-col">
                <h3 class="border-b border-green-900 pb-2 mb-2 text-sm text-gray-300">> SEVERITY DISTRIBUTION</h3>
                <div class="flex-grow relative w-full h-full">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="neon-box p-4 h-80 flex flex-col">
                <h3 class="border-b border-green-900 pb-2 mb-2 text-sm text-gray-300">> TOP SOURCES</h3>
                <div class="flex-grow relative w-full h-full">
                    <canvas id="srcChart"></canvas>
                </div>
            </div>
        </div>

        <div class="col-span-1 xl:col-span-2 neon-box p-0 flex flex-col h-[665px]">
            <div class="p-4 border-b border-green-900 bg-black/40 flex justify-between items-center shrink-0">
                <h3 class="text-xl neon-text">> LIVE TRAFFIC INTERCEPTION</h3>
                <span class="text-xs animate-pulse text-green-600">RECEIVING DATA...</span>
            </div>
            
            <div class="overflow-auto flex-grow w-full">
                <table class="w-full text-left text-sm border-collapse">
                    <thead class="sticky top-0 bg-black z-10 text-gray-500 text-xs shadow-lg shadow-green-900/20">
                        <tr>
                            <th class="p-3 border-b border-green-900 whitespace-nowrap bg-black">TIME</th>
                            <th class="p-3 border-b border-green-900 whitespace-nowrap bg-black">SEV</th>
                            <th class="p-3 border-b border-green-900 whitespace-nowrap bg-black">TYPE</th>
                            <th class="p-3 border-b border-green-900 whitespace-nowrap bg-black">RULE ID</th>
                            <th class="p-3 border-b border-green-900 whitespace-nowrap bg-black">SOURCE</th>
                            <th class="p-3 border-b border-green-900 whitespace-nowrap bg-black">TARGET</th>
                            <th class="p-3 border-b border-green-900 bg-black min-w-[200px]">MSG</th>
                        </tr>
                    </thead>
                    <tbody id="alertsBody" class="font-mono text-xs text-gray-300">
                        </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="mt-8 text-center text-xs text-gray-600 pb-4">
        SIMPLE IDS v1.0 // AUTHORIZED ACCESS ONLY
    </div>

    <script>
        // --- UTILS ---
        function toIsraelTime(isoString) {
            const date = new Date(isoString);
            return date.toLocaleTimeString('en-GB', { 
                timeZone: 'Asia/Jerusalem',
                hour12: false 
            });
        }

        setInterval(() => {
            document.getElementById('clock').innerText = toIsraelTime(new Date());
        }, 1000);

        // --- CHARTS CONFIG ---
        Chart.defaults.color = '#666';
        Chart.defaults.borderColor = '#111';
        Chart.defaults.font.family = "'Share Tech Mono', monospace";
        Chart.defaults.responsive = true;
        Chart.defaults.maintainAspectRatio = false;

        let sevChart, srcChart;

        function initCharts() {
            // Severity Doughnut (No Critical)
            const ctxSev = document.getElementById('severityChart').getContext('2d');
            sevChart = new Chart(ctxSev, {
                type: 'doughnut',
                data: {
                    labels: ['High', 'Medium', 'Low'],
                    datasets: [{
                        data: [0, 0, 0],
                        backgroundColor: ['#ff9900', '#ffff00', '#004400'],
                        borderColor: '#050505',
                        borderWidth: 2
                    }]
                },
                options: {
                    plugins: { 
                        legend: { position: 'bottom', labels: { color: '#00ff41', padding: 20 } } 
                    },
                    layout: { padding: 10 }
                }
            });

            // Source Bar
            const ctxSrc = document.getElementById('srcChart').getContext('2d');
            srcChart = new Chart(ctxSrc, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Alerts',
                        data: [],
                        backgroundColor: '#00ff41',
                        barThickness: 'flex',
                        maxBarThickness: 30
                    }]
                },
                options: {
                    indexAxis: 'y',
                    scales: {
                        x: { ticks: { color: '#00ff41' }, grid: { color: '#002200' } },
                        y: { ticks: { color: '#00ff41' }, grid: { display: false } }
                    },
                    plugins: { legend: { display: false } }
                }
            });
        }

        // --- DATA FETCHING ---
        async function updateDashboard() {
            try {
                const sumRes = await fetch('/api/summary');
                const summary = await sumRes.json();
                
                // Update Cards
                const sev = summary.severity;
                const total = Object.values(sev).reduce((a,b)=>a+b, 0);
                document.getElementById('totalAlerts').innerText = total;
                document.getElementById('highAlerts').innerText = sev.HIGH || 0;

                // Update Severity Chart
                sevChart.data.datasets[0].data = [
                    sev.HIGH || 0, 
                    sev.MEDIUM || 0, 
                    sev.LOW || 0
                ];
                sevChart.update();

                // Update Source Chart (Top 5)
                const sortedSrc = Object.entries(summary.src)
                    .sort(([,a],[,b]) => b-a)
                    .slice(0, 5);
                
                srcChart.data.labels = sortedSrc.map(([k]) => k);
                srcChart.data.datasets[0].data = sortedSrc.map(([,v]) => v);
                srcChart.update();

                // Fetch Alerts
                const alertRes = await fetch('/api/alerts');
                const alerts = await alertRes.json();
                
                const tbody = document.getElementById('alertsBody');
                tbody.innerHTML = '';
                
                if (alerts.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="p-6 text-center text-gray-500 italic">SYSTEM SCANNING... NO ACTIVE THREATS.</td></tr>';
                } else {
                    const recent = alerts.slice().reverse(); 
                    
                    recent.forEach(alert => {
                        let colorClass = 'text-green-400';
                        if (alert.severity === 'MEDIUM') colorClass = 'text-yellow-200';
                        if (alert.severity === 'HIGH') colorClass = 'text-orange-400 font-bold';
                        
                        const localTime = toIsraelTime(alert.timestamp_utc);

                        const tr = document.createElement('tr');
                        tr.className = 'border-b border-green-900/30 transition-colors hover:bg-green-900/10';
                        tr.innerHTML = `
                            <td class="p-3 text-gray-500 whitespace-nowrap">${localTime}</td>
                            <td class="p-3 ${colorClass}">${alert.severity}</td>
                            <td class="p-3 text-white">${alert.detection_type}</td>
                            <td class="p-3 text-gray-400">${alert.rule_id}</td>
                            <td class="p-3 text-gray-400">${alert.src.ip}</td>
                            <td class="p-3 text-gray-400">${alert.dst.ip}</td>
                            <td class="p-3 text-gray-500 truncate max-w-xs" title="${alert.description}">${alert.description}</td>
                        `;
                        tbody.appendChild(tr);
                    });
                }

            } catch (e) {
                console.error("Link Failure:", e);
            }
        }

        initCharts();
        updateDashboard();
        setInterval(updateDashboard, 2000);
    </script>
</body>
</html>
"""

def create_app(config_path: Optional[str] = None) -> Flask:
    """Create and configure the Flask dashboard application."""
    
    # Load config to find alerts path
    if config_path:
        cfg = load_config(config_path)
    else:
        # Fallback to default relative path
        default_path = os.path.join(os.getcwd(), 'config', 'config.yaml')
        if os.path.exists(default_path):
            cfg = load_config(default_path)
        else:
            # Fallback for when running from source root without config
            class MockConfig:
                alerts_jsonl_path = 'data/alerts.jsonl'
            cfg = MockConfig()
            
    alert_file = cfg.alerts_jsonl_path

    app = Flask(__name__)

    @app.route('/')
    def index():
        """Serve the Cyberpunk dashboard."""
        return render_template_string(INDEX_HTML)

    @app.route('/api/alerts')
    def api_alerts() -> Any:
        """Return all alerts as JSON."""
        alerts = _load_alerts(alert_file)
        return jsonify(alerts)

    @app.route('/api/summary')
    def api_summary() -> Any:
        """Return summary statistics."""
        alerts = _load_alerts(alert_file)
        summary = _build_summary(alerts)
        return jsonify(summary)

    return app


def run_dashboard(config_path: Optional[str] = None, host: str = '0.0.0.0', port: int = 5000, debug: bool = False) -> None:
    """Run the dashboard server."""
    app = create_app(config_path)
    print(f"🚀 CYBERWATCH DASHBOARD ACTIVE ON http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    # Allow running directly: python -m src.dashboard.dashboard_app
    run_dashboard(debug=True)