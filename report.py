"""Generate professional HTML reports with charts and recommendations."""

from typing import List
from corscan.models import CORSResult
from datetime import datetime
import base64
import os


def generate_html_report(results: List[CORSResult], filename: str):
    """
    Generate a professional HTML report with charts and analysis.
    
    Args:
        results: List of CORSResult objects to include in report
        filename: Output HTML filename
    """
    
    if not results:
        return
    
    # Calculate statistics
    total = len(results)
    vulnerable = sum(1 for r in results if r.vulnerable)
    critical = sum(1 for r in results if r.severity == 'critical')
    high = sum(1 for r in results if r.severity == 'high')
    medium = sum(1 for r in results if r.severity == 'medium')
    low = sum(1 for r in results if r.severity == 'low')
    safe = total - vulnerable
    
    # Calculate bypass success rate
    bypass_successful = 0
    bypasses_tested = 0
    for result in results:
        if result.bypass_attempts:
            for origin, attempt in result.bypass_attempts.items():
                bypasses_tested += 1
                if attempt.get('vulnerable'):
                    bypass_successful += 1
    
    bypass_rate = (bypass_successful / bypasses_tested * 100) if bypasses_tested > 0 else 0
    
    # Encode logo to base64
    logo_base64 = ""
    logo_path = os.path.join(os.path.dirname(__file__), '..', 'logo', 'logo.webp')
    if os.path.exists(logo_path):
        try:
            with open(logo_path, 'rb') as logo_file:
                logo_base64 = base64.b64encode(logo_file.read()).decode('utf-8')
                logo_html = f'<img src="data:image/webp;base64,{logo_base64}" alt="Corscan Logo" />'
        except Exception:
            logo_html = ""
    else:
        logo_html = ""
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Corscan Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: Arial, sans-serif; background: #f4f6f8; color: #1f2933; padding: 24px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #ffffff; border: 1px solid #d9e2ec; border-radius: 8px; padding: 32px; }}
        h1 {{ color: #102a43; margin-bottom: 8px; font-size: 30px; }}
        .subtitle {{ color: #52606d; margin-bottom: 24px; font-size: 14px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 24px 0 32px; }}
        .stat-box {{ padding: 20px; border: 1px solid #d9e2ec; border-radius: 8px; text-align: center; background: #f8fafc; }}
        .stat-box h3 {{ font-size: 32px; margin-top: 8px; font-weight: 700; }}
        .stat-box p {{ color: #52606d; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
        .stat-critical {{ border-top: 4px solid #d64545; }}
        .stat-high {{ border-top: 4px solid #e67e22; }}
        .stat-medium {{ border-top: 4px solid #d9a404; }}
        .stat-safe {{ border-top: 4px solid #2f855a; }}
        .logo-section {{ text-align: center; margin-bottom: 20px; }}
        .logo-ring {{
            width: 132px;
            height: 132px;
            margin: 0 auto;
            border-radius: 50%;
            overflow: hidden;
            border: 4px solid #d9e2ec;
            box-shadow: 0 10px 24px rgba(16, 42, 67, 0.18);
            background: radial-gradient(circle at 30% 30%, #f8fafc, #d9e2ec);
        }}
        .logo-ring img {{ width: 100%; height: 100%; object-fit: cover; display: block; }}
        .header-subtitle {{ color: #52606d; margin-bottom: 24px; font-size: 14px; text-align: center; }}
        .charts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; margin: 24px 0 32px; }}
        .chart-container {{ position: relative; height: 320px; padding: 20px; background: #ffffff; border: 1px solid #d9e2ec; border-radius: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; border: 1px solid #d9e2ec; }}
        th {{ background: #243b53; color: #ffffff; padding: 14px; text-align: left; font-weight: 600; font-size: 14px; }}
        td {{ padding: 12px 14px; border-bottom: 1px solid #e5e7eb; font-size: 14px; vertical-align: top; }}
        tr:nth-child(even) {{ background: #f8fafc; }}
        .severity-critical {{ color: #b42318; font-weight: bold; }}
        .severity-high {{ color: #c05621; font-weight: bold; }}
        .severity-medium {{ color: #b7791f; font-weight: bold; }}
        .severity-low {{ color: #1d4ed8; font-weight: bold; }}
        .severity-none {{ color: #2f855a; font-weight: bold; }}
        .badge-yes {{ display: inline-block; background: #fde8e8; color: #b42318; padding: 4px 10px; border-radius: 999px; font-weight: bold; font-size: 12px; }}
        .badge-no {{ display: inline-block; background: #e6fffa; color: #17603a; padding: 4px 10px; border-radius: 999px; font-size: 12px; }}
        code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; }}
        .recommendations {{ margin-top: 32px; padding: 20px; background: #f8fafc; border: 1px solid #d9e2ec; border-radius: 8px; }}
        .recommendations h3 {{ color: #102a43; margin-bottom: 12px; }}
        .recommendations ul {{ margin-left: 20px; }}
        .recommendations li {{ margin: 8px 0; color: #334e68; }}
        .footer {{ margin-top: 32px; padding-top: 20px; text-align: center; color: #7b8794; border-top: 1px solid #d9e2ec; font-size: 12px; }}
        .footer-links {{ display: flex; justify-content: center; gap: 10px; flex-wrap: wrap; margin-top: 12px; }}
        .footer-link {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 999px;
            text-decoration: none;
            border: 1px solid #d9e2ec;
            color: #334e68;
            background: #f8fafc;
            transition: all 0.2s ease;
        }}
        .footer-link:hover {{ background: #eaf2fb; border-color: #bcccdc; }}
        .footer-link svg {{ width: 16px; height: 16px; fill: currentColor; }}
        h2 {{ color: #102a43; font-size: 22px; margin-top: 36px; margin-bottom: 16px; font-weight: 600; }}
        h3 {{ color: #334e68; font-size: 16px; margin-bottom: 12px; }}
        @media (max-width: 768px) {{
            body {{ padding: 12px; }}
            .container {{ padding: 20px; }}
            .charts-grid {{ grid-template-columns: 1fr; }}
            th, td {{ font-size: 13px; padding: 10px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo-section">
            <div class="logo-ring">
                {logo_html}
            </div>
        </div>
        <h1 style="text-align: center;">Corscan Vulnerability Report</h1>
        <p class="header-subtitle">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats">
            <div class="stat-box stat-critical">
                <p>Critical</p>
                <h3>{critical}</h3>
            </div>
            <div class="stat-box stat-high">
                <p>High</p>
                <h3>{high}</h3>
            </div>
            <div class="stat-box stat-medium">
                <p>Medium</p>
                <h3>{medium}</h3>
            </div>
            <div class="stat-box stat-safe">
                <p>Safe</p>
                <h3>{safe}</h3>
            </div>
        </div>
        
        <div class="charts-grid">
            <div class="chart-container">
                <h3>Severity Distribution</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Vulnerability Status</h3>
                <canvas id="statusChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Bypass Success Rate</h3>
                <canvas id="bypassChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>Response Time Analysis</h3>
                <canvas id="responseTimeChart"></canvas>
            </div>
        </div>
        
        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Allow Origin</th>
                    <th>Allow Credentials</th>
                    <th>Response Time</th>
                </tr>
            </thead>
            <tbody>
                {_generate_table_rows(results)}
            </tbody>
        </table>
        
        <div class="recommendations">
            <h3>Recommendations</h3>
            <ul>
                {"<li>No CORS vulnerabilities detected.</li>" if vulnerable == 0 else ""}
                {"<li><strong>Critical:</strong> {} URL(s) with CORS + Credentials require immediate fixes.</li>".format(critical) if critical > 0 else ""}
                {"<li><strong>High:</strong> {} URL(s) with wildcard CORS should be reviewed and restricted.</li>".format(high) if high > 0 else ""}
                {"<li><strong>Medium:</strong> {} URL(s) reflect origins and should use an allowlist.</li>".format(medium) if medium > 0 else ""}
                <li>Allow only trusted origins that are required by the application.</li>
                <li>Avoid using Access-Control-Allow-Credentials: true with wildcard origins.</li>
                <li>Review CORS settings regularly in staging and production.</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Report generated by Corscan v1.0.2</p>
            <div class="footer-links">
                <a class="footer-link" href="https://github.com/angixblack/corscan" target="_blank" rel="noopener noreferrer">
                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 0C5.37 0 0 5.49 0 12.26c0 5.42 3.44 10.02 8.2 11.64.6.11.82-.27.82-.6 0-.3-.01-1.28-.02-2.32-3.34.74-4.04-1.46-4.04-1.46-.55-1.43-1.34-1.81-1.34-1.81-1.1-.77.08-.75.08-.75 1.22.09 1.86 1.29 1.86 1.29 1.08 1.9 2.84 1.35 3.53 1.03.11-.8.42-1.35.76-1.66-2.67-.31-5.48-1.37-5.48-6.11 0-1.35.47-2.45 1.24-3.32-.12-.31-.54-1.57.12-3.28 0 0 1.01-.33 3.3 1.27a11.2 11.2 0 0 1 6 0c2.28-1.6 3.29-1.27 3.29-1.27.66 1.71.24 2.97.12 3.28.77.87 1.24 1.97 1.24 3.32 0 4.75-2.81 5.79-5.49 6.1.43.39.82 1.14.82 2.31 0 1.67-.02 3.01-.02 3.42 0 .33.21.72.82.6A12.18 12.18 0 0 0 24 12.26C24 5.49 18.63 0 12 0z"/></svg>
                    <span>GitHub</span>
                </a>
                <a class="footer-link" href="https://buymeacoffee.com/AngixBlack" target="_blank" rel="noopener noreferrer">
                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8h1a4 4 0 0 1 0 8h-1v1a5 5 0 0 1-5 5H7a5 5 0 0 1-5-5V7a3 3 0 0 1 3-3h8a5 5 0 0 1 5 4zm1 6a2 2 0 0 0 0-4h-1v4h1z"/></svg>
                    <span>Buy Me a Coffee</span>
                </a>
            </div>
            <p style="margin-top: 8px; font-style: italic;">Coded By Angix Black</p>
        </div>
    </div>
    
    <script>
        // Severity Distribution Chart
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'None'],
                datasets: [{{
                    data: [{critical}, {high}, {medium}, {low}, {safe}],
                    backgroundColor: ['#e74c3c', '#e67e22', '#f39c12', '#3498db', '#27ae60'],
                    borderColor: 'white',
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Vulnerability Status Chart
        const statusCtx = document.getElementById('statusChart').getContext('2d');
        new Chart(statusCtx, {{
            type: 'pie',
            data: {{
                labels: ['Vulnerable', 'Safe'],
                datasets: [{{
                    data: [{vulnerable}, {safe}],
                    backgroundColor: ['#e74c3c', '#27ae60'],
                    borderColor: 'white',
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Bypass Success Rate
        const bypassCtx = document.getElementById('bypassChart').getContext('2d');
        new Chart(bypassCtx, {{
            type: 'doughnut',
            data: {{
                labels: ['Successful Bypasses', 'Failed Bypasses'],
                datasets: [{{
                    data: [{bypass_successful}, {bypasses_tested - bypass_successful}],
                    backgroundColor: ['#e74c3c', '#95a5a6'],
                    borderColor: 'white',
                    borderWidth: 2
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Response Time Chart
        const responseTimeCtx = document.getElementById('responseTimeChart').getContext('2d');
        new Chart(responseTimeCtx, {{
            type: 'bar',
            data: {{
                labels: {_generate_response_time_labels(results)},
                datasets: [{{
                    label: 'Response Time (ms)',
                    data: {_generate_response_time_data(results)},
                    backgroundColor: '#3498db',
                    borderColor: '#2980b9',
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y',
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    x: {{ beginAtZero: true }}
                }}
            }}
        }});
    </script>
</body>
</html>"""
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
    except IOError as e:
        raise IOError(f"Failed to write HTML report: {e}")


def _generate_table_rows(results: List[CORSResult]) -> str:
    """Generate HTML table rows from results."""
    rows = []
    for result in results:
        status = '<span class="badge-yes">Vulnerable</span>' if result.vulnerable else '<span class="badge-no">Safe</span>'
        severity_class = f"severity-{result.severity}"
        allow_creds = result.cors_headers.get('Access-Control-Allow-Credentials', 'false')
        
        rows.append(f"""                <tr>
                    <td><code>{result.url[:60]}{'...' if len(result.url) > 60 else ''}</code></td>
                    <td>{status}</td>
                    <td><span class="{severity_class}">{result.severity.upper()}</span></td>
                    <td>{result.cors_headers.get('Access-Control-Allow-Origin', 'N/A')}</td>
                    <td>{allow_creds}</td>
                    <td>{result.request_time:.3f}s</td>
                </tr>""")
    
    return '\n'.join(rows)


def _generate_response_time_labels(results: List[CORSResult]) -> str:
    """Generate chart labels for response times."""
    labels = [f"URL {i+1}" for i in range(min(10, len(results)))]
    return str(labels)


def _generate_response_time_data(results: List[CORSResult]) -> str:
    """Generate chart data for response times."""
    data = [r.request_time * 1000 for r in results[:10]]
    return str(data)
