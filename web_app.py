import os
import sys
import json
import logging
from flask import Flask, render_template, jsonify, request

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import AuditEngine
from core.reporter import AuditReporter

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

REPORT_JSON = "report.json"
REPORT_HTML = "report.html"

@app.route('/')
def index():
    """Renders the main dashboard page."""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def run_scan():
    """Triggers the scan engine and returns the fresh results as JSON."""
    try:
        engine = AuditEngine()
        engine.load_checks()
        
        if not engine.checks:
            return jsonify({"error": "No checks loaded for this operating system."}), 400
        
        results = engine.run_all()
        
        # Save report files using reporter
        reporter = AuditReporter(results)
        reporter.generate_html(REPORT_HTML)
        reporter.generate_json(REPORT_JSON)
        
        # Convert results to dictionaries for the response
        serialized_results = [r.to_dict() for r in results]
        
        return jsonify({
            "status": "success",
            "summary": reporter.summary,
            "results": serialized_results
        })
    except Exception as e:
        app.logger.error(f"Error during scan: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/results', methods=['GET'])
def get_results():
    """Retrieves results of the last audit scan from disk."""
    if os.path.exists(REPORT_JSON):
        try:
            with open(REPORT_JSON, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return jsonify(data)
        except Exception as e:
            return jsonify({"error": f"Failed to read report: {str(e)}"}), 500
    else:
        return jsonify({"error": "No previous scan report found. Please run a scan first."}), 404

if __name__ == '__main__':
    print("[*] Launching PrivEscAuditor Web Server...")
    print("[*] Accessible locally at http://127.0.0.1:5000")
    # Bind to 127.0.0.1 strictly for security to prevent exposing auditing panel to the local network
    app.run(host='127.0.0.1', port=5000, debug=True)
