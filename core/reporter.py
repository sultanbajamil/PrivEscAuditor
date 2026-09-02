import json
import os
import datetime
import platform

class AuditReporter:
    def __init__(self, results):
        self.results = results
        self.summary = self._calculate_summary()

    def _calculate_summary(self):
        summary = {
            "total": len(self.results),
            "triggered": 0,
            "passed": 0,
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        for r in self.results:
            if r.triggered:
                summary["triggered"] += 1
                summary[r.severity] += 1
            else:
                summary["passed"] += 1
        return summary

    def generate_json(self, output_path):
        """Generates a raw JSON report."""
        report_data = {
            "timestamp": datetime.datetime.now().isoformat(),
            "system_info": {
                "os": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "node": platform.node(),
                "machine": platform.machine()
            },
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results]
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4)
        return output_path

    def generate_html(self, output_path):
        """Generates a professional HTML report using Tailwind CSS."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        os_name = platform.system()
        node_name = platform.node()

        # Build rows for the results table
        rows_html = ""
        details_html = ""

        # Color codes for severities
        sev_colors = {
            "Critical": "bg-red-100 text-red-800 border-red-200",
            "High": "bg-orange-100 text-orange-800 border-orange-200",
            "Medium": "bg-yellow-100 text-yellow-800 border-yellow-200",
            "Low": "bg-blue-100 text-blue-800 border-blue-200",
            "Info": "bg-gray-100 text-gray-800 border-gray-200"
        }

        for i, r in enumerate(self.results):
            status_badge = '<span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800 border border-red-200">Triggered</span>' if r.triggered else '<span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800 border border-green-200">Passed</span>'
            sev_badge = f'<span class="px-2.5 py-1 text-xs font-semibold rounded-full border {sev_colors.get(r.severity, "bg-gray-100 text-gray-800")}">{r.severity}</span>'
            
            # Table Row
            rows_html += f"""
            <tr class="hover:bg-gray-50 border-b border-gray-100">
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{r.check_name}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{r.category}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm">{sev_badge}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm">{status_badge}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-right">
                    {f'<a href="#check-detail-{i}" class="text-indigo-600 hover:text-indigo-900 font-medium">View Details</a>' if r.triggered else '<span class="text-gray-400">-</span>'}
                </td>
            </tr>
            """

            # Detailed sections for triggered checks
            if r.triggered:
                details_list = ""
                for detail in r.details:
                    if isinstance(detail, dict):
                        details_list += f"<li class='mb-2'><pre class='bg-gray-800 text-gray-200 p-2 rounded text-xs overflow-auto'>{json.dumps(detail, indent=2)}</pre></li>"
                    else:
                        details_list += f"<li class='mb-1 text-gray-700 list-disc list-inside'>{detail}</li>"

                details_html += f"""
                <div id="check-detail-{i}" class="mb-6 p-6 bg-white rounded-lg border border-gray-200 shadow-sm scroll-mt-6">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-lg font-bold text-gray-900">{r.check_name}</h3>
                        <div class="flex space-x-2">
                            <span class="px-2.5 py-1 text-xs font-semibold rounded-full border {sev_colors.get(r.severity, "bg-gray-100 text-gray-800")}">{r.severity}</span>
                            <span class="px-2.5 py-1 text-xs font-semibold rounded-full bg-indigo-100 text-indigo-800">{r.category}</span>
                        </div>
                    </div>
                    <p class="text-gray-600 mb-4 text-sm">{r.description}</p>
                    
                    <div class="mb-4">
                        <h4 class="text-sm font-semibold text-gray-800 mb-2">Findings:</h4>
                        <ul class="space-y-1 text-sm">
                            {details_list}
                        </ul>
                    </div>
                    
                    <div class="bg-indigo-50 border-l-4 border-indigo-500 p-4">
                        <h4 class="text-sm font-semibold text-indigo-900 mb-1">Recommendation:</h4>
                        <p class="text-sm text-indigo-700">{r.recommendation}</p>
                    </div>
                </div>
                """

        if not details_html:
            details_html = """
            <div class="p-6 bg-green-50 text-green-800 rounded-lg border border-green-200 text-center">
                <h3 class="font-bold text-lg mb-2">System looks clean!</h3>
                <p>No critical privilege escalation vulnerabilities were triggered during this scan.</p>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Privilege Escalation Audit Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 text-gray-800 font-sans leading-normal tracking-normal">

    <div class="container mx-auto px-4 py-8 max-w-6xl">
        <!-- Header -->
        <div class="bg-white rounded-lg border border-gray-200 shadow-sm p-6 mb-8 flex flex-col md:flex-row justify-between items-start md:items-center">
            <div>
                <h1 class="text-2xl font-bold text-gray-900 flex items-center">
                    <span class="mr-2 text-indigo-600 font-extrabold">🛡️ PrivEscAuditor</span> Report
                </h1>
                <p class="text-sm text-gray-500 mt-1">Host: <span class="font-semibold text-gray-700">{node_name}</span> | OS: <span class="font-semibold text-gray-700">{os_name}</span></p>
            </div>
            <div class="mt-4 md:mt-0 text-right">
                <span class="text-xs text-gray-400 block uppercase tracking-wider font-semibold">Generated on</span>
                <span class="text-sm font-medium text-gray-700">{timestamp}</span>
            </div>
        </div>

        <!-- Summary Widgets -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div class="bg-white p-5 rounded-lg border border-gray-200 shadow-sm text-center">
                <span class="block text-gray-400 text-xs uppercase tracking-wider font-semibold">Total Checks</span>
                <span class="text-3xl font-bold text-gray-900 mt-1 block">{self.summary['total']}</span>
            </div>
            <div class="bg-white p-5 rounded-lg border border-gray-200 shadow-sm text-center">
                <span class="block text-gray-400 text-xs uppercase tracking-wider font-semibold">Triggered Risks</span>
                <span class="text-3xl font-bold text-red-600 mt-1 block">{self.summary['triggered']}</span>
            </div>
            <div class="bg-white p-5 rounded-lg border border-gray-200 shadow-sm text-center">
                <span class="block text-gray-400 text-xs uppercase tracking-wider font-semibold">Passed Checks</span>
                <span class="text-3xl font-bold text-green-600 mt-1 block">{self.summary['passed']}</span>
            </div>
            <div class="bg-white p-5 rounded-lg border border-gray-200 shadow-sm text-center">
                <span class="block text-gray-400 text-xs uppercase tracking-wider font-semibold">Critical / High</span>
                <span class="text-3xl font-bold text-orange-600 mt-1 block">{self.summary['Critical'] + self.summary['High']}</span>
            </div>
        </div>

        <!-- Summary Severity Breakdown -->
        <div class="bg-white rounded-lg border border-gray-200 shadow-sm p-6 mb-8">
            <h2 class="text-lg font-bold text-gray-900 mb-4">Risk Severity Breakdown</h2>
            <div class="flex h-4 overflow-hidden bg-gray-100 rounded-full">
                {f'<div class="bg-red-500" style="width: {self.summary["Critical"]/max(1, self.summary["triggered"])*100}%" title="Critical"></div>' if self.summary["Critical"] else ''}
                {f'<div class="bg-orange-500" style="width: {self.summary["High"]/max(1, self.summary["triggered"])*100}%" title="High"></div>' if self.summary["High"] else ''}
                {f'<div class="bg-yellow-500" style="width: {self.summary["Medium"]/max(1, self.summary["triggered"])*100}%" title="Medium"></div>' if self.summary["Medium"] else ''}
                {f'<div class="bg-blue-500" style="width: {self.summary["Low"]/max(1, self.summary["triggered"])*100}%" title="Low"></div>' if self.summary["Low"] else ''}
                {f'<div class="bg-gray-500" style="width: {self.summary["Info"]/max(1, self.summary["triggered"])*100}%" title="Info"></div>' if self.summary["Info"] else ''}
            </div>
            <div class="flex flex-wrap gap-4 mt-4 text-xs font-semibold justify-between">
                <div class="flex items-center"><span class="w-3 h-3 bg-red-500 rounded-full mr-2"></span> Critical: {self.summary['Critical']}</div>
                <div class="flex items-center"><span class="w-3 h-3 bg-orange-500 rounded-full mr-2"></span> High: {self.summary['High']}</div>
                <div class="flex items-center"><span class="w-3 h-3 bg-yellow-500 rounded-full mr-2"></span> Medium: {self.summary['Medium']}</div>
                <div class="flex items-center"><span class="w-3 h-3 bg-blue-500 rounded-full mr-2"></span> Low: {self.summary['Low']}</div>
                <div class="flex items-center"><span class="w-3 h-3 bg-gray-500 rounded-full mr-2"></span> Info: {self.summary['Info']}</div>
            </div>
        </div>

        <!-- Summary Table -->
        <div class="bg-white rounded-lg border border-gray-200 shadow-sm overflow-hidden mb-8">
            <div class="px-6 py-4 border-b border-gray-200">
                <h2 class="text-lg font-bold text-gray-900">Audit Checklist Summary</h2>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Check Name</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Category</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Severity</th>
                            <th scope="col" class="px-6 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Status</th>
                            <th scope="col" class="relative px-6 py-3">
                                <span class="sr-only">Actions</span>
                            </th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        {rows_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Triggered Findings Details -->
        <div>
            <h2 class="text-xl font-bold text-gray-900 mb-6">Detailed Findings</h2>
            {details_html}
        </div>
    </div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return output_path
