from datetime import datetime
import json
import html


class ReportGenerator:
    """
    Generates interactive HTML security reports
    with per-container (image) drill-down,
    before/after comparison, and CSV export.
    """

    def __init__(self, scan_results, vulnerabilities, comparison=None):
        self.scan_results = scan_results
        self.vulnerabilities = vulnerabilities
        self.comparison = comparison

    def generate_html_report(self, output_file='security_report.html'):
        vuln_json = json.dumps(self.vulnerabilities)
        comparison_json = json.dumps(self.comparison) if self.comparison else "null"

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Docker Security Scan Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {{ font-family: Arial; background:#f4f6f9; padding:20px }}
h1 {{ text-align:center }}

.cards {{
  display:flex; gap:15px; justify-content:center; flex-wrap:wrap;
}}
.card {{
  background:white; padding:15px; border-radius:10px;
  width:160px; text-align:center; box-shadow:0 2px 6px rgba(0,0,0,.1)
}}

.CRITICAL {{ color:red }}
.HIGH {{ color:orange }}
.MEDIUM {{ color:#caa000 }}
.LOW {{ color:green }}

table {{ width:100%; border-collapse:collapse; background:white }}
th,td {{ padding:8px; border-bottom:1px solid #ddd }}
th {{ background:#333; color:white }}

.controls {{
  margin:15px 0;
  display:flex;
  gap:10px;
  flex-wrap:wrap;
  align-items:center;
}}

.pagination {{ margin-top:10px; text-align:center }}
button {{ padding:6px 12px; cursor:pointer }}
</style>
</head>

<body>

<h1>🔒 Docker Security Scan Report</h1>
<p style="text-align:center">
<b>Image Scope:</b> {html.escape(self.scan_results.get('image_name','N/A'))} |
<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
</p>

<h2>📊 Scan Summary</h2>
<div class="cards">
  <div class="card CRITICAL">Critical<br><b id="sumCritical">0</b></div>
  <div class="card HIGH">High<br><b id="sumHigh">0</b></div>
  <div class="card MEDIUM">Medium<br><b id="sumMedium">0</b></div>
  <div class="card LOW">Low<br><b id="sumLow">0</b></div>
  <div class="card">Total<br><b id="sumTotal">0</b></div>
</div>

<canvas id="summaryChart" height="90"></canvas>

<div id="comparisonSection" style="display:none">
<h2>🔄 Before vs After Validation</h2>
<div class="cards">
  <div class="card">Critical<br><b id="cCrit"></b></div>
  <div class="card">High<br><b id="cHigh"></b></div>
  <div class="card">Medium<br><b id="cMed"></b></div>
  <div class="card">Low<br><b id="cLow"></b></div>
</div>
<canvas id="compareChart" height="90"></canvas>
</div>

<h2>🐛 Vulnerabilities</h2>

<div class="controls">
<label>Image:</label>
<select id="imageFilter">
  <option value="ALL">ALL IMAGES</option>
</select>

<label>Severity:</label>
<select id="severityFilter">
  <option value="ALL">ALL</option>
  <option value="CRITICAL">CRITICAL</option>
  <option value="HIGH">HIGH</option>
  <option value="MEDIUM">MEDIUM</option>
  <option value="LOW">LOW</option>
</select>

<button onclick="exportCSV()">📄 Export CSV</button>
</div>

<table>
<thead>
<tr>
<th>Image</th>
<th>CVE</th>
<th>Severity</th>
<th>Package</th>
<th>Installed</th>
<th>Fixed</th>
</tr>
</thead>
<tbody id="table"></tbody>
</table>

<div class="pagination" id="pagination"></div>

<script>
const vulns = {vuln_json};
const comparison = {comparison_json};

let page = 1;
const size = 10;
let chart = null;

// Populate image dropdown
const imageFilter = document.getElementById("imageFilter");
const images = [...new Set(vulns.map(v => v.image))];
images.forEach(img => {{
  const opt = document.createElement("option");
  opt.value = img;
  opt.textContent = img;
  imageFilter.appendChild(opt);
}});

function getFilteredData() {{
  const sev = document.getElementById("severityFilter").value;
  const img = document.getElementById("imageFilter").value;

  return vulns.filter(v => {{
    const sevMatch = sev === "ALL" || v.severity === sev;
    const imgMatch = img === "ALL" || v.image === img;
    return sevMatch && imgMatch;
  }});
}}

function updateSummary(data) {{
  const count = {{CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0}};
  data.forEach(v => count[v.severity]++);

  document.getElementById("sumCritical").innerText = count.CRITICAL;
  document.getElementById("sumHigh").innerText = count.HIGH;
  document.getElementById("sumMedium").innerText = count.MEDIUM;
  document.getElementById("sumLow").innerText = count.LOW;
  document.getElementById("sumTotal").innerText = data.length;

  if (chart) chart.destroy();
  chart = new Chart(document.getElementById("summaryChart"), {{
    type: "bar",
    data: {{
      labels: ["CRITICAL","HIGH","MEDIUM","LOW"],
      datasets: [{{
        label: "Vulnerabilities",
        data: [count.CRITICAL, count.HIGH, count.MEDIUM, count.LOW],
        backgroundColor: ["red","orange","gold","green"]
      }}]
    }}
  }});
}}

function renderTable() {{
  const data = getFilteredData();
  updateSummary(data);

  const start = (page - 1) * size;
  const rows = data.slice(start, start + size);
  const t = document.getElementById("table");
  t.innerHTML = "";

  rows.forEach(v => t.innerHTML += `
<tr>
<td>${{v.image}}</td>
<td>${{v.cve_id}}</td>
<td class="${{v.severity}}">${{v.severity}}</td>
<td>${{v.package_name}}</td>
<td>${{v.installed_version}}</td>
<td>${{v.fixed_version}}</td>
</tr>`);

  renderPages(data.length);
}}

function renderPages(total) {{
  const pages = Math.ceil(total / size);
  const c = document.getElementById("pagination");
  c.innerHTML = "";
  for (let i = 1; i <= pages; i++) {{
    c.innerHTML += `<button onclick="go(${{i}})">${{i}}</button>`;
  }}
}}

function go(i) {{
  page = i;
  renderTable();
}}

document.getElementById("severityFilter").onchange = () => {{ page = 1; renderTable(); }};
document.getElementById("imageFilter").onchange = () => {{ page = 1; renderTable(); }};

// CSV Export
function exportCSV() {{
  const data = getFilteredData();
  let csv = "Image,CVE,Severity,Package,Installed,Fixed\\n";
  data.forEach(v => {{
    csv += `${{v.image}},${{v.cve_id}},${{v.severity}},${{v.package_name}},${{v.installed_version}},${{v.fixed_version}}\\n`;
  }});

  const blob = new Blob([csv], {{ type: "text/csv" }});
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "security_report.csv";
  a.click();
  window.URL.revokeObjectURL(url);
}}

if (comparison) {{
  document.getElementById("comparisonSection").style.display = "block";
  document.getElementById("cCrit").innerText = comparison.reduction_percentage.critical + "%";
  document.getElementById("cHigh").innerText = comparison.reduction_percentage.high + "%";
  document.getElementById("cMed").innerText = comparison.reduction_percentage.medium + "%";
  document.getElementById("cLow").innerText = comparison.reduction_percentage.low + "%";
}}

renderTable();
</script>

</body>
</html>
"""
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"✅ Report generated: {output_file}")
