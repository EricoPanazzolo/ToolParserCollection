#!/usr/bin/env python3
import re
import sys
import html
import json
from pathlib import Path
from collections import Counter

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s).strip()


def parse_line(line: str):
    raw = strip_ansi(line)
    if not raw:
        return None

    # Typical plain nuclei output:
    # [template-id] [http] [high] https://target
    # [template-id] [dns] [info] example.com
    # [template-id] [http] [medium] https://target [extra]
    brackets = re.findall(r"\[([^\]]+)\]", raw)
    remainder = re.sub(r"^(?:\[[^\]]+\]\s*)+", "", raw).strip()

    template_id = brackets[0] if len(brackets) >= 1 else "unknown"
    protocol = brackets[1] if len(brackets) >= 2 else "unknown"

    severity = "unknown"
    metadata = []

    if len(brackets) >= 3:
        sev_candidate = brackets[2].lower()
        if sev_candidate in SEVERITIES:
            severity = sev_candidate
            metadata = brackets[3:]
        else:
            metadata = brackets[2:]

    target = remainder
    evidence = ""

    m = re.match(r"^(?P<target>\S+)(?:\s+(?P<evidence>.*))?$", remainder)
    if m:
        target = m.group("target") or ""
        evidence = m.group("evidence") or ""

    return {
        "template_id": template_id,
        "protocol": protocol,
        "severity": severity,
        "target": target,
        "evidence": evidence,
        "metadata": metadata,
        "raw": raw,
    }


def severity_rank(sev: str) -> int:
    order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "unknown": 5,
    }
    return order.get(sev, 5)


def build_html(results, source_name):
    counts = Counter(r["severity"] for r in results)
    total = len(results)

    results_sorted = sorted(
        results,
        key=lambda r: (severity_rank(r["severity"]), r["template_id"].lower(), r["target"].lower())
    )

    data_json = json.dumps(results_sorted)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Nuclei HTML Report - {html.escape(source_name)}</title>

  <style>
    :root {{
      --bg: #0b1020;
      --panel: #121a2b;
      --panel-2: #172033;
      --text: #e8eefc;
      --muted: #9fb0d1;
      --border: #26314a;

      --critical: #ff4d6d;
      --high: #ff7b54;
      --medium: #ffb703;
      --low: #7bd389;
      --info: #5dade2;
      --unknown: #9aa5b1;

      --accent: #7c5cff;
      --accent-2: #5dade2;
      --shadow: 0 10px 30px rgba(0,0,0,.25);
    }}

    * {{
      box-sizing: border-box;
    }}

    html, body {{
      margin: 0;
      padding: 0;
      width: 100%;
      max-width: 100%;
      overflow-x: hidden;
      font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(124,92,255,.16), transparent 28%),
        radial-gradient(circle at top right, rgba(93,173,226,.12), transparent 28%),
        linear-gradient(180deg, #0b1020 0%, #12193a 100%);
      color: var(--text);
    }}

    body {{
      min-height: 100vh;
    }}

    .container {{
      width: min(1300px, calc(100vw - 32px));
      margin: 0 auto;
      padding: 16px;
    }}

    .hero {{
      background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02));
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(6px);
      min-width: 0;
    }}

    .hero h1 {{
      margin: 0 0 8px;
      font-size: clamp(1.8rem, 2.5vw, 2.5rem);
      line-height: 1.1;
    }}

    .hero p {{
      margin: 0;
      color: var(--muted);
      word-break: break-word;
    }}

    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin-top: 20px;
      min-width: 0;
    }}

    .stat {{
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px 16px;
      min-width: 0;
      box-shadow: var(--shadow);
    }}

    .stat-label {{
      font-size: 0.92rem;
      color: var(--muted);
      margin-bottom: 8px;
    }}

    .stat-value {{
      font-size: 2rem;
      font-weight: 800;
      line-height: 1;
    }}

    .stat.total {{
      background: linear-gradient(135deg, #122040, #18284a);
    }}

    .stat.critical {{
      border-color: rgba(255,77,109,.35);
    }}

    .stat.critical .stat-value {{
      color: var(--critical);
    }}

    .stat.high {{
      border-color: rgba(255,123,84,.35);
    }}

    .stat.high .stat-value {{
      color: var(--high);
    }}

    .stat.medium {{
      border-color: rgba(255,183,3,.35);
    }}

    .stat.medium .stat-value {{
      color: var(--medium);
    }}

    .stat.low {{
      border-color: rgba(123,211,137,.35);
    }}

    .stat.low .stat-value {{
      color: var(--low);
    }}

    .stat.info {{
      border-color: rgba(93,173,226,.35);
    }}

    .stat.info .stat-value {{
      color: var(--info);
    }}

    .stat.unknown {{
      border-color: rgba(154,165,177,.35);
    }}

    .stat.unknown .stat-value {{
      color: var(--unknown);
    }}

    .toolbar {{
      display: grid;
      grid-template-columns: minmax(0, 1.8fr) minmax(0, 0.9fr) minmax(0, 0.9fr) auto;
      gap: 12px;
      margin-bottom: 22px;
      min-width: 0;
    }}

    .toolbar input,
    .toolbar select,
    .toolbar button {{
      width: 100%;
      min-width: 0;
      max-width: 100%;
      padding: 14px 16px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: rgba(10,18,39,.95);
      color: var(--text);
      outline: none;
      font-size: 0.95rem;
      transition: border-color .15s ease, transform .15s ease, box-shadow .15s ease;
    }}

    .toolbar input::placeholder {{
      color: #8193b9;
    }}

    .toolbar input:focus,
    .toolbar select:focus {{
      border-color: rgba(124,92,255,.55);
      box-shadow: 0 0 0 3px rgba(124,92,255,.15);
    }}

    .toolbar button {{
      background: linear-gradient(135deg, var(--accent), var(--accent-2));
      border: none;
      font-weight: 700;
      cursor: pointer;
      white-space: nowrap;
    }}

    .toolbar button:hover {{
      transform: translateY(-1px);
    }}

    .results {{
      display: grid;
      gap: 16px;
      min-width: 0;
    }}

    .card {{
      background: linear-gradient(180deg, rgba(255,255,255,.03), rgba(255,255,255,.015));
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 18px;
      box-shadow: var(--shadow);
      min-width: 0;
      overflow: hidden;
    }}

    .card-top {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 14px;
      flex-wrap: wrap;
      min-width: 0;
    }}

    .title {{
      font-size: 1.15rem;
      font-weight: 800;
      word-break: break-word;
      min-width: 0;
    }}

    .badges {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      min-width: 0;
    }}

    .badge {{
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 0.78rem;
      font-weight: 800;
      border: 1px solid var(--border);
      background: var(--panel-2);
      white-space: nowrap;
    }}

    .sev-critical {{
      color: var(--critical);
      border-color: rgba(255,77,109,.35);
    }}

    .sev-high {{
      color: var(--high);
      border-color: rgba(255,123,84,.35);
    }}

    .sev-medium {{
      color: var(--medium);
      border-color: rgba(255,183,3,.35);
    }}

    .sev-low {{
      color: var(--low);
      border-color: rgba(123,211,137,.35);
    }}

    .sev-info {{
      color: var(--info);
      border-color: rgba(93,173,226,.35);
    }}

    .sev-unknown {{
      color: var(--unknown);
      border-color: rgba(154,165,177,.35);
    }}

    .meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 12px;
      margin-top: 14px;
      min-width: 0;
    }}

    .meta-box {{
      background: rgba(9,16,35,.92);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 14px;
      min-width: 0;
    }}

    .meta-label {{
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: .06em;
      margin-bottom: 8px;
    }}

    .meta-value {{
      word-break: break-word;
      overflow-wrap: anywhere;
      line-height: 1.45;
    }}

    .meta-value code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.93rem;
      color: #dfe8ff;
    }}

    details {{
      margin-top: 14px;
    }}

    details summary {{
      cursor: pointer;
      color: var(--muted);
      user-select: none;
    }}

    pre {{
      margin-top: 10px;
      padding: 14px;
      border-radius: 14px;
      border: 1px solid var(--border);
      background: #0a0f1d;
      color: #dfe8ff;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }}

    .empty {{
      text-align: center;
      color: var(--muted);
      padding: 32px;
      border-radius: 18px;
      border: 1px dashed var(--border);
      background: rgba(255,255,255,.02);
    }}

    @media (max-width: 960px) {{
      .toolbar {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <section class="hero">
      <h1>Nuclei HTML Report</h1>
      <p>Source: <strong>{html.escape(source_name)}</strong></p>

      <div class="stats">
        <div class="stat total">
          <div class="stat-label">Total Findings</div>
          <div class="stat-value">{total}</div>
        </div>
        <div class="stat critical">
          <div class="stat-label">Critical</div>
          <div class="stat-value">{counts.get("critical", 0)}</div>
        </div>
        <div class="stat high">
          <div class="stat-label">High</div>
          <div class="stat-value">{counts.get("high", 0)}</div>
        </div>
        <div class="stat medium">
          <div class="stat-label">Medium</div>
          <div class="stat-value">{counts.get("medium", 0)}</div>
        </div>
        <div class="stat low">
          <div class="stat-label">Low</div>
          <div class="stat-value">{counts.get("low", 0)}</div>
        </div>
        <div class="stat info">
          <div class="stat-label">Info</div>
          <div class="stat-value">{counts.get("info", 0)}</div>
        </div>
      </div>
    </section>

    <section class="toolbar">
      <input id="search" type="text" placeholder="Search template, target, protocol, evidence, raw line...">
      <select id="severity">
        <option value="">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
        <option value="unknown">Unknown</option>
      </select>
      <select id="protocol">
        <option value="">All protocols</option>
      </select>
      <button id="reset" type="button">Reset Filters</button>
    </section>

    <section id="results" class="results"></section>
  </div>

  <script>
    const data = {data_json};

    const resultsEl = document.getElementById("results");
    const searchEl = document.getElementById("search");
    const severityEl = document.getElementById("severity");
    const protocolEl = document.getElementById("protocol");
    const resetEl = document.getElementById("reset");

    const protocols = [...new Set(
      data.map(x => (x.protocol || "").trim()).filter(Boolean)
    )].sort((a, b) => a.localeCompare(b));

    for (const p of protocols) {{
      const opt = document.createElement("option");
      opt.value = p;
      opt.textContent = p;
      protocolEl.appendChild(opt);
    }}

    function esc(value) {{
      return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
    }}

    function render(items) {{
      if (!items.length) {{
        resultsEl.innerHTML = '<div class="empty">No findings match the current filters.</div>';
        return;
      }}

      resultsEl.innerHTML = items.map(item => {{
        const metaTags = (item.metadata || [])
          .map(m => `<span class="badge">${{esc(m)}}</span>`)
          .join("");

        const evidence = item.evidence && item.evidence.trim() ? item.evidence : "-";

        return `
          <article class="card">
            <div class="card-top">
              <div class="title">${{esc(item.template_id)}}</div>
              <div class="badges">
                <span class="badge sev-${{esc(item.severity)}}">${{esc(item.severity.toUpperCase())}}</span>
                <span class="badge">${{esc(item.protocol || "unknown")}}</span>
                ${{metaTags}}
              </div>
            </div>

            <div class="meta">
              <div class="meta-box">
                <div class="meta-label">Target</div>
                <div class="meta-value"><code>${{esc(item.target)}}</code></div>
              </div>

              <div class="meta-box">
                <div class="meta-label">Evidence / Extra Info</div>
                <div class="meta-value">${{esc(evidence)}}</div>
              </div>
            </div>

            <details>
              <summary>Show raw line</summary>
              <pre>${{esc(item.raw)}}</pre>
            </details>
          </article>
        `;
      }}).join("");
    }}

    function applyFilters() {{
      const q = searchEl.value.trim().toLowerCase();
      const sev = severityEl.value;
      const proto = protocolEl.value;

      const filtered = data.filter(item => {{
        const searchable = [
          item.template_id,
          item.protocol,
          item.severity,
          item.target,
          item.evidence,
          ...(item.metadata || []),
          item.raw
        ]
        .join(" ")
        .toLowerCase();

        const matchesSearch = !q || searchable.includes(q);
        const matchesSeverity = !sev || item.severity === sev;
        const matchesProtocol = !proto || item.protocol === proto;

        return matchesSearch && matchesSeverity && matchesProtocol;
      }});

      render(filtered);
    }}

    searchEl.addEventListener("input", applyFilters);
    severityEl.addEventListener("change", applyFilters);
    protocolEl.addEventListener("change", applyFilters);

    resetEl.addEventListener("click", () => {{
      searchEl.value = "";
      severityEl.value = "";
      protocolEl.value = "";
      applyFilters();
      searchEl.focus();
    }});

    render(data);
  </script>
</body>
</html>
"""


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {Path(sys.argv[0]).name} nuclei-output.txt report.html")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])

    if not input_file.exists():
        print(f"Input file not found: {input_file}")
        sys.exit(1)

    results = []
    for line in input_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        parsed = parse_line(line)
        if parsed:
            results.append(parsed)

    html_report = build_html(results, input_file.name)
    output_file.write_text(html_report, encoding="utf-8")

    print(f"[+] HTML report written to: {output_file}")


if __name__ == "__main__":
    main()