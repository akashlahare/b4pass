# -*- coding: utf-8 -*-
# HTMLReport — dark terminal-style with bypass results
import os
import sys
import time
from engine.reports.base import FileBaseReport
from engine.utils.common import human_size


class HTMLReport(FileBaseReport):
    def generate(self, entries, bypass_results=None):
        bypass_data = list(bypass_results) if bypass_results else []

        meta_cmd  = " ".join(sys.argv)
        meta_date = time.strftime("%Y-%m-%d %H:%M:%S")
        target    = entries[0].url.split("/")[0] + "//" + entries[0].url.split("/")[2] if entries else ""

        # Build discovery rows
        disc_rows = ""
        status_counts = {}
        for e in entries:
            sc = e.status
            status_counts[sc] = status_counts.get(sc, 0) + 1
            if 200 <= sc <= 299:
                cls = "s2xx"
            elif 300 <= sc <= 399:
                cls = "s3xx"
            elif sc == 403:
                cls = "s403"
            elif 400 <= sc <= 499:
                cls = "s4xx"
            elif 500 <= sc <= 599:
                cls = "s5xx"
            else:
                cls = ""

            redir = f'<span class="redir">→ {e.redirect}</span>' if e.redirect else ""
            disc_rows += (
                f'<tr class="disc-row" data-status="{sc}">'
                f'<td class="{cls}">{sc}</td>'
                f'<td>{human_size(e.length)}</td>'
                f'<td><a href="{e.url}" target="_blank" class="url-link">{e.url}</a>{redir}</td>'
                f'<td class="ctype">{getattr(e, "type", "")}</td>'
                f'</tr>\n'
            )

        # Build bypass rows grouped by path
        bypass_by_path = {}
        for b in bypass_data:
            p = b.get("url", "")
            bypass_by_path.setdefault(p, []).append(b)

        bypass_sections = ""
        confirmed_rows  = ""
        for b in bypass_data:
            sc = b.get("status", "")
            if 200 <= int(sc or 0) <= 299:
                cls = "s2xx"
            elif 300 <= int(sc or 0) <= 399:
                cls = "s3xx"
            elif 500 <= int(sc or 0) <= 599:
                cls = "s5xx"
            else:
                cls = "bypass-hit"

            burp_html = ""
            if b.get("burp"):
                burp_lines = b["burp"].replace("<","&lt;").replace(">","&gt;")
                burp_html  = f'<div class="burp-box"><span class="burp-label">↳ BURP SUITE STEPS</span><pre>{burp_lines}</pre></div>'

            redir = f'<span class="redir">→ {b["redirect"]}</span>' if b.get("redirect") else ""
            # Same tag shown in the terminal: a confidence percentage, or
            # the root-echo warning when confidence doesn't apply.
            tag_text = "[BYPASS!\u26a0]" if b.get("root_echo") \
                else f"[BYPASS! {b.get('confidence', 100)}%]"
            confirmed_rows += (
                f'<tr class="bypass-row">'
                f'<td class="{cls} tag-cell">{tag_text}</td>'
                f'<td class="{cls}">{sc}</td>'
                f'<td>{b.get("method","GET")}</td>'
                f'<td>{b.get("size","?")}B</td>'
                f'<td class="tech-cell">{b.get("technique","")}</td>'
                f'<td><a href="{b.get("url","")}" target="_blank" class="url-link">{b.get("url","")}</a>{redir}</td>'
                f'<td>{burp_html}</td>'
                f'</tr>\n'
            )

        # Stats bar
        stats_items = ""
        for code, count in sorted(status_counts.items()):
            if 200 <= code <= 299:   c = "#4af"
            elif 300 <= code <= 399: c = "#fa4"
            elif code == 403:        c = "#f74"
            elif 400 <= code <= 499: c = "#f44"
            else:                    c = "#a4f"
            stats_items += f'<span class="stat-badge" style="border-color:{c};color:{c}">{code} <b>{count}</b></span>'

        bypass_count = len(bypass_data)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>b4pass Report — {target}</title>
<style>
  :root {{
    --bg:      #0d0d0d;
    --bg2:     #141414;
    --bg3:     #1a1a1a;
    --border:  #2a2a2a;
    --text:    #c8c8c8;
    --dim:     #555;
    --green:   #4af542;
    --yellow:  #f5c542;
    --cyan:    #42d4f5;
    --blue:    #4286f5;
    --red:     #f54242;
    --magenta: #c542f5;
    --orange:  #f5834a;
    --white:   #ffffff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Courier New', 'Consolas', monospace;
    font-size: 13px;
    line-height: 1.6;
    padding: 0;
  }}

  /* ── Header ── */
  .header {{
    background: var(--bg2);
    border-bottom: 2px solid var(--cyan);
    padding: 20px 30px 16px;
  }}
  .header-brand {{
    color: var(--cyan);
    font-size: 28px;
    font-weight: bold;
    letter-spacing: 4px;
    margin-bottom: 14px;
    text-shadow: 0 0 8px rgba(66, 212, 245, 0.35);
  }}
  .header-brand .accent {{ color: var(--green); }}
  .header-meta {{ color: var(--dim); font-size: 12px; }}
  .header-meta span {{ color: var(--text); }}
  .target-badge {{
    display: inline-block;
    background: #042a1a;
    border: 1px solid var(--green);
    color: var(--green);
    padding: 4px 14px;
    border-radius: 3px;
    margin-top: 8px;
    font-size: 14px;
    font-weight: bold;
  }}

  /* ── Stats bar ── */
  .stats-bar {{
    background: var(--bg3);
    border-bottom: 1px solid var(--border);
    padding: 12px 30px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
  }}
  .stat-badge {{
    border: 1px solid;
    padding: 2px 10px;
    border-radius: 3px;
    font-size: 12px;
  }}
  .bypass-stat {{
    border: 1px solid var(--green);
    color: var(--green);
    background: #0a2010;
    padding: 2px 12px;
    border-radius: 3px;
    font-size: 12px;
    font-weight: bold;
    margin-left: auto;
  }}

  /* ── Nav tabs ── */
  .tabs {{
    display: flex;
    background: var(--bg2);
    border-bottom: 1px solid var(--border);
    padding: 0 30px;
  }}
  .tab {{
    padding: 10px 22px;
    cursor: pointer;
    color: var(--dim);
    border-bottom: 2px solid transparent;
    transition: all 0.2s;
    font-size: 13px;
  }}
  .tab:hover {{ color: var(--text); }}
  .tab.active {{ color: var(--cyan); border-bottom-color: var(--cyan); }}

  /* ── Content panels ── */
  .panel {{ display: none; padding: 24px 30px; }}
  .panel.active {{ display: block; }}

  /* ── Filter bar ── */
  .filter-bar {{
    display: flex;
    gap: 10px;
    margin-bottom: 16px;
    align-items: center;
    flex-wrap: wrap;
  }}
  .filter-bar input {{
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 6px 12px;
    border-radius: 3px;
    font-family: monospace;
    font-size: 12px;
    width: 280px;
  }}
  .filter-bar input:focus {{ outline: none; border-color: var(--cyan); }}
  .filter-btn {{
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text);
    padding: 5px 12px;
    border-radius: 3px;
    cursor: pointer;
    font-family: monospace;
    font-size: 12px;
  }}
  .filter-btn.active {{ border-color: var(--cyan); color: var(--cyan); }}
  .filter-btn:hover {{ border-color: var(--text); }}
  .result-count {{ color: var(--dim); font-size: 12px; margin-left: auto; }}

  /* ── Tables ── */
  .section-title {{
    color: var(--cyan);
    font-size: 13px;
    font-weight: bold;
    margin-bottom: 10px;
    padding-bottom: 6px;
    border-bottom: 1px solid var(--border);
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }}
  th {{
    background: var(--bg3);
    color: var(--dim);
    text-align: left;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    font-weight: normal;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-size: 11px;
    position: sticky;
    top: 0;
    z-index: 1;
  }}
  td {{
    padding: 6px 12px;
    border-bottom: 1px solid #1a1a1a;
    vertical-align: top;
  }}
  tr:hover td {{ background: #181818; }}

  /* Status colors */
  .s2xx {{ color: var(--green); font-weight: bold; }}
  .s3xx {{ color: var(--cyan); }}
  .s403 {{ color: var(--orange); }}
  .s4xx {{ color: var(--red); }}
  .s5xx {{ color: var(--magenta); }}
  .bypass-hit {{ color: var(--green); font-weight: bold; }}
  .tag-cell {{ color: var(--green); font-weight: bold; white-space: nowrap; }}
  .tech-cell {{ color: var(--yellow); }}
  .ctype {{ color: var(--dim); font-size: 11px; }}
  .redir {{ color: var(--blue); font-size: 11px; display: block; }}
  .url-link {{ color: var(--text); text-decoration: none; }}
  .url-link:hover {{ color: var(--cyan); text-decoration: underline; }}

  /* Bypass box */
  .burp-box {{
    background: #060e06;
    border: 1px solid #1a3a1a;
    border-left: 3px solid var(--green);
    padding: 8px 12px;
    margin-top: 6px;
    border-radius: 3px;
  }}
  .burp-label {{
    color: var(--yellow);
    font-size: 11px;
    font-weight: bold;
    display: block;
    margin-bottom: 4px;
  }}
  .burp-box pre {{
    color: var(--green);
    font-size: 11px;
    white-space: pre-wrap;
    word-break: break-all;
  }}

  /* No data */
  .no-data {{
    text-align: center;
    color: var(--dim);
    padding: 40px;
    font-size: 13px;
  }}

  /* Copy button */
  .copy-btn {{
    background: #042a1a;
    border: 1px solid var(--green);
    color: var(--green);
    padding: 3px 10px;
    border-radius: 3px;
    cursor: pointer;
    font-size: 11px;
    font-family: monospace;
  }}
  .copy-btn:hover {{ background: #073d20; }}

  /* Scrollable table wrapper */
  .table-wrap {{
    overflow-x: auto;
    max-height: 70vh;
    overflow-y: auto;
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-brand">b4<span class="accent">pass</span></div>
  <div class="header-meta">
    <div>Command : <span>{meta_cmd}</span></div>
    <div>Date    : <span>{meta_date}</span></div>
  </div>
  <div class="target-badge">⌖ {target}</div>
</div>

<div class="stats-bar">
  <span style="color:var(--dim);font-size:11px">STATUS CODES:</span>
  {stats_items}
  <span class="bypass-stat">⚡ {bypass_count} BYPASS{'ES' if bypass_count != 1 else ''} FOUND</span>
</div>

<div class="tabs">
  <div class="tab active" onclick="switchTab('discovery',this)">📂 Discovery ({len(entries)} paths)</div>
  <div class="tab" onclick="switchTab('bypass',this)">⚡ Bypass Results ({bypass_count})</div>
</div>

<!-- ── DISCOVERY PANEL ── -->
<div id="panel-discovery" class="panel active">
  <div class="filter-bar">
    <input type="text" id="disc-search" placeholder="Filter by URL or status..." onkeyup="filterDisc()">
    <button class="filter-btn" onclick="filterDiscStatus(0)">All</button>
    <button class="filter-btn" onclick="filterDiscStatus(200)">2xx</button>
    <button class="filter-btn" onclick="filterDiscStatus(301)">3xx</button>
    <button class="filter-btn" onclick="filterDiscStatus(403)">403</button>
    <button class="filter-btn" onclick="filterDiscStatus(500)">5xx</button>
    <span class="result-count" id="disc-count">{len(entries)} results</span>
  </div>
  <div class="table-wrap">
    <table id="disc-table">
      <thead>
        <tr>
          <th>STATUS</th>
          <th>SIZE</th>
          <th>URL</th>
          <th>TYPE</th>
        </tr>
      </thead>
      <tbody>
        {disc_rows if disc_rows else '<tr><td colspan="4" class="no-data">No results found</td></tr>'}
      </tbody>
    </table>
  </div>
</div>

<!-- ── BYPASS PANEL ── -->
<div id="panel-bypass" class="panel">
  {'<div class="no-data">No bypasses found during this scan.</div>' if not confirmed_rows else f"""
  <div class="filter-bar">
    <input type="text" id="bypass-search" placeholder="Filter by technique or URL..." onkeyup="filterBypass()">
    <span class="result-count" id="bypass-count">{bypass_count} bypass{'es' if bypass_count != 1 else ''}</span>
  </div>
  <div class="table-wrap">
    <table id="bypass-table">
      <thead>
        <tr>
          <th>TAG</th>
          <th>STATUS</th>
          <th>METHOD</th>
          <th>SIZE</th>
          <th>TECHNIQUE</th>
          <th>URL</th>
          <th>BURP STEPS</th>
        </tr>
      </thead>
      <tbody>
        {confirmed_rows}
      </tbody>
    </table>
  </div>
  """}
</div>

<script>
  function switchTab(name, el) {{
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    el.classList.add('active');
    document.getElementById('panel-' + name).classList.add('active');
  }}

  function filterDisc() {{
    const q = document.getElementById('disc-search').value.toLowerCase();
    const rows = document.querySelectorAll('#disc-table tbody tr.disc-row');
    let vis = 0;
    rows.forEach(r => {{
      const match = r.textContent.toLowerCase().includes(q);
      r.style.display = match ? '' : 'none';
      if (match) vis++;
    }});
    document.getElementById('disc-count').textContent = vis + ' results';
  }}

  function filterDiscStatus(code) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    const rows = document.querySelectorAll('#disc-table tbody tr.disc-row');
    let vis = 0;
    rows.forEach(r => {{
      const st = parseInt(r.dataset.status);
      const show = code === 0 || (code === 200 && st>=200 && st<=299)
                || (code === 301 && st>=300 && st<=399)
                || (code === 403 && st===403)
                || (code === 500 && st>=500 && st<=599);
      r.style.display = show ? '' : 'none';
      if (show) vis++;
    }});
    document.getElementById('disc-count').textContent = vis + ' results';
  }}

  function filterBypass() {{
    const q = document.getElementById('bypass-search').value.toLowerCase();
    const rows = document.querySelectorAll('#bypass-table tbody tr.bypass-row');
    let vis = 0;
    rows.forEach(r => {{
      const match = r.textContent.toLowerCase().includes(q);
      r.style.display = match ? '' : 'none';
      if (match) vis++;
    }});
    document.getElementById('bypass-count').textContent = vis + ' bypasses';
  }}
</script>
</body>
</html>"""
        return html
