"""
EML forensic parser for Glimpse.
Parses a raw .eml file into a self-contained HTML forensic report.
DNS lookups are optional (do_dns=True/False).
"""
import email
import email.policy
import hashlib
import html as html_lib
import ipaddress
import re
import quopri
import base64
from datetime import datetime, timezone
from email.header import decode_header, make_header
from typing import Optional

# -------------------------------------------------------
# Helpers
# -------------------------------------------------------

def _decode_header(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value or ""

def _safe(value) -> str:
    return html_lib.escape(str(value or ""), quote=True)

def _extract_email_addr(value: str) -> str:
    """Extract bare email address from 'Display Name <addr>' format."""
    m = re.search(r'<([^>]+)>', value or "")
    return m.group(1).strip().lower() if m else (value or "").strip().lower()

def _extract_display_name(value: str) -> str:
    m = re.match(r'^(.*?)\s*<', value or "")
    return m.group(1).strip().strip('"\'') if m else ""

def _domain(email_addr: str) -> str:
    parts = email_addr.split("@")
    return parts[-1].lower() if len(parts) == 2 else ""

def _hash_bytes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def _parse_received(line: str) -> dict:
    """Parse a Received header into structured components."""
    result = {}
    # Extract IP addresses
    ips = re.findall(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', line)
    if ips:
        result["ip"] = ips[0]
    # from/by hostnames
    from_m = re.search(r'\bfrom\s+(\S+)', line, re.IGNORECASE)
    by_m   = re.search(r'\bby\s+(\S+)', line, re.IGNORECASE)
    if from_m: result["from_host"] = from_m.group(1)
    if by_m:   result["by_host"]   = by_m.group(1)
    # timestamp
    ts_m = re.search(
        r';\s*(.{20,40}(?:GMT|UTC|[+-]\d{4}))',
        line, re.IGNORECASE
    )
    if ts_m:
        try:
            from email.utils import parsedate_to_datetime
            result["timestamp"] = parsedate_to_datetime(ts_m.group(1).strip())
        except Exception:
            result["timestamp_raw"] = ts_m.group(1).strip()
    return result

def _parse_auth_results(value: str) -> dict:
    """Parse Authentication-Results header."""
    result = {"spf": None, "dkim": None, "dmarc": None, "raw": value}
    for proto in ("spf", "dkim", "dmarc"):
        m = re.search(rf'\b{proto}=(\S+)', value, re.IGNORECASE)
        if m:
            result[proto] = m.group(1).rstrip(";").lower()
    # DKIM selector and domain
    sel_m = re.search(r'header\.s=(\S+)', value, re.IGNORECASE)
    dom_m = re.search(r'header\.d=(\S+)', value, re.IGNORECASE)
    if sel_m: result["dkim_selector"] = sel_m.group(1).rstrip(";")
    if dom_m: result["dkim_domain"]   = dom_m.group(1).rstrip(";")
    return result

def _do_dns_lookups(data: dict) -> dict:
    """Perform PTR and MX lookups. Returns enriched data."""
    dns_results = {}
    try:
        import dns.resolver
        import dns.reversename

        # PTR lookups for IPs in received chain
        for hop in data.get("received_chain", []):
            ip = hop.get("ip")
            if not ip:
                continue
            try:
                rev = dns.reversename.from_address(ip)
                answers = dns.resolver.resolve(rev, "PTR", lifetime=3)
                hop["ptr"] = str(answers[0]).rstrip(".")
            except Exception:
                hop["ptr"] = None

        # MX for From domain
        from_domain = _domain(_extract_email_addr(data.get("from", "")))
        if from_domain:
            try:
                answers = dns.resolver.resolve(from_domain, "MX", lifetime=3)
                dns_results["from_mx"] = [str(r.exchange).rstrip(".") for r in answers]
            except Exception:
                dns_results["from_mx"] = []

    except ImportError:
        dns_results["error"] = "dnspython not installed"
    except Exception as e:
        dns_results["error"] = str(e)

    data["dns"] = dns_results
    return data

def _extract_urls(text: str) -> list:
    return re.findall(
        r'https?://[^\s\'"<>)\]]+',
        text or ""
    )

def _vt_url(hash_hex: str) -> str:
    return f"https://www.virustotal.com/gui/file/{hash_hex}"

# -------------------------------------------------------
# Main parser
# -------------------------------------------------------

def parse_eml(raw_bytes: bytes, do_dns: bool = False) -> dict:
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)

    # Core headers
    subject    = _decode_header(msg.get("Subject", ""))
    from_      = _decode_header(msg.get("From", ""))
    to_        = _decode_header(msg.get("To", ""))
    cc_        = _decode_header(msg.get("Cc", ""))
    reply_to   = _decode_header(msg.get("Reply-To", ""))
    return_path = _decode_header(msg.get("Return-Path", ""))
    date_raw   = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    x_mailer   = msg.get("X-Mailer", "") or msg.get("User-Agent", "")
    x_orig_ip  = msg.get("X-Originating-IP", "") or msg.get("X-Sender-IP", "")

    # Parse all Received headers in order (oldest last in raw email)
    received_raw = msg.get_all("Received") or []
    received_chain = [_parse_received(r) for r in reversed(received_raw)]

    # Authentication results
    auth_raw = msg.get_all("Authentication-Results") or []
    arc_raw  = msg.get_all("ARC-Authentication-Results") or []
    auth_results = [_parse_auth_results(a) for a in auth_raw]
    arc_results  = [_parse_auth_results(a) for a in arc_raw]

    # All headers as ordered list
    all_headers = [(k, v) for k, v in msg.items()]

    # Body parts and attachments
    text_body   = None
    html_body   = None
    attachments = []
    mime_parts  = []

    def walk_parts(part, depth=0):
        nonlocal text_body, html_body
        ct   = part.get_content_type()
        disp = str(part.get("Content-Disposition") or "")
        fn   = part.get_filename()
        fn   = _decode_header(fn) if fn else None

        mime_parts.append({
            "depth":       depth,
            "content_type": ct,
            "disposition": disp,
            "filename":    fn,
            "encoding":    part.get("Content-Transfer-Encoding", ""),
            "charset":     part.get_content_charset() or "",
        })

        if part.is_multipart():
            for sub in part.get_payload():
                walk_parts(sub, depth + 1)
            return

        payload = part.get_payload(decode=True)
        if payload is None:
            return

        if fn or "attachment" in disp.lower():
            hashes = _hash_bytes(payload)
            attachments.append({
                "filename":     fn or "(unnamed)",
                "content_type": ct,
                "size":         len(payload),
                "md5":          hashes["md5"],
                "sha256":       hashes["sha256"],
            })
            return

        charset = part.get_content_charset() or "utf-8"
        try:
            decoded = payload.decode(charset, errors="replace")
        except Exception:
            decoded = payload.decode("utf-8", errors="replace")

        if ct == "text/plain" and text_body is None:
            text_body = decoded
        elif ct == "text/html" and html_body is None:
            html_body = decoded

    walk_parts(msg)

    # URL extraction
    urls_in_text = _extract_urls(text_body or "")
    urls_in_html = _extract_urls(html_body or "")

    # Link analysis from HTML body
    links = []
    if html_body:
        for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html_body, re.IGNORECASE | re.DOTALL):
            href    = m.group(1)
            display = re.sub(r'<[^>]+>', '', m.group(2)).strip()
            mismatch = bool(display) and ("http" in display) and (display.rstrip("/") != href.rstrip("/"))
            links.append({"href": href, "display": display, "mismatch": mismatch})

    # Tracking pixel candidates
    trackers = []
    if html_body:
        for m in re.finditer(r'<img[^>]+src=["\']([^"\']+)["\'][^>]*/?>',
                             html_body, re.IGNORECASE):
            src = m.group(1)
            w_m = re.search(r'width=["\']?(\d+)', m.group(0), re.IGNORECASE)
            h_m = re.search(r'height=["\']?(\d+)', m.group(0), re.IGNORECASE)
            w   = int(w_m.group(1)) if w_m else None
            h   = int(h_m.group(1)) if h_m else None
            if (w is not None and w <= 3) or (h is not None and h <= 3):
                trackers.append(src)

    # Timestamp delta between hops
    ts_list = []
    for hop in received_chain:
        ts = hop.get("timestamp")
        if ts:
            ts_list.append(ts)

    hop_deltas = []
    for i in range(1, len(ts_list)):
        try:
            delta = ts_list[i] - ts_list[i-1]
            hop_deltas.append(int(delta.total_seconds()))
        except Exception:
            hop_deltas.append(None)

    # Risk indicators
    risks = []
    from_addr    = _extract_email_addr(from_)
    from_domain_ = _domain(from_addr)
    rp_addr      = _extract_email_addr(return_path)
    rt_addr      = _extract_email_addr(reply_to)
    from_display = _extract_display_name(from_)

    # SPF/DKIM/DMARC
    for ar in auth_results:
        if ar.get("spf") and ar["spf"] not in ("pass",):
            risks.append({"level": "high", "type": "SPF", "detail": f"SPF result: {ar['spf']}"})
        if ar.get("dkim") and ar["dkim"] not in ("pass",):
            risks.append({"level": "high", "type": "DKIM", "detail": f"DKIM result: {ar['dkim']}"})
        if ar.get("dmarc") and ar["dmarc"] not in ("pass",):
            risks.append({"level": "high", "type": "DMARC", "detail": f"DMARC result: {ar['dmarc']}"})

    # From vs Return-Path
    if rp_addr and from_addr and _domain(rp_addr) != from_domain_:
        risks.append({"level": "medium", "type": "Return-Path mismatch",
                      "detail": f"From domain '{from_domain_}' differs from Return-Path domain '{_domain(rp_addr)}'"})

    # From vs Reply-To
    if rt_addr and from_addr and _domain(rt_addr) != from_domain_:
        risks.append({"level": "medium", "type": "Reply-To mismatch",
                      "detail": f"From domain '{from_domain_}' differs from Reply-To domain '{_domain(rt_addr)}'"})

    # Display name vs From domain
    if from_display:
        display_lower = from_display.lower()
        known_brands = ["paypal", "amazon", "microsoft", "apple", "google", "netflix",
                        "facebook", "instagram", "linkedin", "dropbox", "docusign",
                        "anz", "commbank", "westpac", "nab", "ato", "mygov"]
        for brand in known_brands:
            if brand in display_lower and brand not in from_domain_:
                risks.append({"level": "high", "type": "Display name spoofing",
                              "detail": f"Display name '{from_display}' suggests '{brand}' but From domain is '{from_domain_}'"})

    # Link mismatches
    for link in links:
        if link["mismatch"]:
            risks.append({"level": "medium", "type": "Link mismatch",
                         "detail": f"Display text '{link['display'][:60]}' differs from href"})

    # Tracking pixels
    for t in trackers:
        risks.append({"level": "low", "type": "Tracking pixel",
                     "detail": f"Possible tracking pixel: {t[:80]}"})

    data = {
        "subject":        subject,
        "from":           from_,
        "to":             to_,
        "cc":             cc_,
        "reply_to":       reply_to,
        "return_path":    return_path,
        "date_raw":       date_raw,
        "message_id":     message_id,
        "x_mailer":       x_mailer,
        "x_orig_ip":      x_orig_ip,
        "received_chain": received_chain,
        "hop_deltas":     hop_deltas,
        "auth_results":   auth_results,
        "arc_results":    arc_results,
        "all_headers":    all_headers,
        "text_body":      text_body,
        "html_body":      html_body,
        "attachments":    attachments,
        "mime_parts":     mime_parts,
        "links":          links,
        "trackers":       trackers,
        "urls_text":      urls_in_text,
        "risks":          risks,
    }

    if do_dns:
        data = _do_dns_lookups(data)

    return data


# -------------------------------------------------------
# HTML report renderer
# -------------------------------------------------------

def render_eml_report(data: dict) -> str:
    def s(v): return _safe(v)
    def badge(level):
        colours = {"high": "#ff4455", "medium": "#ffbb33", "low": "#00e5ff"}
        c = colours.get(level, "#888")
        return f'<span class="badge" style="background:{c}22;color:{c};border:1px solid {c}">{s(level.upper())}</span>'

    # Risk summary
    risk_html = ""
    if data["risks"]:
        items = "".join(
            f'<div class="risk-item">{badge(r["level"])} <strong>{s(r["type"])}</strong> — {s(r["detail"])}</div>'
            for r in data["risks"]
        )
        risk_html = f'<div class="section risk-section"><div class="section-title">⚠ Risk Indicators ({len(data["risks"])})</div>{items}</div>'
    else:
        risk_html = '<div class="section risk-section clean"><div class="section-title">✓ No risk indicators detected</div></div>'

    # Received chain
    chain_rows = ""
    for i, hop in enumerate(data["received_chain"]):
        ts  = hop.get("timestamp")
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else hop.get("timestamp_raw", "")
        delta = ""
        if i < len(data["hop_deltas"]) and data["hop_deltas"][i] is not None:
            d = data["hop_deltas"][i]
            delta = f'<span class="delta">+{d}s</span>' if d >= 0 else f'<span class="delta warn">⚠ {d}s</span>'
        ptr = f'<br><span class="dim">PTR: {s(hop["ptr"])}</span>' if hop.get("ptr") else ""
        chain_rows += f"""
        <tr>
          <td class="hop-num">{i+1}</td>
          <td>{s(hop.get("from_host",""))} {ptr}</td>
          <td>{s(hop.get("by_host",""))}</td>
          <td>{s(hop.get("ip",""))}</td>
          <td>{s(ts_str)} {delta}</td>
        </tr>"""

    # Auth results
    auth_html = ""
    for ar in data["auth_results"]:
        def auth_badge(result):
            if not result: return '<span class="auth-na">N/A</span>'
            c = "#00c896" if result == "pass" else "#ff4455"
            return f'<span class="auth-result" style="color:{c}">{s(result.upper())}</span>'
        auth_html += f"""
        <div class="auth-row">
          <span class="auth-label">SPF</span>{auth_badge(ar.get("spf"))}
          <span class="auth-label">DKIM</span>{auth_badge(ar.get("dkim"))}
          {f'<span class="dim">selector: {s(ar["dkim_selector"])}</span>' if ar.get("dkim_selector") else ""}
          {f'<span class="dim">domain: {s(ar["dkim_domain"])}</span>' if ar.get("dkim_domain") else ""}
          <span class="auth-label">DMARC</span>{auth_badge(ar.get("dmarc"))}
        </div>"""

    # ARC
    arc_html = ""
    for ar in data["arc_results"]:
        arc_html += f'<div class="dim small">ARC: SPF={s(ar.get("spf",""))} DKIM={s(ar.get("dkim",""))} DMARC={s(ar.get("dmarc",""))}</div>'

    # Attachments
    att_html = ""
    for att in data["attachments"]:
        vt_link = f'<a href="{_vt_url(att["sha256"])}" target="_blank" class="vt-link">VirusTotal ↗</a>'
        att_html += f"""
        <div class="attachment-item">
          <div class="att-name">📎 {s(att["filename"])}</div>
          <div class="att-meta">
            {s(att["content_type"])} &middot; {att["size"]:,} bytes
            {vt_link}
          </div>
          <div class="hash-row">
            <span class="hash-label">MD5</span><code>{s(att["md5"])}</code>
            <span class="hash-label">SHA256</span><code class="small">{s(att["sha256"])}</code>
          </div>
        </div>"""
    if not att_html:
        att_html = '<div class="dim">No attachments</div>'

    # Links
    link_html = ""
    for link in data["links"][:50]:
        warn = ' class="link-mismatch"' if link["mismatch"] else ""
        link_html += f'<div{warn}><span class="dim">display:</span> {s(link["display"][:80])} <span class="dim">href:</span> <a href="{s(link["href"])}" target="_blank" rel="noopener noreferrer">{s(link["href"][:100])}</a></div>'
    if not link_html:
        link_html = '<div class="dim">No links found</div>'

    # Trackers
    tracker_html = ""
    for t in data["trackers"]:
        tracker_html += f'<div class="tracker-item">🔍 {s(t)}</div>'
    if not tracker_html:
        tracker_html = '<div class="dim">No tracking pixels detected</div>'

    # MIME tree
    mime_html = ""
    for part in data["mime_parts"]:
        indent = "&nbsp;" * (part["depth"] * 4)
        mime_html += f'<div>{indent}<span class="mime-type">{s(part["content_type"])}</span>'
        if part["filename"]: mime_html += f' <span class="dim">{s(part["filename"])}</span>'
        if part["encoding"]: mime_html += f' <span class="dim">[{s(part["encoding"])}]</span>'
        mime_html += '</div>'

    # All headers raw
    headers_html = "".join(
        f'<div class="header-row"><span class="header-key">{s(k)}:</span> <span class="header-val">{s(v)}</span></div>'
        for k, v in data["all_headers"]
    )

    # Body
    body_html = ""
    if data["html_body"]:
        body_html += f"""
        <div class="section">
          <div class="section-title">HTML Body <button class="toggle-btn" onclick="toggleRaw()">Show Raw HTML</button></div>
          <iframe id="body-iframe" sandbox="allow-same-origin" srcdoc="{html_lib.escape(data['html_body'], quote=True)}"
            style="width:100%;min-height:300px;border:1px solid #1e1e28;border-radius:3px;background:#fff"></iframe>
          <pre id="body-raw" style="display:none;white-space:pre-wrap;font-size:11px;color:#c8ccd8;background:#0a0a0c;padding:14px;border-radius:3px;overflow-x:auto">{s(data['html_body'])}</pre>
        </div>"""
    if data["text_body"]:
        body_html += f"""
        <div class="section">
          <div class="section-title">Plain Text Body</div>
          <pre style="white-space:pre-wrap;font-size:12px;color:#c8ccd8;background:#0a0a0c;padding:14px;border-radius:3px">{s(data['text_body'])}</pre>
        </div>"""

    # DNS section
    dns_html = ""
    if "dns" in data:
        dns = data["dns"]
        if dns.get("error"):
            dns_html = f'<div class="section"><div class="section-title">DNS</div><div class="dim">{s(dns["error"])}</div></div>'
        else:
            mx_list = ", ".join(dns.get("from_mx", [])) or "none found"
            dns_html = f"""
            <div class="section">
              <div class="section-title">DNS Lookups</div>
              <div><span class="header-key">From domain MX:</span> {s(mx_list)}</div>
            </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Glimpse — Email Forensics</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>📧</text></svg>">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
:root{{--bg:#0a0a0c;--surface:#111116;--border:#1e1e28;--accent:#00e5ff;--success:#00c896;--danger:#ff4455;--warn:#ffbb33;--text:#c8ccd8;--dim:#555570}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:12px;padding:24px;max-width:1100px;margin:0 auto;line-height:1.6}}
h1{{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:#fff;margin-bottom:4px}}
h1 span{{color:var(--accent)}}
.subtitle{{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);margin-bottom:28px}}
.section{{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:18px;margin-bottom:16px}}
.section-title{{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:var(--dim);margin-bottom:12px;font-weight:600}}
.risk-section{{border-color:#ff445533}}
.risk-section.clean{{border-color:#00c89633}}
.risk-item{{padding:6px 0;border-bottom:1px solid var(--border)}}
.risk-item:last-child{{border-bottom:none}}
.badge{{font-size:9px;letter-spacing:1px;padding:2px 7px;border-radius:3px;margin-right:8px;font-weight:700}}
.meta-grid{{display:grid;grid-template-columns:120px 1fr;gap:4px 12px}}
.meta-key{{color:var(--dim);font-size:11px}}
.meta-val{{color:var(--text);word-break:break-all}}
table{{width:100%;border-collapse:collapse;font-size:11px}}
th{{font-size:9px;letter-spacing:2px;text-transform:uppercase;color:var(--dim);text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)}}
td{{padding:7px 8px;border-bottom:1px solid var(--border);vertical-align:top}}
.hop-num{{color:var(--dim);text-align:center;width:30px}}
.delta{{font-size:10px;color:var(--success);margin-left:6px}}
.delta.warn{{color:var(--warn)}}
.auth-row{{display:flex;align-items:center;gap:12px;padding:6px 0;flex-wrap:wrap}}
.auth-label{{font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--dim);margin-right:4px}}
.auth-result{{font-weight:700;font-size:12px}}
.auth-na{{color:var(--dim)}}
.attachment-item{{padding:10px 0;border-bottom:1px solid var(--border)}}
.attachment-item:last-child{{border-bottom:none}}
.att-name{{color:#fff;font-weight:600;margin-bottom:4px}}
.att-meta{{color:var(--dim);font-size:11px;margin-bottom:4px}}
.hash-row{{font-size:10px;color:var(--dim);display:flex;gap:12px;flex-wrap:wrap;align-items:center}}
.hash-label{{color:var(--dim);font-size:9px;letter-spacing:1px;text-transform:uppercase}}
code{{background:#0a0a0c;padding:1px 4px;border-radius:2px;font-size:10px}}
.small{{font-size:10px}}
.vt-link{{color:var(--accent);font-size:10px;margin-left:8px;text-decoration:none}}
.vt-link:hover{{text-decoration:underline}}
.link-mismatch{{color:var(--warn);padding:3px 0}}
.tracker-item{{color:var(--warn);padding:3px 0}}
.mime-type{{color:var(--accent)}}
.header-row{{display:grid;grid-template-columns:200px 1fr;gap:8px;padding:3px 0;border-bottom:1px solid #1e1e2855}}
.header-key{{color:var(--dim);font-size:11px;word-break:break-word}}
.header-val{{word-break:break-all;font-size:11px}}
.dim{{color:var(--dim)}}
.toggle-btn{{font-family:'JetBrains Mono',monospace;font-size:10px;background:transparent;border:1px solid var(--border);color:var(--dim);padding:3px 10px;border-radius:2px;cursor:pointer;margin-left:10px}}
.toggle-btn:hover{{border-color:var(--accent);color:var(--accent)}}
details summary{{cursor:pointer;color:var(--dim);font-size:10px;letter-spacing:2px;text-transform:uppercase;padding:4px 0}}
details summary:hover{{color:var(--accent)}}
</style>
</head>
<body>
<h1>Gl<span>i</span>mpse <span style="font-size:14px;font-weight:400;color:var(--dim)">/ Email Forensics</span></h1>
<div class="subtitle">Analysed &middot; Encrypted &middot; Shared</div>

<!-- Summary -->
<div class="section">
  <div class="section-title">Summary</div>
  <div class="meta-grid">
    <span class="meta-key">Subject</span><span class="meta-val"><strong>{s(data["subject"])}</strong></span>
    <span class="meta-key">From</span><span class="meta-val">{s(data["from"])}</span>
    <span class="meta-key">To</span><span class="meta-val">{s(data["to"])}</span>
    {"<span class='meta-key'>CC</span><span class='meta-val'>" + s(data["cc"]) + "</span>" if data["cc"] else ""}
    <span class="meta-key">Date</span><span class="meta-val">{s(data["date_raw"])}</span>
    <span class="meta-key">Message-ID</span><span class="meta-val">{s(data["message_id"])}</span>
    {"<span class='meta-key'>Reply-To</span><span class='meta-val'>" + s(data["reply_to"]) + "</span>" if data["reply_to"] else ""}
    {"<span class='meta-key'>Return-Path</span><span class='meta-val'>" + s(data["return_path"]) + "</span>" if data["return_path"] else ""}
    {"<span class='meta-key'>X-Mailer</span><span class='meta-val'>" + s(data["x_mailer"]) + "</span>" if data["x_mailer"] else ""}
    {"<span class='meta-key'>X-Orig-IP</span><span class='meta-val'>" + s(data["x_orig_ip"]) + "</span>" if data["x_orig_ip"] else ""}
  </div>
</div>

{risk_html}

<!-- Auth Results -->
<div class="section">
  <div class="section-title">Authentication Results</div>
  {auth_html or '<div class="dim">No Authentication-Results header found</div>'}
  {arc_html}
</div>

{dns_html}

<!-- Received Chain -->
<div class="section">
  <div class="section-title">Received Chain ({len(data["received_chain"])} hops)</div>
  <table>
    <thead><tr><th>#</th><th>From</th><th>By</th><th>IP</th><th>Timestamp</th></tr></thead>
    <tbody>{chain_rows or "<tr><td colspan='5' class='dim'>No Received headers found</td></tr>"}</tbody>
  </table>
</div>

{body_html}

<!-- Links -->
<div class="section">
  <div class="section-title">Links ({len(data["links"])})</div>
  {link_html}
</div>

<!-- Tracking Pixels -->
<div class="section">
  <div class="section-title">Tracking Pixels</div>
  {tracker_html}
</div>

<!-- Attachments -->
<div class="section">
  <div class="section-title">Attachments ({len(data["attachments"])})</div>
  {att_html}
</div>

<!-- MIME Structure -->
<details>
  <summary>MIME Structure</summary>
  <div class="section" style="margin-top:8px">{mime_html}</div>
</details>

<!-- All Headers -->
<details>
  <summary>All Headers ({len(data["all_headers"])})</summary>
  <div class="section" style="margin-top:8px">{headers_html}</div>
</details>

<script>
function toggleRaw() {{
  const iframe = document.getElementById('body-iframe');
  const raw    = document.getElementById('body-raw');
  if (!iframe || !raw) return;
  const showing = raw.style.display !== 'none';
  iframe.style.display = showing ? '' : 'none';
  raw.style.display    = showing ? 'none' : 'block';
  document.querySelector('.toggle-btn').textContent = showing ? 'Show Raw HTML' : 'Show Rendered';
}}
</script>
</body>
</html>"""
