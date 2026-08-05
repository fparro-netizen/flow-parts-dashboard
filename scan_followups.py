#!/usr/bin/env python3
"""
Scan Apple Mail's local store for unanswered requests from Flow Auto colleagues.

Runs on Frank's Mac, where Apple Mail has already downloaded the mail.
Nothing leaves the machine: no network calls, no credentials, no forwarding.

Usage:
    python3 scan_followups.py                  # last 60 days
    python3 scan_followups.py --days 30
    python3 scan_followups.py --domain flowauto.com --me FPARRO@flowauto.com

Output:
    followups_local.html   (gitignored — contains real message content)
    plus a summary table in the terminal

Note: macOS protects ~/Library/Mail. If the scan finds no mail files, grant
Full Disk Access to your terminal (or the Claude app) in
System Settings > Privacy & Security > Full Disk Access, then re-run.
"""

import argparse
import email
import email.utils
import glob
import html
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from email.header import decode_header, make_header

# Phrases that signal someone is asking you to do something, rather than just
# sending information. Tuned for how people actually write at work.
REQUEST_PATTERNS = [
    r"\bcan you\b", r"\bcould you\b", r"\bwould you\b", r"\bwill you\b",
    r"\bplease\b", r"\bpls\b",
    r"\bneed (?:you|your|this|that|a|an|the|to)\b", r"\bneeds? your\b",
    r"\bcan we\b", r"\blet me know\b", r"\bget back to me\b",
    r"\bfollow(?:ing)? up\b", r"\bany update\b", r"\bstatus on\b",
    r"\bwhen (?:can|will|do|are|is)\b", r"\bwhat(?:'s| is) the\b",
    r"\bsend me\b", r"\bshare\b", r"\bforward\b", r"\bsign(?: off)?\b",
    r"\bapprove\b", r"\bapproval\b", r"\breview\b", r"\bconfirm\b",
    r"\bthoughts\?", r"\bwaiting on\b", r"\bASAP\b", r"\bby (?:EOD|COB|Friday|Monday)\b",
    r"\bcall me\b", r"\bgive me a call\b", r"\bcheck on\b", r"\blook into\b",
]
REQUEST_RE = re.compile("|".join(REQUEST_PATTERNS), re.IGNORECASE)

# Automated senders that generate volume but never actually need a reply.
NOREPLY_RE = re.compile(
    r"(no[-_.]?reply|do[-_.]?not[-_.]?reply|donotreply|mailer|postmaster|"
    r"notification|automated|alerts?@|system|daemon)",
    re.IGNORECASE,
)

# Named robots at Flow Auto. pbidata blasts the daily Fixed Ops reports —
# it says "please see attached" every morning and never wants an answer.
DEFAULT_IGNORE = {"pbidata"}

# Distribution boilerplate that contains request words but asks nothing.
# Removed before deciding whether a message is a real ask.
BOILERPLATE_RE = re.compile(
    r"please (?:see|find|review) (?:the )?attach\w*|please do not reply|"
    r"please note|please see below|this electronic message transmission",
    re.IGNORECASE,
)


def find_mail_root():
    """Apple Mail's container: ~/Library/Mail/V10 (V9/V8 on older macOS)."""
    base = os.path.expanduser("~/Library/Mail")
    if not os.path.isdir(base):
        return None
    versions = sorted(glob.glob(os.path.join(base, "V*")), reverse=True)
    return versions[0] if versions else base


def read_emlx(path):
    """
    .emlx = byte-count line, then the RFC822 message, then an Apple plist trailer.
    Strip the count and let the plist fall away as trailing garbage.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except (OSError, PermissionError):
        return None
    nl = raw.find(b"\n")
    if nl == -1:
        return None
    first = raw[:nl].strip()
    body = raw[nl + 1:]
    if first.isdigit():
        body = body[: int(first)]
    try:
        return email.message_from_bytes(body)
    except Exception:
        return None


def decode(value):
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value))).strip()
    except Exception:
        return str(value).strip()


def plain_text(msg, limit=4000):
    """Best-effort plaintext, preferring text/plain over stripped HTML."""
    chunks = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and \
                    "attachment" not in str(part.get("Content-Disposition", "")):
                try:
                    chunks.append(part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", "replace"))
                except Exception:
                    pass
    else:
        try:
            chunks.append(msg.get_payload(decode=True).decode(
                msg.get_content_charset() or "utf-8", "replace"))
        except Exception:
            pass
    text = "\n".join(c for c in chunks if c)
    if not text:  # fall back to crudely de-tagged HTML
        try:
            raw = msg.get_payload(decode=True) or b""
            text = re.sub(r"<[^>]+>", " ", raw.decode("utf-8", "replace"))
        except Exception:
            text = ""
    return text[:limit]


def strip_quotes(text):
    """Drop quoted replies and signatures so we judge only what was newly written."""
    lines = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(">"):
            continue
        if re.match(r"^(On .+wrote:|-{2,}\s*Forwarded|From:\s|Sent from my|"
                    r"This electronic message transmission)", s, re.IGNORECASE):
            break
        lines.append(line)
    return "\n".join(lines)


def is_real_ask(subject, body):
    """True when something is asked once mass-mail boilerplate is discounted."""
    clean = BOILERPLATE_RE.sub(" ", strip_quotes(body))
    subj = BOILERPLATE_RE.sub(" ", subject)
    return bool(REQUEST_RE.search(clean) or REQUEST_RE.search(subj) or "?" in clean)


def first_ask(text):
    """
    The sentence that most looks like the actual request.
    Boilerplate is discounted when judging, but the sentence is shown intact —
    scoring on a stripped copy would print mangled half-sentences.
    """
    clean = strip_quotes(text)
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", clean):
        s = " ".join(sentence.split())
        if len(s) < 8 or len(s) > 300:
            continue
        judged = BOILERPLATE_RE.sub(" ", s)
        if REQUEST_RE.search(judged) or judged.rstrip().endswith("?"):
            return s
    for line in clean.splitlines():
        s = " ".join(line.split())
        if len(s) > 12:
            return s[:220]
    return "(no clear ask found — open the message)"


def scan(mail_root, domain, me, days, ignore=DEFAULT_IGNORE):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    me_local = me.split("@")[0].lower()

    candidates = {}   # message-id -> record
    replied_refs = set()   # message-ids Frank has answered

    paths = glob.glob(os.path.join(mail_root, "**", "*.emlx"), recursive=True)
    if not paths:
        return None, []

    for path in paths:
        if path.endswith(".partial.emlx"):
            continue
        msg = read_emlx(path)
        if msg is None:
            continue

        date_hdr = msg.get("Date")
        try:
            dt = email.utils.parsedate_to_datetime(date_hdr)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if dt < cutoff:
            continue

        sender = decode(msg.get("From", ""))
        sender_addr = email.utils.parseaddr(sender)[1].lower()
        msg_id = (msg.get("Message-ID") or "").strip()

        # Anything Frank sent marks the thread it answers as handled.
        if me_local and me_local in sender_addr:
            refs = (msg.get("References", "") + " " + msg.get("In-Reply-To", ""))
            for ref in re.findall(r"<[^>]+>", refs):
                replied_refs.add(ref.strip())
            continue

        if domain not in sender_addr:
            continue
        if NOREPLY_RE.search(sender_addr):
            continue
        if sender_addr.split("@")[0] in ignore:
            continue

        subject = decode(msg.get("Subject", "(no subject)"))
        body = plain_text(msg)
        if not is_real_ask(subject, body):
            continue

        key = msg_id or f"{sender_addr}|{subject}|{dt.isoformat()}"
        prior = candidates.get(key)
        if prior and prior["dt"] >= dt:
            continue
        candidates[key] = {
            "id": msg_id,
            "who": decode(msg.get("From", "")) or sender_addr,
            "addr": sender_addr,
            "subject": subject or "(no subject)",
            "ask": first_ask(body),
            "dt": dt,
        }

    open_items = [r for k, r in candidates.items()
                  if not (r["id"] and r["id"] in replied_refs)]
    open_items.sort(key=lambda r: r["dt"])
    return len(paths), open_items


def render_html(items, days, scanned):
    now = datetime.now().strftime("%b %d, %Y at %I:%M %p")
    overdue = sum(1 for r in items if (datetime.now(timezone.utc) - r["dt"]).days >= 2)
    rows = []
    for r in items:
        age = (datetime.now(timezone.utc) - r["dt"]).days
        cls = "od" if age >= 2 else ""
        rows.append(
            f"<tr class='{cls}'><td>{html.escape(r['who'])}</td>"
            f"<td><strong>{html.escape(r['subject'])}</strong><br>"
            f"<span class='ask'>{html.escape(r['ask'])}</span></td>"
            f"<td>{r['dt'].astimezone().strftime('%b %d')}</td>"
            f"<td>{age}d</td></tr>")
    body = "".join(rows) or (
        "<tr><td colspan='4' class='empty'>Nothing waiting on you. "
        "Inbox is clear of open Flow Auto requests.</td></tr>")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Work Follow-Ups — Flow Auto</title><style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,sans-serif;background:#1a1a2e;color:#ecf0f1;padding:20px}}
.container{{max-width:1100px;margin:0 auto}}
header{{background:linear-gradient(135deg,#0f3460,#16213e);padding:28px;border-radius:8px;margin-bottom:20px}}
h1{{font-size:2em;color:#4fc3f7;margin-bottom:8px}}
.sub{{color:#bdc3c7;font-size:.95em}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:18px;margin-bottom:20px}}
.card{{background:#16213e;border-radius:8px;padding:20px;border-left:4px solid #4fc3f7}}
.card h3{{color:#4fc3f7;font-size:.8em;text-transform:uppercase;margin-bottom:10px;letter-spacing:.04em}}
.v{{font-size:2em;font-weight:bold}}
.panel{{background:#16213e;border-radius:8px;padding:24px;border-left:4px solid #4fc3f7}}
table{{width:100%;border-collapse:collapse;font-size:.92em}}
th{{background:#0f3460;color:#4fc3f7;padding:12px 14px;text-align:left;text-transform:uppercase;
font-size:.78em;border-bottom:2px solid #4fc3f7}}
td{{padding:12px 14px;border-bottom:1px solid #2c3e50;vertical-align:top}}
tr.od td{{background:rgba(231,76,60,.08)}}
.ask{{color:#95a5a6;font-size:.9em}}
.empty{{text-align:center;color:#95a5a6;padding:28px;font-style:italic}}
footer{{text-align:center;padding:18px;color:#7f8c8d;font-size:.88em;
border-top:1px solid #2c3e50;margin-top:28px}}
@media(max-width:700px){{body{{padding:10px}}h1{{font-size:1.5em}}th,td{{padding:8px}}}}
</style></head><body><div class="container">
<header><h1>Work Follow-Ups — Flow Auto</h1>
<div class="sub">From Apple Mail on this Mac · last {days} days · {scanned:,} messages scanned</div></header>
<div class="cards">
<div class="card"><h3>Open Follow-Ups</h3><div class="v">{len(items)}</div></div>
<div class="card"><h3>Overdue (&gt;2 days)</h3><div class="v">{overdue}</div></div>
<div class="card"><h3>Last Scan</h3><div class="v" style="font-size:1.15em">{now}</div></div>
</div>
<div class="panel"><table><thead><tr><th>Who</th><th>What they asked</th>
<th>When</th><th>Age</th></tr></thead><tbody>{body}</tbody></table></div>
<footer>Generated locally from ~/Library/Mail · nothing left this machine</footer>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=60)
    ap.add_argument("--domain", default="flowauto.com")
    ap.add_argument("--me", default="FPARRO@flowauto.com")
    ap.add_argument("--out", default="followups_local.html")
    ap.add_argument("--ignore", default=",".join(sorted(DEFAULT_IGNORE)),
                    help="comma-separated mailbox names to treat as robots")
    args = ap.parse_args()
    ignore = {p.strip().lower() for p in args.ignore.split(",") if p.strip()}

    root = find_mail_root()
    if not root:
        sys.exit("No ~/Library/Mail found. Is this the Mac running Apple Mail?")

    print(f"Scanning {root} for the last {args.days} days...")
    scanned, items = scan(root, args.domain.lower(), args.me.lower(),
                          args.days, ignore)

    if scanned is None:
        sys.exit(
            "Found the Mail folder but could not read any messages.\n"
            "macOS is almost certainly blocking access. Grant Full Disk Access to\n"
            "your terminal (or the Claude app) in System Settings > Privacy &\n"
            "Security > Full Disk Access, then run this again.")

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(render_html(items, args.days, scanned))

    print(f"Scanned {scanned:,} messages. {len(items)} open request(s).\n")
    for r in items:
        age = (datetime.now(timezone.utc) - r["dt"]).days
        flag = "!" if age >= 2 else " "
        print(f" {flag} {age:>3}d  {r['addr']:<32} {r['subject'][:46]}")
        print(f"          {r['ask'][:96]}")
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
