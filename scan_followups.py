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
    # "I need access to the PASE dashboard" is the ask; the polite question
    # that follows it is not. Catch the statement so it wins.
    r"\b(?:I|we) (?:need|will need|would like|want|am asking)\b",
    r"\b(?:I|we)'?d like\b", r"\bneed access\b", r"\brequesting\b",
    r"\bcan we\b", r"\blet me know\b", r"\bget back to me\b",
    r"\bfollow(?:ing)? up\b", r"\bany update\b", r"\bstatus on\b",
    r"\bwhen (?:can|will|do|are|is)\b", r"\bwhat(?:'s| is) the\b",
    r"\bsend me\b", r"\bshare\b", r"\bsign(?: off)?\b",
    # Only a request to forward something. A bare \bforward\b also matches
    # "look forward to" and "move forward", which are idioms, not asks.
    r"\b(?:can|could|would) you (?:please )?forward\b",
    r"\bplease forward\b", r"\bneed you to forward\b",
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

# Closing courtesies. These end almost every work email and are the single
# biggest source of false hits — "please let me know if you have any
# questions" is a goodbye, not a request.
SIGNOFF_RE = re.compile(
    r"(?:please )?(?:let me know|reach out|feel free|don'?t hesitate|"
    r"give me a (?:call|shout))\b[^.?!]*"
    r"(?:if you (?:have|need)|with any|any questions?|any concerns?|"
    r"anything else|if there(?:'s| is) anything)[^.?!]*|"
    r"thanks? (?:in advance|so much|again)|"
    r"(?:any|if you have) (?:questions?|concerns?)[,.]? (?:please )?"
    r"(?:let me know|call|contact|reach)[^.?!]*|"
    r"happy to (?:help|discuss)|hope (?:this|that) helps",
    re.IGNORECASE,
)

# Vacation responders and other machine-generated replies.
AUTOREPLY_SUBJ_RE = re.compile(
    r"^\s*(?:re:\s*)?(?:out of (?:the )?office|automatic reply|auto[-\s]?reply|"
    r"autoreply|away from (?:my|the) (?:desk|office)|vacation reply|"
    r"undeliverable|delivery status notification|read:)",
    re.IGNORECASE,
)


def is_autoreply(msg, subject):
    """Vacation responders announce themselves in headers or the subject."""
    if AUTOREPLY_SUBJ_RE.search(subject or ""):
        return True
    if (msg.get("Auto-Submitted") or "").lower().startswith("auto"):
        return True
    for header in ("X-Autoreply", "X-Autorespond", "X-Auto-Response-Suppress"):
        if msg.get(header):
            return True
    if (msg.get("Precedence") or "").lower() in {"bulk", "auto_reply", "junk"}:
        return True
    return False


def unwrap(text):
    """
    Rejoin hard-wrapped lines before splitting into sentences.

    Mail clients wrap bodies near 72 columns, so a single sentence often spans
    several lines. Splitting on newlines then yields fragments like
    "fee of $22.94 on the wrong belt molding we returned?" — a real question
    with its opening clause chopped off. Join a line to the next when it
    doesn't end at a sentence boundary.
    """
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if out and stripped and not re.search(r"[.!?:;]$", out[-1]) \
                and not re.match(r"^\s*[-*•>\d]", line):
            out[-1] = out[-1] + " " + stripped
        else:
            out.append(stripped)
    return "\n".join(out)


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
    for line in unwrap(text).splitlines():
        s = line.strip()
        if s.startswith(">"):
            continue
        if re.match(r"^(On .+wrote:|-{2,}\s*Forwarded|From:\s|Sent from my|"
                    r"This electronic message transmission)", s, re.IGNORECASE):
            break
        lines.append(line)
    return "\n".join(lines)


def discount(text):
    """Blank out phrases that look like requests but aren't."""
    return SIGNOFF_RE.sub(" ", BOILERPLATE_RE.sub(" ", text))


def addressed_to_other(sentence, me_names):
    """
    "Joe- you got this?" is a real question aimed at someone else.
    A leading name followed by a dash, comma or colon is the giveaway.
    """
    m = re.match(r"^\s*([A-Z][a-z]{1,14})\s*[-–,:]\s+\S", sentence)
    if not m:
        return None
    name = m.group(1).lower()
    if name in me_names or name in {"hi", "hey", "all", "team", "thanks"}:
        return None
    return m.group(1)


def ask_sentences(text):
    """Every sentence in the newly-written portion that reads as a request."""
    clean = strip_quotes(text)
    found = []
    for sentence in re.split(r"(?<=[.!?])\s+|\n+", clean):
        s = " ".join(sentence.split())
        if len(s) < 8 or len(s) > 300:
            continue
        judged = discount(s)
        if len(judged.strip()) < 8:
            continue
        if REQUEST_RE.search(judged) or judged.rstrip().endswith("?"):
            found.append(s)
    return found


def pick_ask(text, me_names):
    """
    The request to show, preferring one aimed at Frank over one aimed at a
    colleague. Returns (sentence, other_name) — other_name set when every
    candidate is addressed to somebody else.
    """
    found = ask_sentences(text)
    if not found:
        return None, None
    deflected = []
    for s in found:
        other = addressed_to_other(s, me_names)
        if other:
            deflected.append((s, other))
        else:
            return s, None
    return deflected[0][0], deflected[0][1]


def scan(mail_root, domain, me, days, ignore=DEFAULT_IGNORE):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    me_local = me.split("@")[0].lower()
    # First names you might be addressed by, so "Frank- can you..." isn't read
    # as a request aimed at somebody else.
    me_names = {me_local, "frank", "francis", "parro"}

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
        if is_autoreply(msg, subject):
            continue

        body = plain_text(msg)
        ask, other = pick_ask(body, me_names)
        if not ask:
            continue

        # Addressed straight to you, or merely copied on someone else's thread.
        to_field = (msg.get("To") or "").lower()
        direct = me_local in to_field

        key = msg_id or f"{sender_addr}|{subject}|{dt.isoformat()}"
        prior = candidates.get(key)
        if prior and prior["dt"] >= dt:
            continue
        candidates[key] = {
            "id": msg_id,
            "who": decode(msg.get("From", "")) or sender_addr,
            "addr": sender_addr,
            "subject": subject or "(no subject)",
            "ask": ask,
            "for_other": other,
            "direct": direct,
            "dt": dt,
        }

    open_items = [r for k, r in candidates.items()
                  if not (r["id"] and r["id"] in replied_refs)]
    # Addressed to you first, then asks aimed at a colleague, oldest within each.
    open_items.sort(key=lambda r: (not r["direct"], bool(r["for_other"]), r["dt"]))
    return len(paths), open_items


def render_html(items, days, scanned):
    now = datetime.now().strftime("%b %d, %Y at %I:%M %p")
    overdue = sum(1 for r in items if (datetime.now(timezone.utc) - r["dt"]).days >= 2)
    rows = []
    for r in items:
        age = (datetime.now(timezone.utc) - r["dt"]).days
        cls = "od" if age >= 2 else ""
        if r["for_other"]:
            tag = f" <span class='tag'>likely for {html.escape(r['for_other'])}</span>"
        elif not r["direct"]:
            tag = " <span class='tag'>you're only cc'd</span>"
        else:
            tag = ""
        rows.append(
            f"<tr class='{cls}'><td>{html.escape(r['who'])}</td>"
            f"<td><strong>{html.escape(r['subject'])}</strong>{tag}<br>"
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
.tag{{display:inline-block;margin-left:8px;padding:2px 8px;border-radius:10px;
background:#3a2f10;color:#ffcf6b;font-size:.72em;font-weight:600;vertical-align:middle}}
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
    direct = [r for r in items if r["direct"] and not r["for_other"]]
    other = [r for r in items if not (r["direct"] and not r["for_other"])]

    def show(rows):
        for r in rows:
            age = (datetime.now(timezone.utc) - r["dt"]).days
            flag = "!" if age >= 2 else " "
            tag = f" [for {r['for_other']}?]" if r["for_other"] else \
                  ("" if r["direct"] else " [cc]")
            print(f" {flag} {age:>3}d  {r['addr']:<30} {r['subject'][:44]}{tag}")
            print(f"          {r['ask'][:100]}")

    print(f"--- Addressed to you ({len(direct)}) ---")
    show(direct)
    if other:
        print(f"\n--- Copied in / aimed at someone else ({len(other)}) ---")
        show(other)
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
