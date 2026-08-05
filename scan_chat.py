#!/usr/bin/env python3
"""
Scan Google Chat notification emails for unanswered work requests.

Chat itself can't be read directly, but with "email notifications for unread
direct messages or @mentions" switched on, Google mails a digest of what was
missed. Those land in the work mailbox, Apple Mail downloads them, and this
reads them off the local disk like the other scanners.

Usage:
    python3 scan_chat.py                    # last 14 days
    python3 scan_chat.py --days 30
    python3 scan_chat.py --me-name "Frank Parro"

Format notes, taken from real notifications rather than assumed:

  Subject: Steven Young <syoung@flowauto.com> messaged you on Google Chat
           while you were away

  body:    <that same line>
           Steven Young          <- speaker name, rendered twice
           Steven Young
           the message text
           Frank Parro           <- your reply, if the digest caught one
           Frank Parro
           ...

The sender's real name and work address are in the subject, so the ordinary
flowauto.com domain filter applies without any guesswork about identity.
"""

import argparse
import email.utils
import glob
import html
import os
import re
import sys
from datetime import datetime, timedelta, timezone

from scan_followups import (find_mail_root, read_emlx, plain_text, decode,
                            REQUEST_RE, discount)

CHAT_SENDER = "chat-noreply@google.com"

# "Steven Young <syoung@flowauto.com> messaged you on Google Chat while..."
SUBJECT_RE = re.compile(
    r"^\s*(?P<name>.+?)\s*<(?P<addr>[^<>@\s]+@[^<>\s]+)>\s*"
    r"(?:messaged|mentioned|sent)", re.IGNORECASE)

# Fallback: From reads "Steven Young (via Google Chat)" <chat-noreply@...>
FROM_NAME_RE = re.compile(r"^\s*(?P<name>.+?)\s*\((?:via )?Google Chat\)\s*$",
                          re.IGNORECASE)


def parse_sender(msg, subject):
    """Recover the colleague's name and work address from a notification."""
    match = SUBJECT_RE.match(subject or "")
    if match:
        return match.group("name").strip(), match.group("addr").strip().lower()
    display = email.utils.parseaddr(decode(msg.get("From", "")))[0]
    fallback = FROM_NAME_RE.match(display or "")
    if fallback:
        return fallback.group("name").strip(), None
    return (display or "(unknown)").strip(), None


def speaker_blocks(body, participants):
    """
    Split the digest into (speaker, lines) blocks.

    Google renders each speaker's name twice — once as avatar alt text, once as
    the label — so a line matching a known participant is a speaker marker, and
    a repeat of the current speaker is just that duplication. Keying off the two
    names we already know beats guessing which lines look name-shaped.
    """
    blocks = []
    current = None
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line in participants:
            if current is None or current[0] != line:
                current = (line, [])
                blocks.append(current)
            continue
        if current is not None:
            current[1].append(line)
    # Digests are truncated, so the final speaker often has no text at all.
    return [(who, lines) for who, lines in blocks if lines]


def find_open_ask(blocks, sender_name, me_name):
    """
    The oldest request from them with no reply from you after it.

    Returns (text, answered_in_digest). Working forwards, any block of yours
    clears whatever came before, which is the same rule the Messages scanner
    uses for texts.
    """
    pending = None
    for who, lines in blocks:
        if who == me_name:
            pending = None                     # you replied — cleared
            continue
        if who != sender_name:
            continue
        if pending is not None:
            continue                           # keep the oldest unanswered
        # Join the block before testing: a long chat message arrives wrapped
        # across several lines, and checking each line alone would split a
        # request in half. Report the matching sentence, not the whole block.
        text = " ".join(lines)
        for sentence in re.split(r"(?<=[.!?])\s+", text):
            sentence = " ".join(sentence.split())
            if len(sentence) < 4:
                continue
            judged = discount(sentence)
            if REQUEST_RE.search(judged) or judged.rstrip().endswith("?"):
                pending = sentence
                break
    return pending


def scan(days, domain, me_name):
    root = find_mail_root()
    if not root:
        sys.exit("No ~/Library/Mail found. Is this the Mac running Apple Mail?")

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    results = {}
    seen = 0

    for path in glob.glob(os.path.join(root, "**", "*.emlx"), recursive=True):
        if path.endswith(".partial.emlx"):
            continue
        msg = read_emlx(path)
        if msg is None:
            continue
        from_addr = email.utils.parseaddr(decode(msg.get("From", "")))[1].lower()
        if CHAT_SENDER not in from_addr:
            continue
        seen += 1

        try:
            dt = email.utils.parsedate_to_datetime(msg.get("Date"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue
        if dt < cutoff:
            continue

        subject = decode(msg.get("Subject", ""))
        name, addr = parse_sender(msg, subject)
        if addr and domain not in addr:
            continue                            # chat from outside the company

        # Deliberately not unwrapped: unwrap() joins lines that don't end in
        # punctuation, which would fuse the speaker-name lines into the prose
        # and destroy the structure this parser depends on.
        body = plain_text(msg, limit=8000)
        blocks = speaker_blocks(body, {name, me_name})
        ask = find_open_ask(blocks, name, me_name)
        if not ask:
            continue

        key = addr or name
        prior = results.get(key)
        if prior and prior["dt"] <= dt:
            prior["count"] += 1                 # a later digest from the same person
            continue
        results[key] = {"name": name, "addr": addr or "(no address)",
                        "ask": ask, "dt": dt, "count": 1}

    items = sorted(results.values(), key=lambda r: r["dt"])
    return seen, items


def render_html(items, days, seen):
    now = datetime.now().strftime("%b %d, %Y at %I:%M %p")
    rows = []
    for r in items:
        age = (datetime.now(timezone.utc) - r["dt"]).days
        more = (f"<br><span class='sub'>+{r['count'] - 1} later digest(s)</span>"
                if r["count"] > 1 else "")
        rows.append(
            f"<tr class=\"{'od' if age >= 2 else ''}\">"
            f"<td>{html.escape(r['name'])}<br>"
            f"<span class='sub'>{html.escape(r['addr'])}</span></td>"
            f"<td>{html.escape(r['ask'][:400])}{more}</td>"
            f"<td>{r['dt'].astimezone().strftime('%b %d')}</td>"
            f"<td>{age}d</td></tr>")
    body = "".join(rows) or ("<tr><td colspan='4' class='empty'>"
                             "No unanswered requests in Chat notifications.</td></tr>")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Chat Follow-Ups</title><style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,sans-serif;background:#1a1a2e;color:#ecf0f1;padding:20px}}
.container{{max-width:1100px;margin:0 auto}}
header{{background:linear-gradient(135deg,#0f3460,#16213e);padding:26px;border-radius:8px;margin-bottom:18px}}
h1{{font-size:1.9em;color:#4fc3f7;margin-bottom:6px}}
.sub{{color:#7f8c8d;font-size:.85em}}
.note{{background:#3a2f10;color:#ffcf6b;padding:14px 18px;border-radius:8px;
margin-bottom:18px;font-size:.9em;line-height:1.5}}
.panel{{background:#16213e;border-radius:8px;padding:22px;border-left:4px solid #4fc3f7}}
table{{width:100%;border-collapse:collapse;font-size:.92em}}
th{{background:#0f3460;color:#4fc3f7;padding:12px;text-align:left;text-transform:uppercase;
font-size:.78em;border-bottom:2px solid #4fc3f7}}
td{{padding:12px;border-bottom:1px solid #2c3e50;vertical-align:top}}
tr.od td{{background:rgba(231,76,60,.08)}}
.empty{{text-align:center;color:#95a5a6;padding:26px;font-style:italic}}
footer{{text-align:center;padding:18px;color:#7f8c8d;font-size:.88em;
border-top:1px solid #2c3e50;margin-top:26px}}
</style></head><body><div class="container">
<header><h1>Chat Follow-Ups</h1>
<div class="sub">From Google Chat notification emails · last {days} days ·
{seen} notification(s) in the store</div></header>
<div class="note"><strong>Read these as leads, not gospel.</strong> Google only
sends a digest when you were away, and it shows a truncated window of the
conversation. If you answered in Chat afterwards, the digest can't know — so an
item here may already be handled.</div>
<div class="panel"><table><thead><tr><th>Who</th><th>What they asked</th>
<th>When</th><th>Age</th></tr></thead><tbody>{body}</tbody></table></div>
<footer>Read locally from ~/Library/Mail · nothing left this machine</footer>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--domain", default="flowauto.com")
    ap.add_argument("--me-name", default="Frank Parro",
                    help="your display name as Google Chat renders it")
    ap.add_argument("--out", default="chat_local.html")
    args = ap.parse_args()

    seen, items = scan(args.days, args.domain.lower(), args.me_name)

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(render_html(items, args.days, seen))

    print(f"{seen} Chat notification(s) in the store; "
          f"{len(items)} unanswered request(s) in the last {args.days} days.\n")
    for r in items:
        age = (datetime.now(timezone.utc) - r["dt"]).days
        flag = "!" if age >= 2 else " "
        more = f"  (+{r['count'] - 1} later)" if r["count"] > 1 else ""
        print(f" {flag} {age:>3}d  {r['name'][:24]:<24} {r['ask'][:66]}{more}")
    if items:
        print("\nThese are digests of moments you were away — if you replied in "
              "Chat afterwards, it can't tell. Treat them as leads.")
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
