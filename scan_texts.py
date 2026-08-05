#!/usr/bin/env python3
"""
Scan macOS Messages for unanswered work requests sent by text.

Messages keeps every SMS and iMessage in ~/Library/Messages/chat.db. This
reads that database directly — no network, no credentials, nothing leaves
the Mac. Same footing as scan_followups.py, which does the mail side.

Usage:
    python3 scan_texts.py                       # last 14 days, everyone
    python3 scan_texts.py --days 30
    python3 scan_texts.py --only-work           # just known work contacts
    python3 scan_texts.py --harvest             # learn work numbers from mail

Identifying work texts is the hard part: a phone number carries no domain.
Three sources are combined, best first:
  1. iMessage handles that are literally @flowauto.com addresses
  2. numbers harvested from @flowauto.com email signatures (--harvest)
  3. names from your Contacts, so you can eyeball the rest

Requires Full Disk Access for the terminal, same as the mail scanner.
"""

import argparse
import glob
import html
import os
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

# Reuse the request-detection work from the mail scanner rather than letting
# two copies of the patterns drift apart.
try:
    from scan_followups import REQUEST_RE, discount
except Exception:  # pragma: no cover - fallback if run standalone
    REQUEST_RE = re.compile(
        r"\bcan you\b|\bcould you\b|\bplease\b|\bneed\b|\bwhen (?:can|will)\b|"
        r"\blet me know\b|\bcall me\b|\bany update\b|\bcan we\b",
        re.IGNORECASE)
    def discount(text):
        return text

CHAT_DB = os.path.expanduser("~/Library/Messages/chat.db")

# Apple stores timestamps as an offset from 2001-01-01, in seconds on older
# systems and nanoseconds since roughly macOS 10.13.
APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)

PHONE_RE = re.compile(r"(?:\+?1[\s.-]?)?\(?(\d{3})\)?[\s.-]?(\d{3})[\s.-]?(\d{4})")


def norm_number(value):
    """Reduce a phone number to its last ten digits for comparison."""
    digits = re.sub(r"\D", "", value or "")
    return digits[-10:] if len(digits) >= 10 else None


def apple_time(raw):
    if raw is None:
        return None
    seconds = raw / 1_000_000_000 if raw > 10_000_000_000 else raw
    try:
        return APPLE_EPOCH + timedelta(seconds=seconds)
    except (OverflowError, ValueError):
        return None


def decode_attributed_body(blob):
    """
    Recent macOS often leaves message.text NULL and stores the body in
    attributedBody, an NSAttributedString typedstream. There's no public
    parser, so pull the longest run of readable text out of the archive.
    Best-effort by nature: if it fails the message is simply skipped.
    """
    if not blob:
        return None
    try:
        raw = blob.decode("utf-8", errors="ignore")
    except Exception:
        return None
    marker = raw.find("NSString")
    if marker != -1:
        raw = raw[marker + 8:]
    runs = re.findall(r"[ -~ -￿]{4,}", raw)
    if not runs:
        return None
    best = max(runs, key=len)
    best = re.sub(r"^[\x00-\x1f+\x84\x81\x92\x86]*", "", best).strip()
    for junk in ("NSDictionary", "NSNumber", "NSValue", "__kIM", "NSAttribute"):
        if junk in best:
            best = best.split(junk)[0].strip()
    return best or None


def load_contacts():
    """Map phone digits -> person name using the local Contacts database."""
    names = {}
    roots = glob.glob(os.path.expanduser(
        "~/Library/Application Support/AddressBook/AddressBook-v22.abcddb"))
    roots += glob.glob(os.path.expanduser(
        "~/Library/Application Support/AddressBook/Sources/*/AddressBook-v22.abcddb"))
    for path in roots:
        try:
            con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            rows = con.execute(
                "SELECT r.ZFIRSTNAME, r.ZLASTNAME, p.ZFULLNUMBER "
                "FROM ZABCDPHONENUMBER p "
                "JOIN ZABCDRECORD r ON p.ZOWNER = r.Z_PK").fetchall()
            con.close()
        except Exception:
            continue
        for first, last, number in rows:
            key = norm_number(number)
            if not key:
                continue
            full = " ".join(p for p in (first, last) if p).strip()
            if full:
                names.setdefault(key, full)
    return names


def harvest_work_numbers(domain, days=365):
    """
    Learn work phone numbers from email signatures.

    Colleagues sign mail with their cell number, so their @domain messages are
    a reliable source for mapping numbers to work people — which is what lets
    a bare phone number in Messages be recognised as work.
    """
    try:
        from scan_followups import find_mail_root, read_emlx, plain_text, decode
    except Exception:
        return {}
    root = find_mail_root()
    if not root:
        return {}
    import email.utils
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    found = {}
    for path in glob.glob(os.path.join(root, "**", "*.emlx"), recursive=True):
        if path.endswith(".partial.emlx"):
            continue
        msg = read_emlx(path)
        if msg is None:
            continue
        sender = email.utils.parseaddr(decode(msg.get("From", "")))[1].lower()
        if domain not in sender:
            continue
        try:
            dt = email.utils.parsedate_to_datetime(msg.get("Date"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt < cutoff:
                continue
        except Exception:
            pass
        body = plain_text(msg, limit=6000)
        # Signatures live at the end; scan the tail to avoid quoted noise.
        for match in PHONE_RE.finditer(body[-2500:]):
            key = norm_number("".join(match.groups()))
            if key:
                found.setdefault(key, sender)
    return found


def open_db(path):
    if not os.path.exists(path):
        sys.exit(f"No Messages database at {path}.\n"
                 "Is Messages set up on this Mac?")
    try:
        return sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.OperationalError as exc:
        sys.exit(f"Could not open {path}: {exc}")


def scan(days, work_numbers, contacts, domain, only_work):
    con = open_db(CHAT_DB)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        rows = con.execute("""
            SELECT m.ROWID, m.text, m.attributedBody, m.date, m.is_from_me,
                   h.id, m.cache_roomnames
            FROM message m
            LEFT JOIN handle h ON m.handle_id = h.ROWID
            ORDER BY m.date ASC
        """).fetchall()
    except sqlite3.OperationalError as exc:
        con.close()
        sys.exit(f"Unexpected Messages schema: {exc}\n"
                 "This macOS version may store messages differently.")
    con.close()

    # Walk chronologically per person: an inbound ask is open until they get a
    # reply, so any later outbound message to the same handle clears it.
    #
    # Keep the OLDEST unanswered ask, not the newest. Someone who asked three
    # days ago and nudged again yesterday has been waiting three days, and
    # overwriting would report it as one.
    results = {}
    for _rid, text, blob, raw_date, is_me, handle, room in rows:
        when = apple_time(raw_date)
        if when is None:
            continue
        body = (text or "").strip() or (decode_attributed_body(blob) or "").strip()
        if not body:
            continue
        who = handle or room or "(unknown)"

        if is_me:
            results.pop(who, None)          # you answered — clear the thread
            continue
        if when < cutoff:
            continue
        judged = discount(body)
        if not (REQUEST_RE.search(judged) or judged.rstrip().endswith("?")):
            continue
        if who in results:
            results[who]["count"] += 1      # a nudge on top of the original
            results[who]["latest"] = body
        else:
            results[who] = {"who": who, "body": body, "dt": when,
                            "count": 1, "latest": body}

    items = []
    for who, rec in results.items():
        key = norm_number(who)
        if domain and "@" in who and domain in who.lower():
            source, is_work = who, True
        elif key and key in work_numbers:
            source, is_work = work_numbers[key], True
        else:
            source, is_work = None, False
        rec["name"] = contacts.get(key) if key else None
        rec["work_email"] = source
        rec["is_work"] = is_work
        if only_work and not is_work:
            continue
        items.append(rec)

    items.sort(key=lambda r: (not r["is_work"], r["dt"]))
    return items


def render_html(items, days):
    now = datetime.now().strftime("%b %d, %Y at %I:%M %p")
    rows = []
    for r in items:
        age = (datetime.now(timezone.utc) - r["dt"]).days
        label = r["name"] or r["who"]
        tag = (f"<span class='tag work'>{html.escape(r['work_email'])}</span>"
               if r["is_work"] else "<span class='tag'>unconfirmed</span>")
        more = (f"<br><span class='sub'>+{r['count'] - 1} later message(s), "
                f"most recent: {html.escape(r['latest'][:120])}</span>"
                if r["count"] > 1 else "")
        rows.append(
            f"<tr class=\"{'od' if age >= 2 else ''}\">"
            f"<td>{html.escape(str(label))}<br>"
            f"<span class='sub'>{html.escape(str(r['who']))}</span></td>"
            f"<td>{html.escape(r['body'][:400])} {tag}{more}</td>"
            f"<td>{r['dt'].astimezone().strftime('%b %d')}</td>"
            f"<td>{age}d</td></tr>")
    body = "".join(rows) or ("<tr><td colspan='4' class='empty'>"
                             "No unanswered requests by text.</td></tr>")
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Text Follow-Ups</title><style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',Tahoma,sans-serif;background:#1a1a2e;color:#ecf0f1;padding:20px}}
.container{{max-width:1100px;margin:0 auto}}
header{{background:linear-gradient(135deg,#0f3460,#16213e);padding:26px;border-radius:8px;margin-bottom:18px}}
h1{{font-size:1.9em;color:#4fc3f7;margin-bottom:6px}}
.sub{{color:#7f8c8d;font-size:.85em}}
.panel{{background:#16213e;border-radius:8px;padding:22px;border-left:4px solid #4fc3f7}}
table{{width:100%;border-collapse:collapse;font-size:.92em}}
th{{background:#0f3460;color:#4fc3f7;padding:12px;text-align:left;text-transform:uppercase;
font-size:.78em;border-bottom:2px solid #4fc3f7}}
td{{padding:12px;border-bottom:1px solid #2c3e50;vertical-align:top}}
tr.od td{{background:rgba(231,76,60,.08)}}
.tag{{display:inline-block;margin-left:8px;padding:2px 8px;border-radius:10px;
background:#3a2f10;color:#ffcf6b;font-size:.72em;font-weight:600}}
.tag.work{{background:#0b4f30;color:#7bf0b6}}
.empty{{text-align:center;color:#95a5a6;padding:26px;font-style:italic}}
footer{{text-align:center;padding:18px;color:#7f8c8d;font-size:.88em;
border-top:1px solid #2c3e50;margin-top:26px}}
</style></head><body><div class="container">
<header><h1>Text Follow-Ups</h1>
<div class="sub">From Messages on this Mac · last {days} days · {len(items)} open</div></header>
<div class="panel"><table><thead><tr><th>Who</th><th>What they asked</th>
<th>When</th><th>Age</th></tr></thead><tbody>{body}</tbody></table></div>
<footer>Read locally from ~/Library/Messages · nothing left this machine</footer>
</div></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--domain", default="flowauto.com")
    ap.add_argument("--only-work", action="store_true",
                    help="show only texts tied to a known work contact")
    ap.add_argument("--harvest", action="store_true",
                    help="learn work numbers from email signatures (slow, cached)")
    ap.add_argument("--numbers", default="work_numbers.txt",
                    help="cache file of known work phone numbers")
    ap.add_argument("--out", default="texts_local.html")
    args = ap.parse_args()

    work = {}
    if os.path.exists(args.numbers):
        with open(args.numbers, encoding="utf-8") as fh:
            for line in fh:
                if line.strip() and not line.startswith("#"):
                    num, _, who = line.strip().partition(",")
                    key = norm_number(num)
                    if key:
                        work[key] = who or "known work contact"
    if args.harvest:
        print("Harvesting work numbers from email signatures (this takes a minute)...")
        work.update(harvest_work_numbers(args.domain.lower()))
        with open(args.numbers, "w", encoding="utf-8") as fh:
            fh.write("# number,source — learned from @%s signatures\n" % args.domain)
            for key, who in sorted(work.items()):
                fh.write(f"{key},{who}\n")
        print(f"Learned {len(work)} work number(s) -> {args.numbers}")

    contacts = load_contacts()
    items = scan(args.days, work, contacts, args.domain.lower(), args.only_work)

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(render_html(items, args.days))

    known = [r for r in items if r["is_work"]]
    unknown = [r for r in items if not r["is_work"]]
    print(f"{len(items)} unanswered request(s) by text "
          f"({len(contacts)} contacts, {len(work)} known work numbers)\n")

    def show(rows):
        for r in rows:
            age = (datetime.now(timezone.utc) - r["dt"]).days
            flag = "!" if age >= 2 else " "
            label = r["name"] or r["who"]
            more = f"  (+{r['count'] - 1} more)" if r["count"] > 1 else ""
            print(f" {flag} {age:>3}d  {str(label)[:28]:<28} {r['body'][:70]}{more}")

    if known:
        print(f"--- Known work contacts ({len(known)}) ---")
        show(known)
    if unknown and not args.only_work:
        print(f"\n--- Unconfirmed sender ({len(unknown)}) ---")
        show(unknown)
    if not work:
        print("\nNo work numbers known yet — run once with --harvest to learn them "
              "from email signatures, or list them in work_numbers.txt.")
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
