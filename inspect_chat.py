#!/usr/bin/env python3
"""
Dump a few Google Chat notification emails so their format can be read.

Chat notifications arrive from chat-noreply@google.com and wrap the real
message in Google's own layout. Before the scanner can pull "who asked what"
out of them, the actual shape has to be seen rather than guessed at.

Usage:
    python3 inspect_chat.py                 # 3 most recent Chat notifications
    python3 inspect_chat.py --count 5
    python3 inspect_chat.py --match pbidata # inspect any other sender

Prints headers and the opening lines of the body. Local only, reads the same
Apple Mail store as scan_followups.py, writes nothing.
"""

import argparse
import email.utils
import glob
import os
import re
import sys
from datetime import datetime, timezone

from scan_followups import find_mail_root, read_emlx, plain_text, decode, unwrap

INTERESTING_HEADERS = [
    "From", "Reply-To", "To", "Subject", "Date",
    "X-Google-Chat-Space", "List-Id", "Auto-Submitted", "Precedence",
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--match", default="chat-noreply",
                    help="substring to look for in the From header")
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--lines", type=int, default=12,
                    help="body lines to show per message")
    args = ap.parse_args()

    root = find_mail_root()
    if not root:
        sys.exit("No ~/Library/Mail found.")

    print(f"Looking for senders matching '{args.match}' in {root}\n")

    hits = []
    for path in glob.glob(os.path.join(root, "**", "*.emlx"), recursive=True):
        if path.endswith(".partial.emlx"):
            continue
        msg = read_emlx(path)
        if msg is None:
            continue
        if args.match.lower() not in decode(msg.get("From", "")).lower():
            continue
        try:
            dt = email.utils.parsedate_to_datetime(msg.get("Date"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except Exception:
            dt = datetime.now(timezone.utc)
        hits.append((dt, msg))

    if not hits:
        sys.exit(f"No messages from a sender matching '{args.match}'.\n"
                 "If Chat notifications go to an account Apple Mail isn't "
                 "downloading, they won't be on this disk.")

    hits.sort(key=lambda pair: pair[0], reverse=True)
    print(f"Found {len(hits)} matching message(s). Showing {min(args.count, len(hits))}:\n")

    for index, (dt, msg) in enumerate(hits[:args.count], start=1):
        print("=" * 72)
        print(f"MESSAGE {index}  ({dt.astimezone().strftime('%b %d %Y %I:%M %p')})")
        print("=" * 72)
        for header in INTERESTING_HEADERS:
            value = msg.get(header)
            if value:
                print(f"{header}: {decode(value)}")
        body = unwrap(plain_text(msg, limit=4000))
        shown = [ln for ln in body.splitlines() if ln.strip()][:args.lines]
        print("--- body ---")
        for line in shown:
            print(f"  {line[:110]}")
        print()

    print("Paste this back so the notification format can be parsed correctly.")
    print("Names and message text are what matter — redact anything sensitive.")


if __name__ == "__main__":
    main()
