#!/usr/bin/env python3
"""
imap_bridge.py — Local HTTP-to-IMAP bridge for SimpleAuthFlow

Exposes a simple HTTP API that the Chrome extension calls to retrieve
verification codes from an IMAP mailbox, avoiding the 5-per-day limit
of Burner Mailbox.

Usage:
    python3 imap_bridge.py \
        --host imap.example.com \
        --port 993 \
        --user your@email.com \
        --password yourpassword \
        [--ssl]            # use SSL (default: true for port 993)
        [--no-ssl]         # disable SSL (e.g. for port 143)
        [--listen-port 9090]   # HTTP server port (default: 9090)

API:
    GET /health
        Returns {"ok": true}

    GET /latest-code?email=user@example.com&since=1712345678000
        Searches the IMAP inbox for an email addressed TO `email`
        that arrived after `since` (Unix milliseconds) containing a
        6-digit verification code.

        Response 200: {"code": "123456", "subject": "...", "from": "..."}
        Response 404: {"error": "not_found"}
        Response 500: {"error": "...message..."}
"""

import argparse
import email as email_lib
import email.header
import imaplib
import json
import re
import ssl
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

# ─── Global IMAP config (set after arg parsing) ───────────────────────────────
IMAP_HOST = ''
IMAP_PORT = 993
IMAP_USER = ''
IMAP_PASS = ''
IMAP_USE_SSL = True
LISTEN_PORT = 9090

# ─── Connection pool (single persistent connection, reconnected on error) ─────
_imap_client = None


def get_imap_client():
    """Return a live IMAP client, reconnecting if needed."""
    global _imap_client
    try:
        if _imap_client is not None:
            # Send a NOOP to check if connection is still alive
            _imap_client.noop()
            return _imap_client
    except Exception:
        _imap_client = None

    _imap_client = connect_imap()
    return _imap_client

# ─── Helpers ──────────────────────────────────────────────────────────────────

def decode_header_value(value):
    """Decode RFC 2047 encoded header values."""
    if not value:
        return ''
    parts = email.header.decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or 'utf-8', errors='replace'))
        else:
            decoded.append(part)
    return ''.join(decoded)


def extract_code_from_text(text):
    """Extract a 6-digit verification code from email body text."""
    if not text:
        return None
    # Pattern 1: "code is 123456" or "code: 123456"
    m = re.search(r'code[:\s]+is[:\s]+(\d{6})', text, re.IGNORECASE)
    if m:
        return m.group(1)
    # Pattern 2: "代码为 123456" or "验证码 123456"
    m = re.search(r'(?:代码为|验证码[^0-9]*?)[\s：:]*(\d{6})', text)
    if m:
        return m.group(1)
    # Pattern 3: standalone 6-digit number (fallback)
    m = re.search(r'\b(\d{6})\b', text)
    if m:
        return m.group(1)
    return None


def get_email_body(msg):
    """Extract plain-text body from an email.Message object."""
    body = ''
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                payload = part.get_payload(decode=True)
                if not isinstance(payload, bytes):
                    # get_payload may return str for non-encoded parts
                    body += str(payload or '')
                    continue
                charset = part.get_content_charset() or 'utf-8'
                try:
                    body += payload.decode(charset, errors='replace')
                except Exception:
                    pass
    else:
        payload = msg.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = msg.get_content_charset() or 'utf-8'
            try:
                body = payload.decode(charset, errors='replace')
            except Exception:
                body = payload.decode('latin-1', errors='replace')
        else:
            body = str(msg.get_payload() or '')
    return body


def connect_imap(timeout=15):
    """Open an authenticated IMAP connection and return the client."""
    import socket as _socket
    _socket.setdefaulttimeout(timeout)
    try:
        if IMAP_USE_SSL:
            ctx = ssl.create_default_context()
            client = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ctx)
        else:
            client = imaplib.IMAP4(IMAP_HOST, IMAP_PORT)
        client.login(IMAP_USER, IMAP_PASS)
    finally:
        _socket.setdefaulttimeout(None)
    return client


def find_latest_code(target_email, since_ms):
    """
    Connect to IMAP, search INBOX for emails addressed to `target_email`
    received after `since_ms` (Unix milliseconds), and return the first
    6-digit verification code found.

    Returns a dict with keys: code, subject, from_addr
    Raises RuntimeError if no matching code is found.
    """
    global _imap_client
    try:
        client = get_imap_client()
        client.select('INBOX', readonly=True)

        # Convert since_ms to IMAP date format (IMAP SINCE is day-granular, not ms)
        since_dt = datetime.fromtimestamp(since_ms / 1000, tz=timezone.utc) if since_ms else None
        since_str = since_dt.strftime('%d-%b-%Y') if since_dt else None

        # Build search criteria
        criteria = 'ALL'
        if since_str:
            criteria = f'SINCE {since_str}'

        status, data = client.search(None, criteria)
        if status != 'OK' or not data or not data[0]:
            raise RuntimeError('No emails found in INBOX')

        mail_ids = data[0].split()
        mail_ids = list(reversed(mail_ids))   # process newest first
        mail_ids = mail_ids[:50]              # limit to last 50 messages

        for mail_id in mail_ids:
            status, msg_data = client.fetch(mail_id, '(BODY[])')
            if status != 'OK' or not msg_data or not msg_data[0]:
                continue
            # imaplib may return b')' (bytes) as a list item instead of a tuple.
            # Indexing into bytes in Python 3 returns int, causing decode errors.
            raw = None
            for item in msg_data:
                if isinstance(item, (tuple, list)) and len(item) >= 2 and isinstance(item[1], bytes):
                    raw = item[1]
                    break
            if not raw:
                continue

            try:
                msg = email_lib.message_from_bytes(raw)
            except Exception:
                continue

            # Check recipient (To and Delivered-To headers)
            to_header = decode_header_value(msg.get('To', ''))
            delivered_to = decode_header_value(msg.get('Delivered-To', ''))
            cc_header = decode_header_value(msg.get('Cc', ''))
            all_recipients = f'{to_header} {delivered_to} {cc_header}'.lower()

            if target_email.lower() not in all_recipients:
                continue

            # Check timestamp
            if since_ms:
                date_str = msg.get('Date', '')
                try:
                    from email.utils import parsedate_to_datetime
                    msg_dt = parsedate_to_datetime(date_str)
                    msg_ts_ms = msg_dt.timestamp() * 1000
                    if msg_ts_ms < since_ms:
                        continue
                except Exception:
                    pass  # If we can't parse date, include the message

            # Extract body and look for code
            body = get_email_body(msg)
            subject = decode_header_value(msg.get('Subject', ''))
            from_addr = decode_header_value(msg.get('From', ''))

            code = extract_code_from_text(body) or extract_code_from_text(subject)
            if code:
                return {
                    'code': code,
                    'subject': subject,
                    'from_addr': from_addr,
                }

        raise RuntimeError('No matching verification code found')

    except imaplib.IMAP4.abort:
        # Connection was reset; clear cached client so next call reconnects
        _imap_client = None
        raise RuntimeError('IMAP connection was reset, will reconnect on next attempt')
    except RuntimeError:
        raise
    except Exception as e:
        _imap_client = None
        raise RuntimeError(str(e))


# ─── HTTP Handler ──────────────────────────────────────────────────────────────

class BridgeHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # Suppress default request logging; use print instead for clarity
        ts = datetime.now().strftime('%H:%M:%S')
        print(f'[{ts}] {fmt % args}')

    def send_json(self, code, obj):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == '/health':
            self.send_json(200, {'ok': True, 'host': IMAP_HOST, 'user': IMAP_USER})
            return

        if parsed.path == '/latest-code':
            target_email = (params.get('email') or [''])[0].strip()
            since_ms_str = (params.get('since') or ['0'])[0].strip()

            if not target_email:
                self.send_json(400, {'error': 'email parameter required'})
                return

            try:
                since_ms = int(since_ms_str) if since_ms_str else 0
            except ValueError:
                since_ms = 0

            try:
                result = find_latest_code(target_email, since_ms)
                print(f'  -> Found code {result["code"]} for {target_email}')
                self.send_json(200, result)
            except RuntimeError as e:
                self.send_json(404, {'error': str(e)})
            except Exception as e:
                print(f'  -> IMAP error: {e}')
                self.send_json(500, {'error': str(e)})
            return

        self.send_json(404, {'error': 'not found'})

    def do_OPTIONS(self):
        # CORS preflight
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    global IMAP_HOST, IMAP_PORT, IMAP_USER, IMAP_PASS, IMAP_USE_SSL, LISTEN_PORT

    parser = argparse.ArgumentParser(
        description='Local HTTP-to-IMAP bridge for SimpleAuthFlow',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--host', required=True, help='IMAP server hostname (e.g. imap.gmail.com)')
    parser.add_argument('--port', type=int, default=993, help='IMAP port (default: 993)')
    parser.add_argument('--user', required=True, help='IMAP login username / email')
    parser.add_argument('--password', required=True, help='IMAP login password')
    parser.add_argument('--ssl', dest='use_ssl', action='store_true', default=True,
                        help='Use SSL/TLS (default: enabled for port 993)')
    parser.add_argument('--no-ssl', dest='use_ssl', action='store_false',
                        help='Disable SSL (e.g. for port 143)')
    parser.add_argument('--listen-port', type=int, default=9090,
                        help='HTTP server listen port (default: 9090)')
    args = parser.parse_args()

    IMAP_HOST = args.host
    IMAP_PORT = args.port
    IMAP_USER = args.user
    IMAP_PASS = args.password
    IMAP_USE_SSL = args.use_ssl
    LISTEN_PORT = args.listen_port

    # Test connection at startup
    print(f'Connecting to {IMAP_HOST}:{IMAP_PORT} as {IMAP_USER} (SSL: {IMAP_USE_SSL})...')
    try:
        c = connect_imap(timeout=15)
        c.logout()
        print('IMAP connection OK')
    except TimeoutError as e:
        print(f'Connection timed out: {e}')
        print('Possible causes:')
        print('  1. Firewall or VPN blocking outbound port 993')
        print('  2. IMAP access disabled — for iCloud: Settings > iCloud > Mail > enable "Access iCloud Mail in other apps"')
        print('  3. Wrong IMAP host or port')
        sys.exit(1)
    except imaplib.IMAP4.error as e:
        print(f'IMAP authentication error: {e}')
        print('Check username and password (iCloud requires an App-Specific Password)')
        sys.exit(1)
    except Exception as e:
        print(f'IMAP connection FAILED: {type(e).__name__}: {e}')
        sys.exit(1)

    server = HTTPServer(('127.0.0.1', LISTEN_PORT), BridgeHandler)
    print(f'HTTP bridge listening on http://127.0.0.1:{LISTEN_PORT}')
    print(f'  GET /health                        — check status')
    print(f'  GET /latest-code?email=...&since=  — fetch verification code')
    print('Press Ctrl+C to stop.')

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')


if __name__ == '__main__':
    main()
