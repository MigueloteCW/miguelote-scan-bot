"""HTTPS terminates at hosting proxy. No public administrative endpoints."""
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from bot import Bot, DataError, Scanner, Store, fetch

MAX_BODY = 64 * 1024

class WebhookApp:
    def __init__(self, token, secret, db_path, allowed=None, gmgn=False):
        if not re.fullmatch(r'[A-Za-z0-9_-]{32,256}', secret):
            raise ValueError('WEBHOOK_SECRET debe tener 32–256 caracteres seguros.')
        self.token, self.secret, self.db_path = token, secret, db_path
        self.allowed, self.gmgn = allowed, gmgn
        self.lock = threading.Lock()
        self.cache = {}
        self.last_request = {}
        self.gmgn_blocked_until = 0
        # Bot/SQLite are constructed in the request thread that uses them.

    def process(self, payload, secret):
        if not hmac.compare_digest(secret, self.secret):
            return 403
        if not isinstance(payload, dict) or type(payload.get('update_id')) is not int:
            return 400
        if not self.lock.acquire(blocking=False):
            return 503  # Telegram retries; do not acknowledge dropped updates.
        store = None
        scanner = None
        try:
            store = Store(self.db_path)
            store.db.execute('CREATE TABLE IF NOT EXISTS handled_updates (id INTEGER PRIMARY KEY, handled REAL)')
            if store.db.execute('SELECT 1 FROM handled_updates WHERE id=?', (payload['update_id'],)).fetchone():
                return 200
            scanner = Scanner(store, gmgn=self.gmgn)
            scanner.cache = self.cache
            scanner.gmgn_blocked_until = self.gmgn_blocked_until
            bot = Bot(self.token, scanner, self.allowed)
            bot.last_request = self.last_request
            bot.handle(payload)
            store.db.execute('INSERT INTO handled_updates VALUES (?,?)', (payload['update_id'], time.time()))
            store.db.execute('DELETE FROM handled_updates WHERE handled < ?', (time.time() - 7 * 86400,))
            store.db.commit()
            return 200
        except (DataError, sqlite3.Error, ValueError, TypeError, KeyError):
            print('Consulta no completada; Telegram puede reintentar.', flush=True)
            return 503
        finally:
            if scanner:
                self.gmgn_blocked_until = scanner.gmgn_blocked_until
            if store:
                store.db.close()
            self.lock.release()


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Do not log paths, headers, bodies or credentials.

        def reply(self, status, body=b''):
            self.send_response(status)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            self.reply(200, b'Veraz Telegram service') if self.path == '/health' else self.reply(404)

        def do_POST(self):
            if self.path != '/telegram':
                return self.reply(404)
            secret = self.headers.get('X-Telegram-Bot-Api-Secret-Token', '')
            if not hmac.compare_digest(secret, app.secret):
                return self.reply(403)
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if length <= 0 or length > MAX_BODY:
                    return self.reply(413)
                self.connection.settimeout(10)
                payload = json.loads(self.rfile.read(length))
            except (ValueError, OSError):
                return self.reply(400)
            self.reply(app.process(payload, secret))
    return Handler


def main():
    token = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    if not re.fullmatch(r'\d+:[A-Za-z0-9_-]+', token):
        raise SystemExit('Configura TELEGRAM_BOT_TOKEN en los secretos del alojamiento.')
    secret = os.environ.get('WEBHOOK_SECRET', '')
    allowed = {int(x.strip()) for x in os.environ.get('ALLOWED_CHAT_IDS', '').split(',') if x.strip()}
    app = WebhookApp(token, secret, os.environ.get('BOT_DB', '/tmp/veraz.sqlite3'),
                     allowed, os.environ.get('ENABLE_GMGN') == '1')
    public_url = os.environ.get('RENDER_EXTERNAL_URL', '').rstrip('/')
    if public_url:
        if not public_url.startswith('https://'):
            raise SystemExit('La URL pública debe usar HTTPS.')
        result = fetch(f'https://api.telegram.org/bot{token}/setWebhook', {
            'url': public_url + '/telegram', 'secret_token': secret,
            'allowed_updates': ['message', 'callback_query'], 'max_connections': 1})
        if not result.get('ok'):
            raise SystemExit('No se pudo registrar el webhook en Telegram.')
    server = ThreadingHTTPServer(('0.0.0.0', int(os.environ.get('PORT', '10000'))), make_handler(app))
    print('Servicio webhook listo.', flush=True)
    server.serve_forever()

if __name__ == '__main__':
    main()
