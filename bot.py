"""Veraz Bot 0.1: read-only Solana scanner. Python 3.11+, stdlib only."""
import argparse
import html
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
NA = 'No disponible'

class DataError(Exception):
    pass


def valid_address(value):
    if not isinstance(value, str) or not 32 <= len(value) <= 44:
        return False
    n = 0
    for c in value:
        if c not in ALPHABET:
            return False
        n = n * 58 + ALPHABET.index(c)
    size = (n.bit_length() + 7) // 8 + len(value) - len(value.lstrip('1'))
    return size == 32


def number(value):
    if isinstance(value, bool) or value is None:
        return None
    try:
        result = float(value)
        return result if math.isfinite(result) else None
    except (ValueError, TypeError):
        return None


def fmt(value, money=False, ratio=False):
    n = number(value)
    if n is None:
        return NA
    if ratio:
        return f'{n * 100:.2f}%'
    if money:
        return '$' + (f'{n:,.2f}' if abs(n) >= 1 else (format(Decimal(str(n)), 'f').rstrip('0').rstrip('.') if n else '0'))
    return f'{n:,.8f}'.rstrip('0').rstrip('.')


def stamp(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def esc(value, limit=100):
    return html.escape(str(value)[:limit])


def fetch(url, payload=None, timeout=20):
    headers = {'User-Agent': 'VerazBot/0.1', 'Accept': 'application/json'}
    data = None
    if payload is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(payload).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=timeout) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        # Do not expose URLs: Telegram URLs contain a secret token.
        raise DataError('Proveedor no disponible, acceso denegado o límite de consultas.') from None


def select_pair(rows, mint):
    if not isinstance(rows, list):
        raise DataError('Respuesta de mercado no reconocida.')
    pairs = [p for p in rows if isinstance(p, dict) and p.get('chainId') == 'solana'
             and (p.get('baseToken') or {}).get('address') == mint
             and valid_address(p.get('pairAddress'))]
    if not pairs:
        raise DataError('Sin par indexado con este contrato como token base en Solana.')
    def rank(p):
        return (number((p.get('liquidity') or {}).get('usd')) or 0, p['pairAddress'])
    return max(pairs, key=rank), pairs


class Store:
    def __init__(self, path='veraz.sqlite3'):
        self.db = sqlite3.connect(path)
        self.db.execute('CREATE TABLE IF NOT EXISTS preferences (user INTEGER PRIMARY KEY, provider TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS snapshots (mint TEXT, fetched REAL, pair TEXT, payload TEXT)')
        self.db.execute('CREATE INDEX IF NOT EXISTS by_mint ON snapshots(mint,fetched)')
        self.db.execute('CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT)')

    def preference(self, user, provider=None):
        if provider is not None:
            if provider not in ('dexscreener', 'dextools'):
                raise ValueError('Proveedor incorrecto')
            self.db.execute('INSERT OR REPLACE INTO preferences VALUES (?,?)', (user, provider))
            self.db.commit()
        row = self.db.execute('SELECT provider FROM preferences WHERE user=?', (user,)).fetchone()
        return row[0] if row else 'dexscreener'

    def save(self, mint, pair, fetched):
        self.db.execute('INSERT INTO snapshots VALUES (?,?,?,?)', (mint, fetched, pair['pairAddress'], json.dumps(pair)))
        self.db.commit()

    def offset(self, value=None):
        if value is not None:
            self.db.execute("INSERT OR REPLACE INTO state VALUES ('offset',?)", (str(value),))
            self.db.commit()
        row = self.db.execute("SELECT value FROM state WHERE key='offset'").fetchone()
        return int(row[0]) if row else 0


class Scanner:
    def __init__(self, store, transport=fetch, gmgn=False):
        self.store, self.transport, self.gmgn = store, transport, gmgn
        self.cache = {}
        self.gmgn_blocked_until = 0

    def market(self, mint):
        if not valid_address(mint):
            raise DataError('Contrato Solana inválido. Pega la dirección completa.')
        key = ('market', mint)
        if key in self.cache and time.time() - self.cache[key][0] < 30:
            return self.cache[key][1]
        rows = self.transport(f'https://api.dexscreener.com/token-pairs/v1/solana/{mint}')
        pair, pairs = select_pair(rows, mint)
        fetched = time.time()
        self.store.save(mint, pair, fetched)
        result = (pair, pairs, fetched)
        self.cache[key] = (fetched, result)
        return result

    def gmgn_query(self, command, mint):
        if not valid_address(mint):
            raise DataError('Contrato inválido.')
        if not self.gmgn:
            raise DataError('GMGN pendiente de configurar: hace falta su clave API de consulta.')
        if time.time() < self.gmgn_blocked_until:
            raise DataError('GMGN en pausa por límite de consultas; vuelve a intentarlo más tarde.')
        if not shutil.which('gmgn-cli'):
            raise DataError('Falta instalar gmgn-cli en el equipo del bot.')
        key = ('gmgn', command, mint)
        if key in self.cache and time.time() - self.cache[key][0] < 60:
            return self.cache[key][1]
        args = ['gmgn-cli', 'token', command, '--chain', 'sol', '--address', mint, '--raw']
        if command == 'holders':
            args += ['--limit', '10', '--order-by', 'amount_percentage', '--direction', 'desc']
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=25, check=False)
            if proc.returncode:
                self.gmgn_blocked_until = time.time() + 300
                raise DataError('GMGN no devolvió datos: revisa clave, permisos y cuota gratuita. Pausa de 5 minutos.')
            data = json.loads(proc.stdout)
            if not isinstance(data, dict):
                raise DataError('Formato GMGN no reconocido.')
            if data.get('code') not in (None, 0, '0', 200, '200') or data.get('success') is False:
                self.gmgn_blocked_until = time.time() + 300
                raise DataError('GMGN rechazó la consulta. Pausa de 5 minutos.')
            data = data.get('data', data)
            if not isinstance(data, dict):
                raise DataError('Formato GMGN no reconocido.')
        except (OSError, subprocess.TimeoutExpired, ValueError):
            self.gmgn_blocked_until = time.time() + 300
            raise DataError('GMGN no disponible. Pausa de 5 minutos.') from None
        self.cache[key] = (time.time(), data)
        return data

    def history(self, mint):
        pair, pairs, _ = self.market(mint)
        key = ('history', mint)
        if key in self.cache and time.time() - self.cache[key][0] < 300:
            return self.cache[key][1]
        # Deliberately bounded free lookup. Never certify this result as a lifetime ATH.
        url = (f'https://api.geckoterminal.com/api/v2/networks/solana/pools/{pair["pairAddress"]}'
               f'/ohlcv/day?aggregate=1&limit=1000&currency=usd&token={mint}')
        data = self.transport(url)
        meta = data.get('meta') or {}
        if mint not in ((meta.get('base') or {}).get('address'), (meta.get('quote') or {}).get('address')):
            raise DataError('No se pudo confirmar el token del historial. Máximo no calculado.')
        rows = ((data.get('data') or {}).get('attributes') or {}).get('ohlcv_list')
        if not isinstance(rows, list):
            raise DataError('Historial no disponible.')
        candles = []
        for row in rows:
            if not isinstance(row, list) or len(row) < 6:
                continue
            vals = [number(v) for v in row[:6]]
            if any(v is None for v in vals):
                continue
            t, o, high, low, close, volume = vals
            if 0 < t <= time.time() and high >= max(o, close) and 0 <= low <= min(o, close) and high > 0 and volume > 0:
                candles.append(vals)
        if not candles:
            raise DataError('No hay velas válidas con operaciones para calcular un máximo.')
        peak = max(candles, key=lambda r: r[2])
        result = (f'<b>Máximo del historial disponible · precio USD</b>\n'
                  f'{fmt(peak[2], money=True)} · vela diaria {stamp(peak[0])}\n'
                  f'Período recibido: {stamp(min(r[0] for r in candles))} — {stamp(max(r[0] for r in candles))}\n'
                  f'{len(candles)} velas con volumen. Fuente: GeckoTerminal.\n'
                  f'Par: <code>{pair["pairAddress"]}</code>\n\n'
                  '<b>ATH histórico: sin verificar.</b> Consulta limitada a un par y una página de hasta 1.000 velas. '
                  'No cubre necesariamente lanzamiento, otros mercados ni migraciones. '
                  'El pico no se ha contrastado con operaciones individuales. '
                  'La fecha corresponde al inicio de la vela, no al instante exacto.\n'
                  'ATH de capitalización: no calculado; falta suministro circulante histórico.\n'
                  f'Consultado: {stamp(time.time())}')
        self.cache[key] = (time.time(), result)
        return result


def keyboard(mint, pair, preference='dexscreener'):
    urls = {'dexscreener': f'https://dexscreener.com/solana/{pair}',
            'dextools': f'https://www.dextools.io/app/en/solana/pair-explorer/{pair}'}
    labels = {'dexscreener': '📊 DexScreener', 'dextools': '📈 DEXTools'}
    order = [preference, 'dextools' if preference == 'dexscreener' else 'dexscreener']
    return {'inline_keyboard': [
        [{'text': labels[k] + (' ★' if k == preference else ''), 'url': urls[k]} for k in order],
        [{'text': '🫧 Bubble Maps', 'url': f'https://app.bubblemaps.io/sol/token/{mint}'},
         {'text': '👥 Top holders', 'callback_data': f'holders:{mint}'}],
        [{'text': '🎯 Snipers', 'callback_data': f'snipers:{mint}'},
         {'text': '🏔 Historial / ATH', 'callback_data': f'ath:{mint}'}],
        [{'text': 'GMGN', 'url': f'https://gmgn.ai/sol/token/{mint}'},
         {'text': 'Solscan', 'url': f'https://solscan.io/token/{mint}'}],
        [{'text': '🔄 Actualizar', 'callback_data': f'scan:{mint}'},
         {'text': 'ℹ Fuentes', 'callback_data': f'sources:{mint}'},
         {'text': '⚙ Chart', 'callback_data': 'settings'}]
    ]}


def compact(value, money=False):
    n = number(value)
    if n is None:
        return '—'
    prefix = '$' if money else ''
    for scale, suffix in ((1e12, 'T'), (1e9, 'B'), (1e6, 'M'), (1e3, 'K')):
        if abs(n) >= scale:
            return prefix + f'{n / scale:.2f}'.rstrip('0').rstrip('.') + suffix
    return fmt(n, money=money)


def change(value):
    n = number(value)
    if n is None:
        return '—'
    return ('🟢 +' if n > 0 else '🔴 ' if n < 0 else '') + f'{n:.2f}'.rstrip('0').rstrip('.') + '%'


def card(mint, pair, fetched, info=None, gmgn_note='GMGN pendiente de configurar.'):
    base = pair.get('baseToken') or {}
    changes = pair.get('priceChange') or {}
    tx = (pair.get('txns') or {}).get('h24') or {}
    info = info or {}
    stat, tags = info.get('stat') or {}, info.get('wallet_tags_stat') or {}
    price = fmt(pair.get('priceUsd'), money=True) if number(pair.get('priceUsd')) is not None else '—'
    top = fmt(stat.get('top_10_holder_rate'), ratio=True) if number(stat.get('top_10_holder_rate')) is not None else '—'
    lines = [f'<b>{esc(base.get("name", "Token"))} · ${esc(base.get("symbol", "?"), 25)}</b>',
             f'Solana · {esc(pair.get("dexId", "DEX"))}',
             f'💵 <b>{price}</b>', '',
             f'MC <b>{compact(pair.get("marketCap"), True)}</b> · Liq <b>{compact((pair.get("liquidity") or {}).get("usd"), True)}</b>',
             f'FDV {compact(pair.get("fdv"), True)} · Vol 24h {compact((pair.get("volume") or {}).get("h24"), True)}',
             ' · '.join(f'{label} {change(changes.get(key))}' for key, label in [('m5', '5m'), ('h1', '1h'), ('h24', '24h')]),
             f'Compras {compact(tx.get("buys"))} · Ventas {compact(tx.get("sells"))} <i>(24h)</i>', '',
             '🏔 <b>ATH histórico: sin verificar</b>',
             f'👥 Holders {compact(info.get("holder_count"))} · Top 10 {top}',
             f'🎯 Snipers etiquetados {compact(tags.get("sniper_wallets"))}']
    if gmgn_note:
        lines.append('<i>GMGN: datos no disponibles</i>')
    lines += ['', f'<code>{mint}</code>', '',
              f'<i>DexScreener · Consulta {stamp(fetched)}</i>',
              '<i>— Sin datos · Detalles en «Fuentes»</i>']
    return '\n'.join(lines)


def sources_text(pair, fetched, gmgn_note=''):
    lines = ['<b>Fuentes y alcance</b>',
             'Mercado: DexScreener. MC reportada por el proveedor; FDV es valoración diluida.',
             'Precio, liquidez, variaciones, volumen y operaciones: par con mayor liquidez disponible. No representan todos los mercados.',
             'Holders, Top 10 y etiquetas sniper: GMGN cuando está disponible. Una etiqueta no prueba que sea un bot.',
             'ATH histórico sin verificar: el botón ATH consulta el máximo del historial disponible, que puede ser incompleto.',
             'Bubble Maps abre el mapa externo si el proyecto tiene cobertura.']
    created = number(pair.get('pairCreatedAt'))
    if created and 0 < created / 1000 <= time.time():
        lines.append(f'Creación del par (no del token): {stamp(created / 1000)}')
    if gmgn_note:
        lines.append(esc(gmgn_note, 300))
    lines += [f'Consulta de mercado: {stamp(fetched)}.',
              'La hora de consulta no garantiza la frescura del proveedor. — significa dato no disponible, nunca cero.']
    return '\n\n'.join(lines)


def holders_text(data):
    rows = data.get('list')
    if not isinstance(rows, list):
        raise DataError('Lista de holders no disponible en GMGN.')
    lines = ['<b>Top holders · reportado por GMGN</b>']
    for index, row in enumerate(rows[:10], 1):
        addr = row.get('address')
        if not valid_address(addr):
            continue
        kind = 'Exchange / pool' if row.get('addr_type') == 2 else 'Sin clasificar'
        lines.append(f'{index}. <a href="https://solscan.io/account/{addr}">{addr[:6]}…{addr[-4:]}</a> '
                     f'· {fmt(row.get("amount_percentage"), ratio=True)} · {fmt(row.get("balance"))} tokens · {kind}')
    if len(lines) == 1:
        lines.append('No hay filas válidas disponibles; no implica cero holders.')
    lines += ['', 'No se infiere que carteras relacionadas sean del mismo dueño. Clasificación del proveedor.',
              f'Consulta/caché de hasta 60 s · {stamp(time.time())}']
    return '\n'.join(lines)


HELP = ('<b>Veraz · versión inicial para Solana</b>\n'
        'Pega un contrato o utiliza /scan CONTRATO.\n'
        '/chart — elegir DexScreener o DEXTools\n'
        '/holders CONTRATO — top holders GMGN\n'
        '/snipers CONTRATO — detección GMGN\n'
        '/ath CONTRATO — máximo del historial disponible\n\n'
        'Los charts se abren en el navegador. Bubble Maps depende de cobertura externa. '
        'No certificamos un ATH si falta historial. Axiom: integración automática pendiente.')


class Bot:
    def __init__(self, token, scanner, allowed=None):
        self.token, self.scanner = token, scanner
        self.allowed = allowed or set()
        self.last_request = {}

    def api(self, method, payload):
        response = fetch(f'https://api.telegram.org/bot{self.token}/{method}', payload, timeout=40)
        if not isinstance(response, dict) or not response.get('ok'):
            raise DataError('Telegram rechazó la petición; revisa configuración y permisos.')
        return response.get('result')

    def send(self, chat, text, markup=None):
        payload = {'chat_id': chat, 'text': text, 'parse_mode': 'HTML',
                   'link_preview_options': {'is_disabled': True}}
        if markup:
            payload['reply_markup'] = markup
        return self.api('sendMessage', payload)

    def settings(self, chat):
        self.send(chat, 'Elige tu gráfico preferido. Siempre tendrás disponibles los dos botones.',
                  {'inline_keyboard': [[{'text': 'DexScreener', 'callback_data': 'pref:dexscreener'},
                                        {'text': 'DEXTools', 'callback_data': 'pref:dextools'}]]})

    def handle(self, update):
        callback = update.get('callback_query')
        msg = (callback or {}).get('message') if callback else update.get('message')
        if not msg or 'chat' not in msg:
            return
        chat = msg['chat']['id']
        if self.allowed and chat not in self.allowed:
            return
        user = ((callback or msg).get('from') or {}).get('id', chat)
        if callback:
            self.api('answerCallbackQuery', {'callback_query_id': callback['id']})
            action, _, arg = callback.get('data', '').partition(':')
        else:
            text = (msg.get('text') or '').strip()
            if text.startswith('/'):
                first, _, arg = text.partition(' ')
                action = first.split('@')[0][1:].lower()
            elif valid_address(text):
                action, arg = 'scan', text
            else:
                return
        if action in ('start', 'help'):
            return self.send(chat, HELP)
        if action in ('chart', 'settings'):
            if arg.lower() in ('dexscreener', 'dextools'):
                self.scanner.store.preference(user, arg.lower())
                return self.send(chat, 'Preferencia guardada para tus próximas consultas.')
            return self.settings(chat)
        if action == 'pref':
            if arg in ('dexscreener', 'dextools'):
                self.scanner.store.preference(user, arg)
                return self.send(chat, 'Preferencia guardada para tus próximas consultas.')
            return
        if action not in ('scan', 'ath', 'holders', 'snipers', 'sources'):
            return self.send(chat, HELP)
        if time.monotonic() - self.last_request.get(user, -100) < 3:
            return self.send(chat, 'Espera unos segundos antes de la siguiente consulta.')
        self.last_request[user] = time.monotonic()
        try:
            if not valid_address(arg):
                raise DataError('Pega el contrato completo de Solana después del comando.')
            if action == 'scan':
                pair, _, fetched = self.scanner.market(arg)
                info, note = None, ''
                try:
                    info = self.scanner.gmgn_query('info', arg)
                except DataError as error:
                    note = str(error)
                return self.send(chat, card(arg, pair, fetched, info, note),
                                 keyboard(arg, pair['pairAddress'], self.scanner.store.preference(user)))
            if action == 'sources':
                pair, _, fetched = self.scanner.market(arg)
                note = ''
                try:
                    self.scanner.gmgn_query('info', arg)
                except DataError as error:
                    note = str(error)
                return self.send(chat, sources_text(pair, fetched, note))
            if action == 'ath':
                return self.send(chat, self.scanner.history(arg))
            if action == 'holders':
                return self.send(chat, holders_text(self.scanner.gmgn_query('holders', arg)))
            if action == 'snipers':
                data = self.scanner.gmgn_query('security', arg)
                return self.send(chat, '<b>Snipers de lanzamiento · GMGN</b>\n'
                                 f'Carteras detectadas: {fmt(data.get("sniper_count"))}\n'
                                 'Clasificación de GMGN; no prueba que todas sean bots ni que conserven tokens.\n'
                                 'Porcentaje que conservan: no calculado en esta versión.\n'
                                 f'Consulta/caché de hasta 60 s · {stamp(time.time())}')
        except DataError as error:
            return self.send(chat, esc(str(error), 500))

    def run(self):
        self.api('getMe', {})
        print('Bot iniciado. Pulsa Ctrl+C para detenerlo.', flush=True)
        offset = self.scanner.store.offset()
        while True:
            try:
                updates = self.api('getUpdates', {'offset': offset, 'timeout': 25,
                                   'allowed_updates': ['message', 'callback_query']})
                for update in updates:
                    self.handle(update)
                    offset = update['update_id'] + 1
                    self.scanner.store.offset(offset)
            except DataError:
                print('Servicio temporalmente no disponible. Reintento en 10 s.', flush=True)
                time.sleep(10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scan', help='Consultar sin Telegram; requiere acceso a DexScreener')
    args = parser.parse_args()
    store = Store(os.environ.get('BOT_DB', 'veraz.sqlite3'))
    scanner = Scanner(store, gmgn=os.environ.get('ENABLE_GMGN') == '1')
    if args.scan:
        try:
            pair, _, fetched = scanner.market(args.scan)
            print(card(args.scan, pair, fetched))
            print(json.dumps(keyboard(args.scan, pair['pairAddress']), ensure_ascii=False, indent=2))
        except DataError as error:
            parser.exit(1, f'{error}\n')
        return
    token = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    if not re.fullmatch(r'\d+:[A-Za-z0-9_-]+', token):
        parser.exit(1, 'Falta TELEGRAM_BOT_TOKEN. Ejecuta python iniciar.py para introducirlo de forma privada.\n')
    allowed = {int(x.strip()) for x in os.environ.get('ALLOWED_CHAT_IDS', '').split(',') if x.strip()}
    try:
        Bot(token, scanner, allowed).run()
    except KeyboardInterrupt:
        print('Bot detenido.')


if __name__ == '__main__':
    main()
