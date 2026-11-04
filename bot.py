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
from email.utils import parsedate_to_datetime

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
NA = 'No disponible'

class DataError(Exception):
    pass


class RateLimitError(DataError):
    def __init__(self, message, retry_after=300):
        super().__init__(message)
        self.retry_after = retry_after


def retry_delay(value):
    seconds = number(value)
    if seconds is None and value:
        try:
            seconds = parsedate_to_datetime(value).timestamp() - time.time()
        except (ValueError, TypeError, OverflowError):
            pass
    return max(60, seconds) if seconds is not None else 300


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
    except urllib.error.HTTPError as error:
        # Only a fixed provider label and numeric status; never expose credential URLs.
        host = urllib.parse.urlsplit(url).hostname
        provider = {'api.geckoterminal.com': 'GeckoTerminal (historial)',
                    'api.dexscreener.com': 'DexScreener (mercado)',
                    'api.telegram.org': 'Telegram'}.get(host, 'Proveedor')
        reasons = {400: 'petición no aceptada', 401: 'autenticación requerida',
                   403: 'acceso denegado', 404: 'recurso no encontrado',
                   429: 'límite de consultas alcanzado'}
        if error.code == 429:
            delay = retry_delay((error.headers or {}).get('Retry-After'))
            raise RateLimitError(f'{provider}: HTTP 429 — límite de consultas alcanzado.', delay) from None
        reason = reasons.get(error.code, 'error del servicio')
        raise DataError(f'{provider}: HTTP {error.code} — {reason}.') from None
    except (TimeoutError, urllib.error.URLError, OSError):
        raise DataError('No se pudo conectar con el proveedor o se agotó el tiempo de espera.') from None
    except ValueError:
        raise DataError('El proveedor devolvió una respuesta no válida.') from None


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
        self.db.execute('CREATE TABLE IF NOT EXISTS calls (chat INTEGER, mint TEXT, author TEXT, message_id INTEGER, called_at REAL, price REAL, quoted_at REAL, PRIMARY KEY(chat,mint))')

    def first_call(self, chat, mint, author=None, message_id=None, called_at=None):
        if author is not None:
            self.db.execute('INSERT OR IGNORE INTO calls(chat,mint,author,message_id,called_at) VALUES (?,?,?,?,?)',
                            (chat, mint, author, message_id, called_at))
            self.db.commit()
        return self.db.execute('SELECT author,message_id,called_at,price,quoted_at FROM calls WHERE chat=? AND mint=?', (chat,mint)).fetchone()

    def quote_call(self, chat, mint, message_id, price, quoted_at):
        price = number(price)
        if price is not None and price > 0:
            self.db.execute('UPDATE calls SET price=?,quoted_at=? WHERE chat=? AND mint=? AND message_id=? AND price IS NULL',
                            (price,quoted_at,chat,mint,message_id))
            self.db.commit()


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
        info = self.gmgn_query('info', mint)
        if info.get('address') != mint:
            raise DataError('GMGN no confirmó el contrato solicitado.')
        price = info.get('price') if isinstance(info.get('price'), dict) else {}
        pool = info.get('pool') if isinstance(info.get('pool'), dict) else {}
        current = number(price.get('price'))
        def product(supply):
            value = number(supply)
            return current * value if current is not None and current >= 0 and value is not None and value >= 0 else None
        changes = {}
        for field, window in [('m5', '5m'), ('h1', '1h'), ('h24', '24h')]:
            old = number(price.get('price_' + window))
            changes[field] = (current / old - 1) * 100 if current is not None and old is not None and old > 0 else None
        address = info.get('biggest_pool_address') or pool.get('pool_address')
        pair = {'baseToken': {'name': info.get('name', 'Token'), 'symbol': info.get('symbol', '?')},
                'pairAddress': address if valid_address(address) else None,
                'dexId': pool.get('exchange', 'GMGN'), 'priceUsd': current,
                'marketCap': product(info.get('circulating_supply')), 'fdv': product(info.get('total_supply')),
                'liquidity': {'usd': info.get('liquidity') if info.get('liquidity') is not None else pool.get('liquidity')},
                'volume': {'h24': price.get('volume_24h')}, 'priceChange': changes,
                'txns': {'h24': {'buys': price.get('buys_24h'), 'sells': price.get('sells_24h')}},
                'gmgn_info': info}
        fetched = self.cache.get(('gmgn', 'info', mint), (time.time(),))[0]
        return pair, [pair], fetched

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
        args = ['gmgn-cli', 'token', 'holders' if command == 'sniper_holders' else command, '--chain', 'sol', '--address', mint, '--raw']
        if command == 'sniper_holders':
            args += ['--tag', 'sniper', '--limit', '100', '--order-by', 'amount_percentage', '--direction', 'desc']
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

    def current_snipers(self, mint):
        data = self.gmgn_query('sniper_holders', mint)
        rows = data.get('list')
        if not isinstance(rows, list):
            raise DataError('GMGN no devolvió la lista de snipers actuales.')
        seen, total = set(), 0.0
        for row in rows:
            if not isinstance(row, dict) or not valid_address(row.get('address')):
                raise DataError('Lista sniper incompleta o no válida.')
            ratio = number(row.get('amount_percentage'))
            if ratio is None or not 0 <= ratio <= 1 or row['address'] in seen:
                raise DataError('Porcentajes sniper no válidos; no se calcula un total.')
            seen.add(row['address'])
            total += ratio
        if total > 1.000001:
            raise DataError('Porcentajes sniper inconsistentes.')
        label = 'Snipers actuales (parcial, 100 carteras)' if len(rows) >= 100 else 'Snipers actuales (GMGN)'
        return f'🎯 {label}: {fmt(total, ratio=True)} del suministro'

    def history(self, mint):
        pair, _, fetched = self.market(mint)
        info = pair['gmgn_info']
        ath = number(info.get('ath_price'))
        current = number(pair.get('priceUsd'))
        if ath is None or ath <= 0:
            return ('<b>ATH de precio · GMGN</b>\nNo disponible en la respuesta de GMGN.\n'
                    'ATH histórico sin verificar. No se calcula con el suministro actual.')
        if current is not None and ath < current:
            return '<b>ATH de precio · GMGN</b>\nDato inconsistente: inferior al precio actual. ATH sin verificar.'
        return (f'<b>ATH de precio reportado por GMGN</b>\n{fmt(ath, money=True)}\n\n'
                'Fecha del ATH: no disponible en este campo.\n'
                f'{ath_mc(info)}\n'
                '*Si aparece ≈: estimación con suministro actual; MC histórico sin verificar.\n'
                'Dato del proveedor, sin contraste independiente de todo el historial.\n'
                f'Consulta: {stamp(fetched)}')


def keyboard(mint, pair, preference='dexscreener'):
    urls = {'dexscreener': f'https://dexscreener.com/solana/{pair}',
            'dextools': f'https://www.dextools.io/app/en/solana/pair-explorer/{pair}'}
    labels = {'dexscreener': 'DexScreener', 'dextools': 'DEXTools'}
    order = [preference, 'dextools' if preference == 'dexscreener' else 'dexscreener']
    return {'inline_keyboard': [
        [({'text': labels[k] + (' ★' if k == preference else ''), 'url': urls[k]} if valid_address(pair) else {'text': labels[k], 'callback_data': 'missingpool'}) for k in order],
        [{'text': '🫧 Mapa', 'url': f'https://app.bubblemaps.io/sol/token/{mint}'},
         {'text': '👥 Holders', 'callback_data': f'holders:{mint}'}],
        [{'text': '🎯 Snipers', 'callback_data': f'snipers:{mint}'},
         {'text': '🏔 ATH', 'callback_data': f'ath:{mint}'}],
        [{'text': 'GMGN', 'url': f'https://gmgn.ai/sol/token/{mint}'},
         {'text': 'Solscan', 'url': f'https://solscan.io/token/{mint}'}],
        [{'text': '🔄 Actualizar', 'callback_data': f'scan:{mint}'},
         {'text': 'ℹ Fuentes', 'callback_data': f'sources:{mint}'}],
        [{'text': '⚙ Elegir gráfico', 'callback_data': 'settings'}]
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


def ath_mc(info):
    ath, supply = number(info.get('ath_price')), number(info.get('circulating_supply'))
    if ath is None or ath <= 0 or supply is None or supply < 0:
        return 'MC al precio ATH: — (sin suministro histórico)'
    return f'MC al precio ATH ≈ {compact(ath * supply, True)}*'


def call_text(record, current):
    if not record:
        return ''
    author, message_id, when, initial, quoted_at = record
    current = number(current)
    variation = change((current / initial - 1) * 100) if initial and current is not None else '— (sin precio inicial)'
    return f'📣 Primera call registrada: <b>{esc(author, 70)}</b>\nDesde su call: <b>{variation}</b>\n<i>{stamp(when)}</i>'


def ath_line(info, current):
    ath, current = number(info.get('ath_price')), number(current)
    if ath is None or ath <= 0:
        return '🏔 <b>ATH de precio: no disponible</b>'
    if current is not None and ath < current:
        return '🏔 <b>ATH de precio: dato inconsistente</b>'
    return f'🏔 <b>ATH precio {fmt(ath, money=True)}</b> · {ath_mc(info)}'


def card(mint, pair, fetched, info=None, gmgn_note=''):
    base = pair.get('baseToken') or {}
    changes = pair.get('priceChange') or {}
    tx = (pair.get('txns') or {}).get('h24') or {}
    info = info or pair.get('gmgn_info') or {}
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
             ath_line(info, pair.get('priceUsd')),
             f'👥 Holders {compact(info.get("holder_count"))} · Top 10 {top}',
             pair.get('sniper_text', '🎯 Snipers actuales: —')]
    if gmgn_note:
        lines.append('<i>GMGN: datos no disponibles</i>')
    if pair.get('call_text'):
        lines += ['', pair['call_text']]
    if '≈' in ath_mc(info):
        lines.append('<i>*Estimación con suministro circulante actual; MC histórico sin verificar.</i>')
    lines += ['', f'<code>{mint}</code>', '',
              f'<i>GMGN · Consulta {stamp(fetched)}</i>',
              '<i>— Sin datos · Detalles en «Fuentes»</i>']
    return '\n'.join(lines)


def sources_text(pair, fetched, gmgn_note=''):
    lines = ['<b>Fuentes y alcance</b>',
             'Mercado: GMGN. MC = precio × suministro circulante. FDV = precio × suministro total; no se sustituye MC por FDV.',
             'Precio y actividad: GMGN. Variaciones calculadas con sus precios al inicio de cada período. Liquidez del pool principal indicado por GMGN.',
             'Holders, Top 10 y etiquetas sniper: GMGN cuando está disponible. Una etiqueta no prueba que sea un bot.',
             'ATH de precio: reportado por GMGN. MC al precio ATH marcado ≈ es una estimación con suministro circulante actual, no el MC histórico. Snipers: suma de participaciones de holders etiquetados por GMGN, consulta limitada a 100 carteras; una lista de 100 es parcial. Calls: primer contrato recibido por el bot en cada grupo; precio de referencia de la primera consulta, no precio exacto del mensaje. La variación se actualiza al consultar, sin alertas automáticas.',
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
        'Datos: GMGN. ATH de precio reportado por el proveedor; no certificado independientemente.')


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

    def send_card(self, chat, text, markup, logo):
        if isinstance(logo, str) and logo.startswith('https://') and len(logo) < 2048:
            payload = {'chat_id': chat, 'photo': logo}
            fits = len(text.encode('utf-16-le')) // 2 <= 1024
            if fits:
                payload.update(caption=text, parse_mode='HTML', reply_markup=markup)
            try:
                result = self.api('sendPhoto', payload)
                if fits:
                    return result
            except DataError:
                text += '\n<i>Imagen no disponible.</i>'
        return self.send(chat, text, markup)

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
            text = (msg.get('text') or msg.get('caption') or '').strip()
            if text.startswith('/'):
                first, _, arg = text.partition(' ')
                action = first.split('@')[0][1:].lower()
            elif valid_address(text):
                action, arg = 'scan', text
            else:
                candidates = re.findall(r'(?<![A-Za-z0-9])[1-9A-HJ-NP-Za-km-z]{32,44}(?![A-Za-z0-9])', text)
                arg = next((x for x in candidates if valid_address(x)), '')
                if not arg:
                    return
                action = 'scan'
        if action == 'missingpool':
            return self.send(chat, 'GMGN no ha devuelto un pool válido para abrir este gráfico. Puedes usar el botón GMGN.')
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
        group_call = not callback and action == 'scan' and msg['chat'].get('type') in ('group', 'supergroup') and valid_address(arg)
        if group_call:
            sender = msg.get('sender_chat') or msg.get('from') or {}
            author = ('@' + sender['username']) if sender.get('username') else sender.get('title') or sender.get('first_name') or 'Autor no identificado'
            self.scanner.store.first_call(chat, arg, author, msg.get('message_id'), msg.get('date', time.time()))
        if time.monotonic() - self.last_request.get(user, -100) < 3:
            return self.send(chat, 'Espera unos segundos antes de la siguiente consulta.')
        self.last_request[user] = time.monotonic()
        try:
            if not valid_address(arg):
                raise DataError('Pega el contrato completo de Solana después del comando.')
            if action == 'scan':
                pair, _, fetched = self.scanner.market(arg)
                info = pair['gmgn_info']
                if group_call:
                    self.scanner.store.quote_call(chat, arg, msg.get('message_id'), pair.get('priceUsd'), fetched)
                try:
                    pair['sniper_text'] = self.scanner.current_snipers(arg)
                except DataError:
                    pair['sniper_text'] = '🎯 Snipers actuales: — (consulta no disponible)'
                pair['call_text'] = call_text(self.scanner.store.first_call(chat, arg), pair.get('priceUsd'))
                return self.send_card(chat, card(arg, pair, fetched, info),
                                      keyboard(arg, pair['pairAddress'], self.scanner.store.preference(user)), info.get('logo'))
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
                return self.send(chat, self.scanner.current_snipers(arg) +
                                 '\nParticipación actual de las carteras etiquetadas por GMGN; no porcentaje de compras al lanzamiento. Consulta limitada a 100 carteras.\n' +
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
    parser.add_argument('--scan', help='Consultar sin Telegram; requiere GMGN')
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
