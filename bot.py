"""Miguelote Scan: read-only multichain scanner. Python 3.11+, stdlib only."""
import argparse
import hashlib
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


GMGN_CHAINS = {'solana':'sol','ethereum':'eth','bsc':'bsc','base':'base','arbitrum':'arbitrum',
               'hyperevm':'hyperevm','robinhood':'robinhood','arc':'arc','stable':'stable','avalanche':'avalanche'}

def valid_contract(value):
    return isinstance(value, str) and (valid_address(value) or bool(re.fullmatch(r'0x[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?', value)) or bool(re.fullmatch(r'T[1-9A-HJ-NP-Za-km-z]{33}', value)))

def normalized(value):
    return value.lower() if isinstance(value,str) and value.startswith('0x') else value

def same_token(a,b):
    return isinstance(a,str) and normalized(a)==normalized(b)


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
        self.db.commit()

    def reference(self, data=None, key=None):
        if data is not None:
            value=json.dumps(data,sort_keys=True)
            key=hashlib.sha256(value.encode()).hexdigest()[:20]
            self.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)', ('ref:'+key,value))
            self.db.commit()
            return key
        row=self.db.execute('SELECT value FROM state WHERE key=?',('ref:'+key,)).fetchone()
        return json.loads(row[0]) if row else None

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
        self.chain = "solana"

    def dex_pairs(self, mint):
        key=('dex', normalized(mint))
        if key in self.cache and time.time()-self.cache[key][0]<60:
            return self.cache[key][1]
        data=self.transport('https://api.dexscreener.com/latest/dex/search?q='+urllib.parse.quote(mint,safe=''))
        rows=data.get('pairs') if isinstance(data,dict) else None
        if not isinstance(rows,list):
            raise DataError('Mercado no disponible. Inténtalo más tarde.')
        rows=[p for p in rows if isinstance(p,dict) and same_token((p.get('baseToken') or {}).get('address'),mint)
              and isinstance(p.get('chainId'),str) and re.fullmatch(r'[a-z0-9-]{1,40}',p['chainId'])]
        self.cache[key]=(time.time(),rows)
        return rows

    def aser(self, mint, live=False):
        # Public read-only API, currently Solana only. Never use peak_mcap as ATH.
        if self.chain!='solana':raise DataError('Aser no disponible para esta red.')
        key=('aser', 'coin' if live else 'token', mint)
        if key in self.cache and time.time()-self.cache[key][0]<60:
            result=self.cache[key][1]
            if result is None:raise DataError('Aser no disponible.')
            return result
        try:
            result=self.transport('https://aser.trade/api/'+key[1]+'/'+urllib.parse.quote(mint,safe=''))
            item=result if live else result.get('token')
            if not isinstance(item,dict) or item.get('mint')!=mint:raise DataError('Aser no confirmó el contrato.')
            self.cache[key]=(time.time(),item)
            return item
        except (DataError,AttributeError,TypeError):
            self.cache[key]=(time.time(),None)
            raise DataError('Aser no disponible.') from None

    def aser_snipers(self,mint):
        data=self.aser(mint,live=True)
        ledger=data.get('holders') or {}
        info=data.get('info') or {}
        checked=number(info.get('checked'))
        if not checked or not 0<=time.time()-checked/1000<=120 or ledger.get('stale') or ledger.get('partial') or ledger.get('frozen'):
            raise DataError('Aser no dispone de una lectura actual y completa de snipers.')
        reading=info.get('snipers')
        pct=number(reading.get('pct')) if isinstance(reading,dict) else number(reading)
        if pct is None or not 0<=pct<=100:raise DataError('Snipers no disponibles en Aser.')
        return f'🎯 Snipers: {pct:.2f}% (Aser)'

    def images(self, mint, info):
        urls=[]
        try:
            metadata=self.aser(mint)
            urls += [metadata.get('header'),metadata.get('image')]
        except DataError:
            pass
        urls.append(info.get('logo'))
        try:
            rows=[p for p in self.dex_pairs(mint) if p['chainId']==self.chain]
            rows.sort(key=lambda p:number((p.get('liquidity') or {}).get('usd')) or 0,reverse=True)
            urls += [(p.get('info') or {}).get('imageUrl') for p in rows]
        except DataError:
            pass
        return list(dict.fromkeys(u for u in urls if isinstance(u,str) and u.startswith('https://') and len(u)<2048))[:3]

    def refresh_market(self,mint):
        self.cache.pop(('gmgn',self.chain,'info',normalized(mint)),None)
        self.cache.pop(('dex',normalized(mint)),None)
        return self.market(mint)

    def market(self, mint):
        try:
            return self.gmgn_market(mint)
        except DataError:
            rows=[p for p in self.dex_pairs(mint) if p['chainId']==self.chain]
            if not rows:
                raise DataError('Sin datos para este contrato y red.')
            pair=dict(max(rows,key=lambda p:number((p.get('liquidity') or {}).get('usd')) or 0))
            pair.update(gmgn_info={},source='DexScreener')
            return pair,rows,self.cache[('dex',normalized(mint))][0]

    def enrich_activity(self,mint,pair):
        # Enrich only the selected pool on the selected chain; never a different market.
        result=dict(pair)
        try:
            matches=[p for p in self.dex_pairs(mint)
                     if p.get('chainId')==pair.get('chainId')
                     and pair.get('pairAddress') and same_token(p.get('pairAddress'),pair['pairAddress'])]
            if matches:
                row=matches[0]
                result['activity_extra']={k:row.get(k) for k in ('txns','boosts','pairCreatedAt')}
        except DataError:
            pass
        return result

    def gmgn_market(self, mint):
        info = self.gmgn_query('info', mint)
        if not same_token(info.get('address'), mint):
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
                'pairAddress': address if valid_contract(address) else None,
                'chainId': self.chain, 'source': 'GMGN',
                'dexId': pool.get('exchange', 'GMGN'), 'priceUsd': current,
                'marketCap': product(info.get('circulating_supply')), 'fdv': product(info.get('total_supply')),
                'liquidity': {'usd': info.get('liquidity') if info.get('liquidity') is not None else pool.get('liquidity')},
                'volume': {'h24': price.get('volume_24h')}, 'priceChange': changes,
                'txns': {'h24': {'buys': price.get('buys_24h'), 'sells': price.get('sells_24h')}},
                'gmgn_info': info}
        fetched = self.cache.get(('gmgn', self.chain, 'info', normalized(mint)), (time.time(),))[0]
        return pair, [pair], fetched

    def gmgn_query(self, command, mint):
        if not valid_contract(mint) or self.chain not in GMGN_CHAINS:
            raise DataError('Sin cobertura de GMGN para esta red.')
        if not self.gmgn:
            raise DataError('GMGN pendiente de configurar: hace falta su clave API de consulta.')
        key = ('gmgn', self.chain, command, normalized(mint))
        if key in self.cache and time.time() - self.cache[key][0] < 60:
            return self.cache[key][1]
        if time.time() < self.gmgn_blocked_until:
            raise DataError('GMGN en pausa por límite de consultas; vuelve a intentarlo más tarde.')
        if not shutil.which('gmgn-cli'):
            raise DataError('Falta instalar gmgn-cli en el equipo del bot.')
        args = ['gmgn-cli', 'token', 'holders' if command in ('sniper_holders','bundler_holders') else command, '--chain', GMGN_CHAINS[self.chain], '--address', mint, '--raw']
        if command in ('sniper_holders','bundler_holders'):
            args += ['--tag', 'sniper' if command=='sniper_holders' else 'bundler', '--limit', '100', '--order-by', 'amount_percentage', '--direction', 'desc']
        if command == 'holders':
            args += ['--limit', '10', '--order-by', 'amount_percentage', '--direction', 'desc']
        delay = 1.1 - (time.monotonic() - self.cache.get(('gmgn_last',), 0))
        if delay > 0:
            time.sleep(delay)
        self.cache[('gmgn_last',)] = time.monotonic()
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
        try:return self.current_tag_holdings(mint,'sniper')
        except DataError:return self.aser_snipers(mint)

    def current_tag_holdings(self, mint, tag):
        if tag not in ('sniper','bundler'):
            raise DataError('Etiqueta no válida.')
        data = self.gmgn_query(tag+'_holders', mint)
        rows = data.get('list')
        if not isinstance(rows, list):
            raise DataError('GMGN no devolvió la lista de snipers actuales.')
        seen, total = set(), 0.0
        for row in rows:
            if not isinstance(row, dict) or not valid_contract(row.get('address')):
                raise DataError('Lista sniper incompleta o no válida.')
            ratio = number(row.get('amount_percentage'))
            if ratio is None or not 0 <= ratio <= 1 or row['address'] in seen:
                raise DataError('Porcentajes sniper no válidos; no se calcula un total.')
            seen.add(row['address'])
            total += ratio
        if total > 1.000001:
            raise DataError('Porcentajes sniper inconsistentes.')
        label = 'Snipers' if tag=='sniper' else 'Bundled'
        if len(rows)>=100: label += ' (parcial)'
        return f'🎯 {label}: {fmt(total, ratio=True)}'

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
        return 'MC estimado —'
    return f'MC estimado ≈ {compact(ath * supply, True)}'


def ath_line(info, current):
    ath, current = number(info.get('ath_price')), number(current)
    if ath is None or ath <= 0:
        return '🏔 ATH —'
    if current is not None and ath < current:
        return '🏔 <b>ATH de precio: dato inconsistente</b>'
    return f'🏔 <b>ATH {fmt(ath, money=True)}</b> · {ath_mc(info)}'


def safe_link(label, url):
    if not isinstance(url,str) or len(url)>2048:
        return None
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username:
        return None
    return f'<a href="{html.escape(url,quote=True)}">{esc(label)}</a>'


def age_text(timestamp, now):
    value=number(timestamp)
    if value is None or value<=0 or value>now:
        return '—'
    seconds=now-value
    if seconds>=86400: return str(int(seconds//86400))+'d'
    if seconds>=3600: return str(int(seconds//3600))+'h'
    return str(int(seconds//60))+'m'


def activity_lines(pair,now):
    extra=pair.get('activity_extra') or (pair if pair.get('source')=='DexScreener' else {})
    txns=extra.get('txns') if isinstance(extra.get('txns'),dict) else {}
    def count(value):
        n=number(value)
        return compact(n) if n is not None and n>=0 and n.is_integer() else '—'
    def transactions(window):
        tx=txns.get(window) if isinstance(txns.get(window),dict) else {}
        return count(tx.get('buys'))+' / '+count(tx.get('sells'))
    liq=number((pair.get('liquidity') or {}).get('usd'))
    mc=number(pair.get('marketCap'))
    volume=number((pair.get('volume') or {}).get('h24'))
    liquidity_ratio=f'{100*liq/mc:.2f}%' if liq is not None and liq>=0 and mc is not None and mc>0 else '—'
    turnover=f'{volume/liq:.2f}×' if volume is not None and volume>=0 and liq is not None and liq>0 else '—'
    boosts=extra.get('boosts') if isinstance(extra.get('boosts'),dict) else {}
    created=number(extra.get('pairCreatedAt'))
    age=age_text(created/1000 if created else None,now)
    return ['', '⚡ <b>Actividad del par</b>',
            f'├ C/V 5m: <b>{transactions("m5")}</b>',
            f'├ C/V 1h: <b>{transactions("h1")}</b>',
            f'├ LIQ/MC: <b>{liquidity_ratio}</b>',
            f'├ VOL/LIQ 24h: <b>{turnover}</b>',
            f'├ Edad del par: <b>{age}</b>',
            f'└ Boosts DEX: <b>{count(boosts.get("active"))}</b>']


def card(mint, pair, fetched, info=None, gmgn_note=''):
    base=pair.get('baseToken') or {}
    info=info or pair.get('gmgn_info') or {}
    stat=info.get('stat') or {}
    dev=info.get('dev') or {}
    changes=pair.get('priceChange') or {}
    tx=(pair.get('txns') or {}).get('h24') or {}
    current=number(pair.get('priceUsd'))
    ath=number(info.get('ath_price'))
    chain=pair.get('chainId','solana')
    ratio=lambda v:fmt(v,ratio=True) if number(v) is not None and 0<=number(v)<=1 else '—'
    short=lambda v: (v[:6]+'…'+v[-4:]) if valid_contract(v) else '—'
    age=age_text(info.get('creation_timestamp'),fetched)
    name=esc(base.get('name','Token'),45)
    symbol=esc(base.get('symbol','?'),18)
    lines=[f'<b>{name} (${symbol})</b>',
           f'{esc(chain.title())} · {esc(pair.get("dexId","DEX"),25)} · 🌱 {age}', '',
           '📊 <b>Token Stats</b>',
           f'├ MC: <b>{compact(pair.get("marketCap"),True)}</b>',
           f'├ USD: <b>{fmt(current,money=True) if current is not None else "—"}</b>',
           f'├ LIQ: <b>{compact((pair.get("liquidity") or {}).get("usd"),True)}</b>',
           f'├ VOL: <b>{compact((pair.get("volume") or {}).get("h24"),True)}</b> (24h)',
           f'├ 5m: {change(changes.get("m5"))} · 1h: {change(changes.get("h1"))}',
           f'├ 24h: {change(changes.get("h24"))}',
           f'├ B/S: <b>{compact(tx.get("buys"))} / {compact(tx.get("sells"))}</b> (24h)',
           f'└ HLD: <b>{compact(info.get("holder_count"))}</b>', '',
           '🏔 <b>ATH</b>']
    lines=lines[:-2]+activity_lines(pair,fetched)+['','🏔 <b>ATH</b>']
    if ath is not None and ath>0 and (current is None or current<=ath):
        lines += [f'├ Precio: <b>{fmt(ath,money=True)}</b>',f'├ {ath_mc(info)}']
        drop=(current/ath-1)*100 if current is not None else None
        lines += [f'└ Desde ATH: {change(drop)}']
    else:
        lines += ['└ —']
    social=info.get('link') or {}
    links=[]
    for label,key in [('Web','website'),('TG','telegram'),('Discord','discord')]:
        link=safe_link(label,social.get(key))
        if link:links.append(link)
    username=social.get('twitter_username')
    if isinstance(username,str) and re.fullmatch(r'@?[A-Za-z0-9_]{1,15}',username):
        links.append(safe_link('X','https://x.com/'+username.lstrip('@')))
    if links: lines += ['', '🔗 <b>Socials</b>', ' · '.join(links)]
    lines += ['', '👥 <b>Distribución</b>',
              f'├ Top 10: <b>{ratio(stat.get("top_10_holder_rate"))}</b>',
              '├ '+pair.get('sniper_text','🎯 Snipers —').replace('🎯 ',''),
              '├ '+pair.get('bundler_text','Bundled —').replace('🎯 ',''),
              f'└ Equipo: {ratio(stat.get("dev_team_hold_rate"))}',
              '', f'P: <code>{short(pair.get("pairAddress"))}</code>',
              f'DEV: <code>{short(dev.get("creator_address"))}</code>',
              '',f'<code>{mint}</code>']
    return '\n'.join(lines)


def sources_text(pair, fetched, gmgn_note=''):
    lines = ['<b>Fuentes y alcance</b>', f'Mercado de esta ficha: {esc(pair.get("source","GMGN"))}. Red: {esc(pair.get("chainId","solana"))}. Imágenes: logo GMGN y alternativa DexScreener.',
             'Con GMGN: MC = precio × suministro circulante; FDV = precio × suministro total. Con DexScreener: valores reportados, sin sustituir MC por FDV.',
             'Precio y actividad: GMGN. Variaciones calculadas con sus precios al inicio de cada período. Liquidez del pool principal indicado por GMGN.',
             'Holders, Top 10 y etiquetas sniper: GMGN cuando está disponible. Una etiqueta no prueba que sea un bot.',
             'ATH de precio: reportado por GMGN. MC al precio ATH marcado ≈ es una estimación con suministro circulante actual, no el MC histórico. Snipers: suma de participaciones de holders etiquetados por GMGN, consulta limitada a 100 carteras; una lista de 100 es parcial.',
             'Actividad del par: C/V son cantidades de compras/ventas, no dólares ni personas únicas. Ventanas 5m y 1h, edad del par y boosts: DexScreener, solo para el mismo pool y red. Boosts son promoción, no garantía de calidad. LIQ/MC = liquidez / capitalización × 100; VOL/LIQ = volumen 24h / liquidez. Son relaciones descriptivas, no medidas de seguridad.',
             'Edad: fecha de creación del token según GMGN; no se sustituye por la edad del pool. Equipo: suministro en carteras etiquetadas como equipo. No se calcula una puntuación de auditoría ni se equipara volumen de bundlers con suministro retenido. Bubble Maps abre el mapa externo si el proyecto tiene cobertura.']
    created = number(pair.get('pairCreatedAt'))
    if created and 0 < created / 1000 <= time.time():
        lines.append(f'Creación del par (no del token): {stamp(created / 1000)}')
    if gmgn_note:
        lines.append(esc(gmgn_note, 300))
    lines += [f'Consulta de mercado: {stamp(fetched)}.',
              'La hora de consulta no garantiza la frescura del proveedor. — significa dato no disponible, nunca cero.']
    return '\n\n'.join(lines)


def holders_text(data, chain='solana'):
    rows = data.get('list')
    if not isinstance(rows, list):
        raise DataError('Lista de holders no disponible en GMGN.')
    lines = ['<b>Top holders · reportado por GMGN</b>']
    for index, row in enumerate(rows[:10], 1):
        addr = row.get('address')
        if not valid_contract(addr):
            continue
        kind = 'Exchange / pool' if row.get('addr_type') == 2 else 'Sin clasificar'
        lines.append(f'{index}. <code>{addr[:6]}…{addr[-4:]}</code> '
                     f'· {fmt(row.get("amount_percentage"), ratio=True)} · {fmt(row.get("balance"))} tokens · {kind}')
    if len(lines) == 1:
        lines.append('No hay filas válidas disponibles; no implica cero holders.')
    lines += ['', 'No se infiere que carteras relacionadas sean del mismo dueño. Clasificación del proveedor.',
              f'Consulta/caché de hasta 60 s · {stamp(time.time())}']
    return '\n'.join(lines)


HELP = ('<b>Miguelote Scan · Multired</b>\n'
        'Pega un contrato o utiliza /scan RED:CONTRATO. Ejemplo: base:0x…\n'
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
        logos = logo if isinstance(logo, list) else [logo]
        for logo in logos:
            if not isinstance(logo,str) or not logo.startswith('https://') or len(logo)>=2048:
                continue
            payload = {'chat_id': chat, 'photo': logo}
            fits = len(text.encode('utf-16-le')) // 2 <= 1024
            if fits:
                payload.update(caption=text, parse_mode='HTML', reply_markup=markup)
            try:
                result = self.api('sendPhoto', payload)
                if fits:
                    return result
                break
            except DataError:
                continue
        return self.send(chat, text, markup)

    def network_keyboard(self, chat, mint, pair, user):
        chain=self.scanner.chain
        ref=self.scanner.store.reference({'chat':chat,'mint':mint,'chain':chain})
        data='ref_'+ref
        markup=keyboard(mint,pair.get('pairAddress'),self.scanner.store.preference(user))
        for row in markup['inline_keyboard']:
            for button in row:
                if ':' in button.get('callback_data',''):
                    button['callback_data']=button['callback_data'].split(':')[0]+':'+data
        if chain=='solana':
            return markup
        q=urllib.parse.quote
        pool=pair.get('pairAddress')
        charts=[{'text':'DexScreener','url':f'https://dexscreener.com/{chain}/{q(pool or mint,safe="")}'}]
        dt={'ethereum':'ether','bsc':'bnb','base':'base','arbitrum':'arbitrum','avalanche':'avalanche','polygon':'polygon'}
        if pool and chain in dt:
            charts.append({'text':'DEXTools','url':f'https://www.dextools.io/app/en/{dt[chain]}/pair-explorer/{q(pool,safe="")}'})
        rows=[charts,markup['inline_keyboard'][2]]
        rows.append([{'text':'👥 Holders','callback_data':'holders:'+data}])
        if chain in GMGN_CHAINS:
            rows[-1].append({'text':'GMGN','url':f'https://gmgn.ai/{GMGN_CHAINS[chain]}/token/{mint}'})
        rows+=markup['inline_keyboard'][4:]
        return {'inline_keyboard':rows}

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
            elif valid_contract(text) or re.fullmatch(r'[a-z0-9-]+:[A-Za-z0-9]+',text):
                action, arg = 'scan', text
            else:
                candidates = re.findall(r'(?<![A-Za-z0-9])(?:0x[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?|[1-9A-HJ-NP-Za-km-z]{32,44})(?![A-Za-z0-9])', text)
                arg = next((x for x in candidates if valid_contract(x)), '')
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
        chain = None
        if arg.startswith('ref_'):
            ref=self.scanner.store.reference(key=arg[4:])
            if not ref or ref.get('chat') != chat:
                return self.send(chat,'Esta ficha ha caducado. Envía de nuevo el contrato.')
            chain,arg=ref['chain'],ref['mint']
        elif ':' in arg:
            chain,arg=arg.split(':',1)
            chain={'sol':'solana','eth':'ethereum','bnb':'bsc'}.get(chain.lower(),chain.lower())
        if not valid_contract(arg):
            return self.send(chat,'Formato no reconocido. Usa /scan RED:CONTRATO con la dirección completa.')
        arg=normalized(arg)
        self.scanner.chain='solana'
        try:
            if chain is None:
                if valid_address(arg):
                    chain='solana'
                else:
                    chains=sorted({p['chainId'] for p in self.scanner.dex_pairs(arg)})
                    if len(chains)==1:
                        chain=chains[0]
                    else:
                        choices=chains or list(GMGN_CHAINS.keys())[1:]
                        buttons=[]
                        for c in choices[:30]:
                            ref=self.scanner.store.reference({'chat':chat,'chain':c,'mint':arg})
                            buttons.append({'text':c.title(),'callback_data':action+':ref_'+ref})
                        return self.send(chat,'Elige la red del contrato:',{'inline_keyboard':[buttons[i:i+2] for i in range(0,len(buttons),2)]})
            if not re.fullmatch(r'[a-z0-9-]{1,40}',chain):
                raise DataError('Red no válida.')
            if chain=='solana' and not valid_address(arg):
                raise DataError('El contrato no tiene formato Solana.')
        except DataError as error:
            return self.send(chat,esc(str(error),500))
        self.scanner.chain=chain
        if time.monotonic() - self.last_request.get(user, -100) < 3:
            return self.send(chat, 'Espera unos segundos antes de la siguiente consulta.')
        self.last_request[user] = time.monotonic()
        try:
            if action == 'scan':
                pair, _, fetched = self.scanner.refresh_market(arg)
                pair = self.scanner.enrich_activity(arg,pair)
                info = pair['gmgn_info']
                try:
                    pair['sniper_text'] = self.scanner.current_snipers(arg)
                except DataError:
                    pair['sniper_text'] = '🎯 Snipers —'
                try:
                    pair['bundler_text']=self.scanner.current_tag_holdings(arg,'bundler')
                except DataError:
                    pair['bundler_text']='Bundled —'
                return self.send_card(chat, card(arg, pair, fetched, info),
                                      self.network_keyboard(chat,arg,pair,user), self.scanner.images(arg,info))
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
                return self.send(chat, holders_text(self.scanner.gmgn_query('holders', arg),chain))
            if action == 'snipers':
                return self.send(chat, self.scanner.current_snipers(arg) +
                                 '\nParticipación actual del suministro en carteras etiquetadas. GMGN: hasta 100 carteras; Aser: solo lecturas completas y recientes. No mide las compras al lanzamiento.\n' +
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
