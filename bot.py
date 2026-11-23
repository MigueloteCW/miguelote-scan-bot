"""Miguelote Scan: read-only multichain scanner. Python 3.11+, stdlib only."""
import argparse
import hashlib
import html
import http.client
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from decimal import Decimal
from email.utils import parsedate_to_datetime

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
NA = 'No disponible'
USER_AGENT = 'MigueloteScan/1.0'
# Índice SCAN: verde >= SCORE_OK, naranja >= SCORE_WARN, rojo por debajo.
# Veredicto, color y leyenda comparten estos cortes.
SCORE_OK = 70
SCORE_WARN = 40
CAPTION_LIMIT = 1024  # pie de foto de Telegram, en unidades UTF-16
CHAIN_ALIASES = {'sol': 'solana', 'eth': 'ethereum', 'bnb': 'bsc', 'bnbchain': 'bsc',
                 'arb': 'arbitrum', 'avax': 'avalanche', 'matic': 'polygon',
                 'poly': 'polygon', 'op': 'optimism'}

class DataError(Exception):
    pass


class RateLimitError(DataError):
    def __init__(self, message, retry_after=300):
        super().__init__(message)
        self.retry_after = retry_after


class TelegramRequestError(DataError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class DeliveryRetryError(DataError):
    """Telegram explicitly rejected a delivery with 429; safe to retry exactly it."""
    def __init__(self, method, payload, retry_after):
        super().__init__('Telegram solicita esperar antes de enviar.')
        self.retry_after = max(1, retry_after)
        self.steps = [{'method': method, 'payload': payload}]


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


def canonical_chain(value):
    value = str(value).lower()
    return CHAIN_ALIASES.get(value, value)


def network_contract(text):
    """True para `red:contrato` con un contrato válido (evita reaccionar a textos como 11:30)."""
    match = re.fullmatch(r'([A-Za-z0-9-]+):(\S+)', text)
    return bool(match and valid_contract(match.group(2)))


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


def fetch(url, payload=None, timeout=20, extra_headers=None):
    headers = {'User-Agent': USER_AGENT, 'Accept': 'application/json'}
    headers.update(extra_headers or {})
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
                    'api.telegram.org': 'Telegram',
                    'api.gopluslabs.io': 'GoPlus', 'api.honeypot.is': 'Honeypot.is',
                    'api.rugcheck.xyz': 'RugCheck'}.get(host, 'Proveedor')
        if host=='api.telegram.org' and error.code==400 and url.rsplit('/',1)[-1] in ('editMessageText','editMessageCaption'):
            try:
                detail=json.loads(error.read(16384)).get('description','')
                if 'message is not modified' in detail.lower():return {'ok':True,'result':True}
            except (ValueError,OSError,AttributeError):pass
        reasons = {400: 'petición no aceptada', 401: 'autenticación requerida',
                   403: 'acceso denegado', 404: 'recurso no encontrado', 409: 'conflicto: otra instancia o un webhook activo',
                   429: 'límite de consultas alcanzado'}
        if error.code == 429:
            delay = retry_delay((error.headers or {}).get('Retry-After'))
            if host == 'api.telegram.org':
                try:
                    body = json.loads(error.read(16384))
                    seconds = number((body.get('parameters') or {}).get('retry_after'))
                    if seconds is not None and seconds >= 0:
                        delay = max(1, seconds)
                except (ValueError, OSError, AttributeError, http.client.HTTPException):
                    pass
            raise RateLimitError(f'{provider}: HTTP 429 — límite de consultas alcanzado.', delay) from None
        reason = reasons.get(error.code, 'error del servicio')
        if host == 'api.telegram.org':
            raise TelegramRequestError(f'Telegram: HTTP {error.code} — {reason}.', error.code) from None
        raise DataError(f'{provider}: HTTP {error.code} — {reason}.') from None
    except (TimeoutError, urllib.error.URLError, OSError, http.client.HTTPException):
        if urllib.parse.urlsplit(url).hostname == 'api.telegram.org':
            raise TelegramRequestError('Telegram no confirmó el resultado de la petición.') from None
        raise DataError('No se pudo conectar con el proveedor o se agotó el tiempo de espera.') from None
    except ValueError:
        if urllib.parse.urlsplit(url).hostname == 'api.telegram.org':
            raise TelegramRequestError('Telegram devolvió una respuesta no válida.') from None
        raise DataError('El proveedor devolvió una respuesta no válida.') from None


class Store:
    def __init__(self, path='veraz.sqlite3'):
        # check_same_thread=False: el acceso se serializa con self.lock (webhook con hilos).
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        with self.lock:
            self.db.execute('CREATE TABLE IF NOT EXISTS preferences (user INTEGER PRIMARY KEY, provider TEXT)')
            self.db.execute('CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT)')
            if 'updated' not in {row[1] for row in self.db.execute('PRAGMA table_info(state)')}:
                # Bases creadas por versiones anteriores: añade la marca de tiempo.
                self.db.execute('ALTER TABLE state ADD COLUMN updated REAL')
                self.db.execute('UPDATE state SET updated=?', (time.time(),))
            self.db.commit()
        self.prune()

    def put(self, key, value):
        with self.lock:
            self.db.execute('INSERT OR REPLACE INTO state(key,value,updated) VALUES (?,?,?)', (key, value, time.time()))
            self.db.commit()

    def delete(self, key):
        with self.lock:
            self.db.execute('DELETE FROM state WHERE key=?', (key,))
            self.db.commit()

    def get(self, key):
        with self.lock:
            row = self.db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return row[0] if row else None

    def prune(self, days=30):
        """Borra referencias y snapshots de botones con más de `days` días."""
        with self.lock:
            self.db.execute("DELETE FROM state WHERE (key LIKE 'ref:%' OR key LIKE 'card:%') AND updated < ?",
                            (time.time() - days * 86400,))
            self.db.commit()

    def reference(self, data=None, key=None):
        if data is not None:
            value = json.dumps(data, sort_keys=True)
            key = hashlib.sha256(value.encode()).hexdigest()[:20]
            self.put('ref:' + key, value)
            return key
        value = self.get('ref:' + str(key))
        return json.loads(value) if value else None

    def card_snapshot(self, chat, message_id, value=None):
        key = f'card:{chat}:{message_id}'
        if value is not None:
            self.put(key, json.dumps(value))
            return None
        value = self.get(key)
        return json.loads(value) if value else None

    def preference(self, user, provider=None):
        if provider is not None:
            if provider not in ('dexscreener', 'dextools'):
                raise ValueError('Proveedor incorrecto')
            with self.lock:
                self.db.execute('INSERT OR REPLACE INTO preferences VALUES (?,?)', (user, provider))
                self.db.commit()
        with self.lock:
            row = self.db.execute('SELECT provider FROM preferences WHERE user=?', (user,)).fetchone()
        return row[0] if row else 'dexscreener'

    def offset(self, value=None):
        if value is not None:
            self.put('offset', str(value))
        value = self.get('offset')
        return int(value) if value else 0


class Scanner:
    def __init__(self, store, transport=fetch, gmgn=False):
        self.store, self.transport, self.gmgn = store, transport, gmgn
        self.cache = {}
        self.gmgn_blocked_until = 0
        self.gmgn_neg = {}        # consultas auxiliares fallidas: (clave) -> instante
        self.gmgn_aux_fails = 0   # fallos auxiliares consecutivos
        self.chain = "solana"
        self.dex_lock = threading.RLock()
        self.gmgn_lock = threading.RLock()

    def prune(self, max_age=3600, limit=1500):
        """Acota la caché en memoria: descarta entradas antiguas cuando crece demasiado."""
        now = time.time()
        if len(self.gmgn_neg) > 500:
            self.gmgn_neg = dict(sorted(((k, v) for k, v in self.gmgn_neg.items() if now - v < 60), key=lambda item: item[1])[-500:])
        if len(self.cache) <= limit:
            return
        entries = [(value[0], key) for key, value in list(self.cache.items())
                   if isinstance(value, tuple) and value and isinstance(value[0], (int, float))]
        for fetched, key in entries:
            if now - fetched > max_age:
                self.cache.pop(key, None)
        for _, key in sorted(entries, key=lambda item: item[0]):
            if len(self.cache) <= limit:
                break
            self.cache.pop(key, None)

    def search_ticker(self,ticker):
        ticker=ticker.lstrip('$').upper()
        if not re.fullmatch(r'[A-Z][A-Z0-9_]{0,19}',ticker):raise DataError('Ticker no válido.')
        key=('ticker',ticker)
        if key in self.cache and time.time()-self.cache[key][0]<30:return self.cache[key][1]
        data=self.transport('https://api.dexscreener.com/latest/dex/search?q='+urllib.parse.quote(ticker,safe=''))
        rows=data.get('pairs') if isinstance(data,dict) else None
        if not isinstance(rows,list):raise DataError('No se pudo buscar el ticker. Prueba con el contrato.')
        found={}
        for row in rows:
            if not isinstance(row,dict):continue
            token=row.get('baseToken') or {}
            chain=row.get('chainId')
            if not isinstance(token,dict) or str(token.get('symbol','')).lstrip('$').upper()!=ticker:continue
            address=token.get('address')
            if not valid_contract(address) or not isinstance(chain,str) or not re.fullmatch(r'[a-z0-9-]{1,40}',chain):continue
            identity=(chain,normalized(address))
            liquidity=number((row.get('liquidity') or {}).get('usd')) or 0
            if identity not in found or liquidity>found[identity]['liquidity']:
                found[identity]={'chain':chain,'mint':normalized(address),'name':str(token.get('name') or ticker),'symbol':ticker,'liquidity':liquidity}
        results=sorted(found.values(),key=lambda x:(-x['liquidity'],x['chain'],x['mint']))
        self.cache[key]=(time.time(),results)
        return results

    def provider_security(self, source, chain, mint, force=False):
        key = ('security_negative', source, chain, normalized(mint))
        hit = self.cache.get(key)
        if hit and time.time() - hit[0] < 30:
            raise DataError('Consulta de seguridad temporalmente no disponible.')
        try:
            return self._provider_security(source, chain, mint, force)
        except DataError:
            self.cache[key] = (time.time(), None)
            raise

    def _provider_security(self, source, chain, mint, force=False):
        """Fixed read-only security endpoints. Missing results never mean 0% or safe."""
        key=('security',source,chain,normalized(mint))
        if not force and key in self.cache and time.time()-self.cache[key][0]<90:
            return self.cache[key][1]
        if not valid_contract(mint):
            raise DataError('Contrato no válido para el escáner.')
        address=urllib.parse.quote(mint, safe='')
        chain_ids={'ethereum':1,'bsc':56,'base':8453,'arbitrum':42161,
                   'polygon':137,'avalanche':43114,'optimism':10}
        if source=='goplus':
            if chain=='solana' and valid_address(mint):
                url='https://api.gopluslabs.io/api/v1/solana/token_security?contract_addresses='+address
            elif chain in chain_ids and re.fullmatch(r'0x[0-9a-fA-F]{40}',mint):
                url=f'https://api.gopluslabs.io/api/v1/token_security/{chain_ids[chain]}?contract_addresses={address}'
            else:
                raise DataError('GoPlus sin cobertura confirmada para esta combinación red/contrato.')
            key_value=os.environ.get('GOPLUS_ACCESS_TOKEN','').strip()
            headers={'Authorization':'Bearer '+key_value} if key_value else None
            data=(fetch(url,timeout=10,extra_headers=headers) if self.transport is fetch else self.transport(url))
            if not isinstance(data,dict) or str(data.get('code'))!='1':
                raise DataError('GoPlus no devolvió información de seguridad válida.')
            result=data.get('result')
            if not isinstance(result,dict):raise DataError('GoPlus devolvió un resultado vacío.')
            # Never display data for a different token even if the response has one entry.
            match=next((v for k,v in result.items() if same_token(k,mint) and isinstance(v,dict)),None)
            if match is None:raise DataError('GoPlus no confirmó este contrato en la red.')
        elif source=='honeypot':
            if chain not in ('ethereum','bsc','base') or not re.fullmatch(r'0x[0-9a-fA-F]{40}',mint):
                raise DataError('Honeypot.is no verifica esta red.')
            cid={'ethereum':1,'bsc':56,'base':8453}[chain]
            url=f'https://api.honeypot.is/v2/IsHoneypot?address={address}&chainID={cid}'
            data=(fetch(url,timeout=10) if self.transport is fetch else self.transport(url))
            if not isinstance(data,dict) or not isinstance(data.get('token'),dict) or not same_token(data['token'].get('address'),mint):
                raise DataError('Honeypot.is no confirmó el contrato consultado.')
            match=data
        elif source=='rugcheck':
            if chain!='solana' or not valid_address(mint):
                raise DataError('RugCheck solo se consulta para tokens de Solana.')
            url=f'https://api.rugcheck.xyz/v1/tokens/{address}/report/summary'
            match=(fetch(url,timeout=10) if self.transport is fetch else self.transport(url))
            if not isinstance(match,dict) or not any(k in match for k in ('risks','score','lpLockedPct','tokenProgram')):
                raise DataError('RugCheck no devolvió un informe verificable.')
        else:
            raise DataError('Proveedor desconocido.')
        self.cache[key]=(time.time(),match)
        return match

    def security_evidence(self,chain,mint,deep=False,force=False):
        """Gather supported providers separately, preserving partial failures."""
        sources={}
        try:sources['GoPlus']=self.provider_security('goplus',chain,mint,force)
        except DataError:pass
        # The full scan consults a second independent service. On EVM cards,
        # Honeypot.is is a TAX fallback when GoPlus omits either rate.
        hp_chains=('ethereum','bsc','base')
        missing_tax=(evm_rate((sources.get('GoPlus') or {}).get('buy_tax')) is None or
                     evm_rate((sources.get('GoPlus') or {}).get('sell_tax')) is None)
        if chain=='solana' and deep:
            try:sources['RugCheck']=self.provider_security('rugcheck',chain,mint,force)
            except DataError:pass
        elif chain in hp_chains and (deep or missing_tax):
            try:sources['Honeypot.is']=self.provider_security('honeypot',chain,mint,force)
            except DataError:pass
        return sources

    def dex_pairs(self, mint):
        # Images and activity share the same lookup, including when running concurrently.
        with self.dex_lock:
            return self._dex_pairs(mint)

    def _dex_pairs(self, mint):
        key=('dex', normalized(mint))
        if key in self.cache and time.time()-self.cache[key][0]<60:
            return self.cache[key][1]
        if time.time()<self.cache.get(('dex_pause',),0):
            raise DataError('DexScreener en pausa temporal por límite de consultas.')
        try:
            data=self.transport('https://api.dexscreener.com/latest/dex/search?q='+urllib.parse.quote(mint,safe=''), timeout=6)
        except RateLimitError as error:
            self.cache[('dex_pause',)]=time.time()+error.retry_after
            raise
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
            result=self.transport('https://aser.trade/api/'+key[1]+'/'+urllib.parse.quote(mint,safe=''), timeout=5)
            item=result if live else result.get('token')
            if not isinstance(item,dict) or item.get('mint')!=mint:raise DataError('Aser no confirmó el contrato.')
            self.cache[key]=(time.time(),item)
            return item
        except (DataError,AttributeError,TypeError):
            self.cache[key]=(time.time(),None)
            raise DataError('Aser no disponible.') from None

    def aser_signals(self, mint):
        if self.chain!='solana':
            raise DataError('ASER: señales disponibles solo para Solana.')
        api_key=os.environ.get('ASER_API_KEY','').strip()
        if not api_key:
            raise DataError('ASER: falta configurar ASER_API_KEY en Render.')
        if not valid_address(mint):raise DataError('Contrato Solana no válido.')
        key=('aser','signals',mint)
        cached=self.cache.get(key)
        if cached and time.time()-cached[0]<60:return cached[1]
        if time.time()<self.cache.get(('aser_signals_pause',),0):
            raise DataError('ASER: consulta temporalmente no disponible.')
        url='https://aser.trade/aser/api/v1/signals/'+urllib.parse.quote(mint,safe='')
        try:
            data=self.transport(url,timeout=6,extra_headers={'Authorization':'Bearer '+api_key})
            if not isinstance(data,dict) or data.get('mint')!=mint:
                raise DataError('ASER no confirmó el contrato solicitado.')
            for field in ('signals','theses'):
                if not isinstance(data.get(field),list) or any(not isinstance(row,dict) for row in data[field]):
                    raise DataError('ASER devolvió un historial incompleto.')
                for row in data[field]:
                    if row.get('mint') not in (None,mint):raise DataError('ASER devolvió otro contrato.')
            self.cache[key]=(time.time(),data)
            return data
        except RateLimitError as error:
            self.cache[('aser_signals_pause',)]=time.time()+max(60,error.retry_after)
            raise DataError('ASER: límite de consultas; se reintentará más tarde.') from None
        except DataError:
            self.cache[('aser_signals_pause',)]=time.time()+60
            raise

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
            for row in rows:
                meta=row.get('info') or {}
                urls.extend([meta.get('header'),meta.get('imageUrl')])
        except DataError:
            pass
        return list(dict.fromkeys(u for u in urls if image_url(u)))[:6]

    def rank_images(self,urls):
        urls=list(dict.fromkeys(u for u in urls if image_url(u)))[:10]
        def measure(url):
            key=('image_size',url);hit=self.cache.get(key)
            if hit and time.time()-hit[0]<(3600 if hit[1] else 120):return hit[1]
            size=probe_image_size(url)
            self.cache[key]=(time.time(),size)
            return size
        if not urls:return [],False
        with ThreadPoolExecutor(max_workers=6) as pool:
            sizes=list(pool.map(measure,urls))
        ranked=sorted(zip(urls,sizes),key=lambda item:image_quality(item[1]),reverse=True)
        return [u for u,_ in ranked],any(image_quality(size)[0]>=2 for size in sizes)

    def extra_images(self,mint):
        # Fallback metadata is cached independently from live market refreshes.
        key=('image_metadata',self.chain,normalized(mint))
        hit=self.cache.get(key)
        if hit and time.time()-hit[0]<(3600 if hit[1] else 120):return hit[1]
        urls=[]
        networks={'solana':'solana','ethereum':'eth','bsc':'bsc','base':'base',
                  'arbitrum':'arbitrum','polygon':'polygon_pos','avalanche':'avax',
                  'optimism':'optimism','fantom':'ftm','ton':'ton','sui':'sui',
                  'tron':'tron','hyperevm':'hyperevm'}
        network=networks.get(self.chain)
        if network and time.time()>=self.cache.get(('image_gt_pause',),0):
            try:
                data=self.transport('https://api.geckoterminal.com/api/v2/networks/'+network+'/tokens/'+urllib.parse.quote(mint,safe='')+'/info',timeout=5)
                token=data.get('data') if isinstance(data,dict) else None
                attr=token.get('attributes') if isinstance(token,dict) else None
                if isinstance(attr,dict) and same_token(attr.get('address'),mint) and isinstance(token.get('id'),str) and token['id'].startswith(network+'_') and same_token(token['id'][len(network)+1:],mint):
                    sizes=attr.get('image') if isinstance(attr.get('image'),dict) else {}
                    urls.extend([attr.get('banner_image_url'),sizes.get('large'),attr.get('image_url')])
            except RateLimitError as error:
                self.cache[('image_gt_pause',)]=time.time()+error.retry_after
            except DataError:pass
        # Recent profiles are only a fallback, never a complete token directory.
        if not any(image_url(u) for u in urls) and time.time()>=self.cache.get(('dex_pause',),0):
            profiles=self.cache.get(('image_dex_profiles',))
            if not profiles or time.time()-profiles[0]>=300:
                try:
                    data=self.transport('https://api.dexscreener.com/token-profiles/latest/v1',timeout=5)
                    profiles=(time.time(),data if isinstance(data,list) else [])
                    self.cache[('image_dex_profiles',)]=profiles
                except RateLimitError as error:
                    self.cache[('dex_pause',)]=time.time()+error.retry_after
                    profiles=None
                except DataError:
                    profiles=(time.time(),[])
                    self.cache[('image_dex_profiles',)]=profiles
            for row in (profiles[1] if profiles else []):
                if isinstance(row,dict) and row.get('chainId')==self.chain and same_token(row.get('tokenAddress'),mint):
                    urls.extend([row.get('header'),row.get('icon')])
        result=list(dict.fromkeys(u for u in urls if image_url(u)))[:4]
        self.cache[key]=(time.time(),result)
        return result

    def refresh_market(self,mint):
        for key in list(self.cache):
            if len(key)>=3 and (key[0]=='gmgn' or key[:2] in (('aser','signals'),('aser','coin'))) and key[-1]==normalized(mint):
                self.cache.pop(key,None)
        for key in list(self.gmgn_neg):
            if key[-1]==normalized(mint):
                self.gmgn_neg.pop(key,None)
        self.cache.pop(('dex',normalized(mint)),None)
        self.cache.pop(('gecko_market',self.chain,normalized(mint)),None)
        return self.market(mint)

    def gecko_market(self,mint):
        networks={'solana':'solana','ethereum':'eth','bsc':'bsc','base':'base',
                  'arbitrum':'arbitrum','polygon':'polygon_pos','avalanche':'avax',
                  'optimism':'optimism','fantom':'ftm','ton':'ton','sui':'sui',
                  'tron':'tron','hyperevm':'hyperevm'}
        network=networks.get(self.chain)
        if not network:raise DataError('Red sin cobertura de reserva.')
        key=('gecko_market',self.chain,normalized(mint))
        hit=self.cache.get(key)
        if hit and time.time()-hit[0]<30:return hit[1],hit[2],hit[0]
        if time.time()<self.cache.get(('gecko_market_pause',),0):
            raise DataError('Mercado de reserva temporalmente limitado.')
        try:
            data=self.transport('https://api.geckoterminal.com/api/v2/networks/'+network+'/tokens/'+urllib.parse.quote(mint,safe='')+'/pools?include=base_token,quote_token',timeout=8)
        except RateLimitError as error:
            self.cache[('gecko_market_pause',)]=time.time()+error.retry_after
            raise
        if not isinstance(data,dict):raise DataError('Respuesta de mercado no válida.')
        tokens={t.get('id'):t.get('attributes',{}) for t in (data.get('included') or []) if isinstance(t,dict) and t.get('type')=='token'}
        rows=[]
        for pool in data.get('data') or []:
            if not isinstance(pool,dict):continue
            attr=pool.get('attributes') or {};rel=pool.get('relationships') or {}
            token_id=((rel.get('base_token') or {}).get('data') or {}).get('id','')
            token=tokens.get(token_id) or {}
            # Pool metrics are for the base token. Never relabel quote-token metrics.
            if not token_id.startswith(network+'_') or not same_token(token_id[len(network)+1:],mint) or not same_token(token.get('address'),mint):continue
            if not str(pool.get('id','')).startswith(network+'_'):continue
            price=number(attr.get('base_token_price_usd'))
            if price is None or price<=0:continue
            rows.append({'chainId':self.chain,'pairAddress':attr.get('address'),
                'dexId':((rel.get('dex') or {}).get('data') or {}).get('id'),
                'baseToken':{'address':mint,'name':token.get('name'),'symbol':token.get('symbol')},
                'priceUsd':price,'marketCap':number(attr.get('market_cap_usd')),
                'fdv':number(attr.get('fdv_usd')),'liquidity':{'usd':number(attr.get('reserve_in_usd'))},
                'volume':attr.get('volume_usd') or {},'priceChange':attr.get('price_change_percentage') or {},
                'txns':attr.get('transactions') or {},'gmgn_info':{'logo':token.get('image_url')},
                'source':'GeckoTerminal'})
        if not rows:raise DataError('Sin mercado verificado para este contrato y red.')
        pair=max(rows,key=lambda p:number(p['liquidity']['usd']) or 0)
        stamp=time.time();self.cache[key]=(stamp,pair,rows)
        return pair,rows,stamp

    def market(self, mint):
        try:
            return self.gmgn_market(mint)
        except DataError as error:
            gmgn_error = str(error)
        try:
            rows=[p for p in self.dex_pairs(mint) if p['chainId']==self.chain]
            if rows:
                pair=dict(max(rows,key=lambda p:number((p.get('liquidity') or {}).get('usd')) or 0))
                pair.update(gmgn_info={},source='DexScreener',gmgn_error=gmgn_error)
                return pair,rows,self.cache[('dex',normalized(mint))][0]
        except DataError:pass
        try:
            pair, rows, fetched = self.gecko_market(mint)
            pair = dict(pair, gmgn_error=gmgn_error)
            return pair, rows, fetched
        except DataError:
            raise DataError('No se pudo obtener el mercado de este contrato en '+self.chain+'. Los proveedores no responden o no tienen cobertura. Reinténtalo más tarde.') from None

    def enrich_activity(self,mint,pair):
        # Enrich only the selected pool on the selected chain; never a different market.
        result=dict(pair)
        try:
            matches=[p for p in self.dex_pairs(mint)
                     if p.get('chainId')==pair.get('chainId')
                     and pair.get('pairAddress') and same_token(p.get('pairAddress'),pair['pairAddress'])]
            if matches:
                row=matches[0]
                result['activity_extra']={k:row.get(k) for k in ('txns','boosts','pairCreatedAt','info')}
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
        pair = {'baseToken': {'name': info.get('name') or 'Token', 'symbol': info.get('symbol') or '?'},
                'pairAddress': address if valid_contract(address) else None,
                'chainId': self.chain, 'source': 'GMGN',
                'dexId': pool.get('exchange') or 'GMGN', 'priceUsd': current,
                'marketCap': product(info.get('circulating_supply')), 'fdv': product(info.get('total_supply')),
                'liquidity': {'usd': info.get('liquidity') if info.get('liquidity') is not None else pool.get('liquidity')},
                'volume': {'h24': price.get('volume_24h')}, 'priceChange': changes,
                'txns': {'h24': {'buys': price.get('buys_24h'), 'sells': price.get('sells_24h')}},
                'gmgn_info': info}
        fetched = self.cache.get(('gmgn', self.chain, 'info', normalized(mint)), (time.time(),))[0]
        return pair, [pair], fetched

    def gmgn_query(self, command, mint, wallet=None):
        # CLI processes are CPU-heavy on small instances: keep GMGN serialized.
        # Independent HTTP providers still run concurrently.
        with self.gmgn_lock:
            return self._gmgn_query(command, mint, wallet)

    def _gmgn_query(self, command, mint, wallet=None):
        if not valid_contract(mint) or self.chain not in GMGN_CHAINS:
            raise DataError('Sin cobertura de GMGN para esta red.')
        if not self.gmgn:
            raise DataError('GMGN pendiente de configurar: hace falta su clave API de consulta.')
        if command=='dev_sales' and not valid_contract(wallet):raise DataError('Cartera DEV no identificada.')
        key = ('gmgn', self.chain, command, normalized(wallet), normalized(mint)) if command=='dev_sales' else ('gmgn', self.chain, command, normalized(mint))
        if key in self.cache and time.time() - self.cache[key][0] < 60:
            return self.cache[key][1]
        if time.time() - self.gmgn_neg.get(key, 0) < 60:
            raise DataError('GMGN no devolvió datos para esta consulta hace instantes; reintento en breve.')
        if time.time() < self.gmgn_blocked_until:
            raise DataError('GMGN en pausa por límite de consultas; vuelve a intentarlo más tarde.')
        if not shutil.which('gmgn-cli'):
            raise DataError('Falta instalar gmgn-cli en el equipo del bot.')
        args = ['gmgn-cli', 'token', 'holders' if command in ('sniper_holders','bundler_holders') else command, '--chain', GMGN_CHAINS[self.chain], '--address', mint, '--raw']
        if command=='dev_sales':
            args=['gmgn-cli','portfolio','activity','--chain',GMGN_CHAINS[self.chain],'--wallet',wallet,'--token',mint,'--type','sell','--limit','1','--raw']
        if command in ('sniper_holders','bundler_holders'):
            args += ['--tag', 'sniper' if command=='sniper_holders' else 'bundler', '--limit', '100', '--order-by', 'amount_percentage', '--direction', 'desc']
        if command == 'holders':
            args += ['--limit', '10', '--order-by', 'amount_percentage', '--direction', 'desc']
        with self.gmgn_lock:
            delay = 1.1 - (time.monotonic() - self.cache.get(('gmgn_last',), 0))
            if delay > 0:
                time.sleep(delay)
            if time.time() < self.gmgn_blocked_until:
                raise DataError('GMGN en pausa temporal por cuota.')
            self.cache[('gmgn_last',)] = time.monotonic()
        def fail(message, limited=False):
            print('GMGN ' + command + ': ' + message, flush=True)
            self.gmgn_neg[key] = time.time()
            if limited:
                self.gmgn_blocked_until = time.time() + 300
                raise DataError(message + ' Pausa de 5 minutos.') from None
            # A token/endpoint failure must not disable unrelated tokens and endpoints.
            raise DataError(message) from None

        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=25, check=False)
        except subprocess.TimeoutExpired:
            fail('GMGN superó el tiempo de espera de 25 segundos.')
        except (OSError, ValueError):
            fail('No se pudo ejecutar la consulta de GMGN.')
        if proc.returncode:
            report = (proc.stderr or '') + ' ' + (proc.stdout or '')[:500]
            fail('GMGN no devolvió datos: revisa clave, permisos y cuota gratuita.',
                 limited=bool(re.search(r'429|rate.?limit|too many|quota', report, re.I)))
        try:
            data = json.loads(proc.stdout)
        except ValueError:
            fail('Formato GMGN no reconocido.')
        if not isinstance(data, dict):
            fail('Formato GMGN no reconocido.')
        if data.get('code') not in (None, 0, '0', 200, '200') or data.get('success') is False:
            fail('GMGN rechazó la consulta.',
                 limited=bool(re.search(r'429|limit', str(data.get('message') or data.get('msg') or ''), re.I)))
        data = data.get('data', data)
        if not isinstance(data, dict):
            fail('Formato GMGN no reconocido.')
        self.gmgn_aux_fails = 0
        self.cache[key] = (time.time(), data)
        return data

    def dev_sell(self,mint,info):
        dev=info.get('dev') if isinstance(info.get('dev'),dict) else {}
        creator=dev.get('creator_address')
        if not valid_contract(creator):return '⚪ Sin verificar'
        # Only the documented token-info "sell" status indicates a sale.
        # "hold", zero balance and "creator_close" do not prove absence/presence of sales.
        if dev.get('creator_token_status')=='sell':return '🔴 Sí'
        try:data=self.gmgn_query('dev_sales',mint,wallet=creator)
        except DataError:return '⚪ Sin verificar'
        rows=data.get('activities')
        if not isinstance(rows,list):return '⚪ Sin verificar'
        for row in rows:
            if not isinstance(row,dict):continue
            token=row.get('token') or {}
            if isinstance(token,dict) and same_token(token.get('address'),mint) and (row.get('event_type') or row.get('type'))=='sell' and row.get('tx_hash'):
                return '🔴 Sí'
        if not rows and 'next' in data and data['next'] in (None,''):
            return '🟢 No detectado'
        return '⚪ Sin verificar'

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

    def dex_paid(self, chain, mint):
        key=('dex_paid',chain,mint)
        cached=self.cache.get(key)
        if cached and time.time()-cached[0]<60:
            return cached[1]
        if time.time()<self.cache.get(('orders_pause',),0):
            return None
        try:
            data=self.transport('https://api.dexscreener.com/orders/v1/'+urllib.parse.quote(chain,safe='')+'/'+urllib.parse.quote(mint,safe=''),timeout=4)
            rows=data.get('orders') if isinstance(data,dict) else data
            if not isinstance(rows,list) or not all(isinstance(r,dict) and r.get('type') and r.get('status') for r in rows):
                return None
            states={r['status'] for r in rows if r['type']=='tokenProfile'}
            result=True if 'approved' in states else (None if states-{'rejected','cancelled'} else False)
            self.cache[key]=(time.time(),result)
            return result
        except RateLimitError as error:
            self.cache[('orders_pause',)]=time.time()+max(60,error.retry_after)
            return None

    def card_inputs(self, mint, pair, refreshing=False):
        info = pair.get('gmgn_info') or {}
        chain = self.chain
        jobs = {
            'activity': (lambda: self.enrich_activity(mint, pair), dict(pair)),
            'dex_paid': (lambda: self.dex_paid(chain,mint), None),
            'sniper_text': (lambda: self.current_snipers(mint), '🎯 Snipers —'),
            'bundler_text': (lambda: self.current_tag_holdings(mint, 'bundler'), 'Bundled —'),
            'dev_sell_text': (lambda: self.dev_sell(mint, info), '⚪ Sin verificar'),
        }
        if chain == 'solana':
            jobs['aser_signals'] = (lambda: self.aser_signals(mint), None)
        if not refreshing:
            jobs['images'] = (lambda: self.rank_images(self.images(mint, info))[0], [])
        results = {}
        with ThreadPoolExecutor(max_workers=7) as pool:
            pending = {name: pool.submit(fn) for name, (fn, _) in jobs.items()}
            for name, future in pending.items():
                try:
                    results[name] = future.result()
                except Exception as error:
                    print('Consulta opcional fallida: ' + name + ' (' + type(error).__name__ + ')', flush=True)
                    results[name] = jobs[name][1]
        result = dict(results['activity'])
        result.update({key: results[key] for key in ('sniper_text', 'bundler_text', 'dev_sell_text')})
        result['dex_paid'] = results['dex_paid']
        if results.get('aser_signals') is not None:
            result['aser_signals'] = results['aser_signals']
        else:
            result.pop('aser_signals', None)
        return result, results.get('images', [])

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


# Verified tax data is deliberately distinct from DEX pool fees and slippage.
def known_flag(value):
    if isinstance(value,dict):value=value.get('status')
    if value in (True,1,'1'):return True
    if value in (False,0,'0'):return False
    return None


def evm_rate(value):
    """GoPlus EVM rates are fractions (1 == 100%); blank is unknown."""
    n=number(value)
    return n*100 if n is not None and 0<=n<=1 else None


def percentage(n):
    return ('{:.2f}'.format(n).rstrip('0').rstrip('.'))+'%' if n is not None else '—'


def tax_details(chain, sources):
    gp=sources.get('GoPlus') or {}
    hp=sources.get('Honeypot.is') or {}
    if chain=='solana':
        transfer=gp.get('transfer_fee') if isinstance(gp.get('transfer_fee'),dict) else {}
        current=transfer.get('current_fee_rate') if isinstance(transfer.get('current_fee_rate'),dict) else {}
        basis=number(current.get('fee_rate'))
        fee=basis/100 if basis is not None and 0<=basis<=10000 else None
        scheduled=transfer.get('scheduled_fee_rate') if isinstance(transfer.get('scheduled_fee_rate'),dict) else {}
        planned=number(scheduled.get('fee_rate'))
        return {'buy':None,'sell':None,'transfer':fee,'source':'GoPlus' if fee is not None else None,
                'scheduled':planned/100 if planned is not None and 0<=planned<=10000 else None}
    buy,sell=evm_rate(gp.get('buy_tax')),evm_rate(gp.get('sell_tax'))
    source='GoPlus' if buy is not None or sell is not None else None
    sim=hp.get('simulationResult') if isinstance(hp.get('simulationResult'),dict) else {}
    # Honeypot.is simulated values are already percentages, unlike GoPlus fractions.
    def hp_rate(v):
        n=number(v)
        return n if n is not None and 0<=n<=100 else None
    hb,hs=hp_rate(sim.get('buyTax')),hp_rate(sim.get('sellTax'))
    mismatch=(buy is not None and hb is not None and abs(buy-hb)>=3) or (sell is not None and hs is not None and abs(sell-hs)>=3)
    if buy is None:buy=hb
    if sell is None:sell=hs
    if source is None and (buy is not None or sell is not None):source='Honeypot.is'
    return {'buy':buy,'sell':sell,'transfer':None,'source':source,'mismatch':mismatch,
            'honeypot_buy':hb,'honeypot_sell':hs}


def security_assessment(chain,sources,market=None):
    """Conservative heuristic, *not* a financial recommendation or an audit."""
    flags=[]
    evidence=0
    critical=False
    def mark(label,penalty=15,urgent=False):
        nonlocal critical
        if label not in [item[0] for item in flags]:flags.append((label,penalty))
        critical=critical or urgent
    gp=sources.get('GoPlus') or {}
    hp=sources.get('Honeypot.is') or {}
    rug=sources.get('RugCheck') or {}
    if gp:
        if chain=='solana':
            checks=[('mintable','Puede emitir más tokens',22),('freezable','Puede congelar cuentas',28),
                    ('closable','Autoridad para cerrar el programa',35),
                    ('balance_mutable_authority','Puede modificar balances',50),
                    ('transfer_fee_upgradable','Comisión modificable',26),
                    ('default_account_state_upgradable','Restricciones de cuentas modificables',18),
                    ('transfer_hook_upgradable','Hook de transferencia modificable',26)]
            for key,label,penalty in checks:
                val=known_flag(gp.get(key))
                if val is not None:
                    evidence+=1
                    if val:mark(label,penalty,penalty>=35)
            if known_flag(gp.get('non_transferable')) is not None:
                evidence+=1
                if known_flag(gp.get('non_transferable')):mark('Token no transferible',65,True)
            state=str(gp.get('default_account_state',''))
            if state in ('1','2'):
                evidence+=1
                if state=='2':mark('Cuentas congeladas por defecto',60,True)
            hook=gp.get('transfer_hook')
            if isinstance(hook,dict) and hook.get('address'):
                evidence+=1
                mark('Transferencias con programa externo',20)
        else:
            checks=[('is_honeypot','Honeypot detectado por GoPlus',80),
                    ('cannot_buy','Restricciones para comprar',35),
                    ('cannot_sell_all','No permite vender el 100%',40),
                    ('is_mintable','Puede emitir más tokens',24),
                    ('hidden_owner','Propietario oculto',30),
                    ('owner_change_balance','Puede cambiar balances',60),
                    ('transfer_pausable','Transferencias pausables',30),
                    ('slippage_modifiable','TAX modificable',28),
                    ('is_blacklisted','Posibilidad de lista negra',22),
                    ('is_proxy','Contrato actualizable mediante proxy',15)]
            for key,label,penalty in checks:
                val=known_flag(gp.get(key))
                if val is not None:
                    evidence+=1
                    if val:mark(label,penalty,penalty>=40)
            if known_flag(gp.get('is_open_source')) is not None:
                evidence+=1
                if known_flag(gp.get('is_open_source')) is False:mark('Código fuente no verificado',28)
    hp_state=(hp.get('honeypotResult') or {}) if isinstance(hp.get('honeypotResult'),dict) else {}
    if known_flag(hp_state.get('isHoneypot')) is not None:
        evidence+=1
        if known_flag(hp_state['isHoneypot']):mark('Honeypot detectado por simulación',85,True)
    risk_list=rug.get('risks') if isinstance(rug.get('risks'),list) else []
    if rug:
        evidence+=1
        for risk in risk_list[:6]:
            if not isinstance(risk,dict):continue
            level=str(risk.get('level','')).lower()
            if level not in ('danger','warn','warning','critical'):continue
            p=32 if level in ('danger','critical') else 15
            mark('RugCheck: '+str(risk.get('name') or 'riesgo detectado')[:65],p,level in ('danger','critical'))
    tax=tax_details(chain,sources)
    for side in ('buy','sell','transfer'):
        v=tax.get(side)
        if v is not None:
            evidence+=1
            if v>=40:mark('Comisión '+side+' extrema ('+percentage(v)+')',55,True)
            elif v>=15:mark('Comisión '+side+' elevada ('+percentage(v)+')',30)
            elif v>=7:mark('Comisión '+side+' significativa ('+percentage(v)+')',12)
    if tax.get('mismatch'):
        mark('TAX diferente entre GoPlus y Honeypot.is',22)
    if market:
        liquidity=number((market.get('liquidity') or {}).get('usd'))
        if liquidity is not None:
            evidence+=1
            if liquidity<1000:mark('Liquidez extremadamente baja',60)
            elif liquidity<5000:mark('Liquidez baja',20)
    if not evidence:
        return {'score':None,'verdict':'SIN DATOS SUFICIENTES','flags':[],'coverage':'insuficiente'}
    score=max(0,100-sum(weight for _,weight in flags))
    # Never award a full 100/100 when coverage is too weak to justify a score.
    if not flags and (evidence<5 or len(sources)<2):score=None
    # Never label a token low-risk on the strength of one source or few fields.
    if critical:verdict='RIESGO CRÍTICO'
    elif score is None:verdict='ANÁLISIS PARCIAL'
    elif score<SCORE_WARN:verdict='RIESGO ALTO'
    elif score<SCORE_OK:verdict='PRECAUCIÓN'
    elif evidence<5 or len(sources)<2:verdict='ANÁLISIS PARCIAL'
    else:verdict='SIN ALERTAS CRÍTICAS DETECTADAS'
    return {'score':score,'verdict':verdict,'flags':[name for name,_ in flags],
            'coverage':'parcial' if evidence<5 or len(sources)<2 else 'múltiples fuentes'}


def security_text(mint,chain,sources,market=None):
    result=security_assessment(chain,sources,market)
    tax=tax_details(chain,sources)
    lines=['🔍 <b>MIGUELOTE SCAN · SEGURIDAD</b>',
           f'Red: <b>{esc(chain.upper())}</b>',f'<code>{esc(mint,96)}</code>','',
           '🛡️ <b>AUDIT · índice SCAN (0–100)</b>']
    if result['score'] is None:
        lines.append('Puntuación: — · '+result['verdict'])
    else:
        lines.append(f'Índice SCAN: <b>{result["score"]}/100</b> · {result["verdict"]}')
    lines += [f'Índice calculado por Miguelote Scan con las comprobaciones recibidas; no es una nota del proveedor. Verde: {SCORE_OK}–100; naranja: {SCORE_WARN}–{SCORE_OK-1}; rojo: 0–{SCORE_WARN-1}. —: sin datos suficientes para puntuar.']
    lines += ['', '🧾 <b>Impuestos/comisiones del token</b>']
    if chain=='solana':
        lines.append('Compra / venta: — (no inferible con estas fuentes)')
        lines.append('Token-2022 · comisión transferencia: <b>'+percentage(tax['transfer'])+'</b>')
        if tax.get('scheduled') is not None:
            lines.append('Próxima comisión configurada: '+percentage(tax['scheduled']))
    else:
        lines.append('TAX compra: <b>'+percentage(tax['buy'])+'</b>')
        lines.append('TAX venta: <b>'+percentage(tax['sell'])+'</b>')
        if tax.get('mismatch'):lines.append('⚠️ Los proveedores discrepan sobre el TAX.')
    lines += ['', '🚩 <b>Alertas</b>']
    lines += ['• '+esc(v,100) for v in result['flags'][:8]] if result['flags'] else ['Sin alertas reportadas en los datos consultados.']
    providers='GoPlus · RugCheck' if chain=='solana' else ('GoPlus · Honeypot.is' if chain in ('ethereum','bsc','base') else 'GoPlus (si hay cobertura)')
    lines += ['',f'Fuentes previstas: {providers}',
              'Datos obtenidos: '+(', '.join(sources) if sources else 'ninguno'),
              '<i>Consulta: '+stamp(time.time())+'</i>',
              '<i>Escáner de riesgos, no auditoría ni consejo de inversión. Si faltan datos, NO implica seguridad.</i>']
    return '\n'.join(lines)

def aser_first_signal(data):
    rows=data.get('signals') or []
    if not rows:return None
    # Do not guess chronology when any timestamp is absent/invalid.
    if any(number(r.get('time')) is None or not 0<number(r['time'])<=time.time()*1000+60000 for r in rows):
        return rows[0] if len(rows)==1 else None
    return min(rows,key=lambda r:number(r['time']))


def aser_summary(data):
    if not data:return ''
    ns,nt=len(data['signals']),len(data['theses'])
    if not ns and not nt:return ''
    parts=[]
    if ns:
        first=aser_first_signal(data)
        mc=number(first.get('mcap_usd')) if first else None
        value=compact(mc,True) if mc is not None and mc>=0 else '—'
        parts.append('<b>'+str(ns)+'</b> señal'+('es' if ns!=1 else '')+(' · 1ª call MC <b>'+value+'</b>' if value != '—' else ''))
    if nt:parts.append('<b>'+str(nt)+'</b> mención'+('es' if nt!=1 else '')+' comunidad')
    return '📡 <b>ASER</b>: '+' · '.join(parts)


def aser_report(mint,data):
    lines=['📡 <b>ASER · Señales y comunidad</b>','Solana · '+f'<code>{mint}</code>']
    def when(row):
        n=number(row.get('time'))
        return n if n is not None and 0<n<=time.time()*1000+60000 else 0
    signals=sorted(data['signals'],key=when,reverse=True)
    theses=sorted(data['theses'],key=when,reverse=True)
    first=aser_first_signal(data)
    if first:
        mc=number(first.get('mcap_usd'))
        lines+=['','<b>Primera señal registrada por ASER</b>', 'MC: '+(compact(mc,True) if mc is not None and mc>=0 else '—')]
        if when(first):lines.append(stamp(when(first)/1000))
        lines.append(esc(' '.join(str(first.get('title') or first.get('kind') or 'Señal').split()),100))
        if first.get('approved') is False:lines.append('⚠️ No pasó el filtro de ASER.')
    lines+=['','<b>Señales de ASER</b>']
    if not signals:lines.append('Sin señales en el historial devuelto.')
    for row in signals[:3]:
        title=' '.join(str(row.get('title') or row.get('kind') or 'Señal').split())
        lines.append('• '+esc(title,100))
        if when(row):lines.append(stamp(when(row)/1000))
        price,mc=number(row.get('price_usd')),number(row.get('mcap_usd'))
        lines.append('Precio: '+(fmt(price,True) if price is not None and price>=0 else '—')+' · MC: '+(compact(mc,True) if mc is not None and mc>=0 else '—'))
        if row.get('approved') is False:lines.append('⚠️ No pasó el filtro de ASER.')
    lines+=['','<b>Menciones de la comunidad</b>']
    if not theses:lines.append('Sin menciones en el historial devuelto.')
    for row in theses[:2]:
        author=row.get('author') if isinstance(row.get('author'),dict) else {}
        lines.append('• '+esc(author.get('alias') or 'Usuario',40)+': '+esc(' '.join(str(row.get('text') or '').split()),180))
        if when(row):lines.append(stamp(when(row)/1000))
    lines+=['','Mostradas hasta 3 señales y 2 menciones recientes.',
            'Las señales pueden ser avisos positivos o negativos. Las menciones son opiniones de usuarios.',
            '<i>Consulta: '+stamp(time.time())+'</i>']
    return '\n'.join(lines)


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
        [{'text': '🔍 Escáner', 'callback_data': f'security:{mint}'}],
        [{'text': '🔄 Actualizar', 'callback_data': f'scan:{mint}'},
         {'text': 'ℹ Fuentes', 'callback_data': f'sources:{mint}'}],
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
    rounded = round(n, 2)
    if rounded == 0:
        return '0%'
    text = f'{abs(rounded):.2f}'.rstrip('0').rstrip('.')
    return ('🟢 +' if rounded > 0 else '🔴 -') + text + '%'


def ath_mc(info):
    ath, supply = number(info.get('ath_price')), number(info.get('circulating_supply'))
    if ath is None or ath <= 0 or supply is None or supply < 0:
        return 'MC estimado <b>—</b>'
    return f'MC estimado ≈ <b>{compact(ath * supply, True)}</b>'


def image_dimensions(data):
    """Read dimensions without decoding or enlarging the original image."""
    try:
        if data.startswith(b'\x89PNG\r\n\x1a\n') and len(data)>=24:
            return struct.unpack('>II',data[16:24])
        if data[:3]==b'GIF' and len(data)>=10:return struct.unpack('<HH',data[6:10])
        if data[:4]==b'RIFF' and data[8:12]==b'WEBP':
            kind=data[12:16]
            if kind==b'VP8X' and len(data)>=30:
                return 1+int.from_bytes(data[24:27],'little'),1+int.from_bytes(data[27:30],'little')
            if kind==b'VP8 ' and data[23:26]==b'\x9d\x01\x2a':
                w,h=struct.unpack('<HH',data[26:30]);return w&16383,h&16383
            if kind==b'VP8L' and len(data)>=25 and data[20]==47:
                bits=int.from_bytes(data[21:25],'little');return (bits&16383)+1,((bits>>14)&16383)+1
        if data[:2]==b'\xff\xd8':
            i=2
            while i+4<=len(data):
                if data[i]!=255:break
                while i<len(data) and data[i]==255:i+=1
                marker=data[i];i+=1
                if marker in (216,217,1) or 208<=marker<=215:continue
                length=int.from_bytes(data[i:i+2],'big')
                if length<2 or i+length>len(data):break
                if marker in (192,193,194,195,197,198,199,201,202,203,205,206,207):
                    h,w=struct.unpack('>HH',data[i+3:i+7]);return w,h
                i+=length
    except (IndexError,ValueError,struct.error):pass
    return None


def public_https(url):
    """True si la URL es https y su host resuelve solo a direcciones públicas."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username:
            return False
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
        return bool(infos) and all(ipaddress.ip_address(info[4][0].split('%')[0]).is_global for info in infos)
    except (OSError, ValueError):
        return False


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    """Sigue redirecciones solo hacia https públicos."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not public_https(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class PublicHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        addresses = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        if not addresses or any(not ipaddress.ip_address(row[4][0].split('%')[0]).is_global
                                for row in addresses):
            raise OSError('Destino de imagen no público.')
        # Connect to the validated address, but verify TLS against the original hostname.
        family, kind, proto, _, address = addresses[0]
        sock = socket.socket(family, kind, proto)
        sock.settimeout(self.timeout)
        try:
            sock.connect(address)
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


class PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(PublicHTTPSConnection, req)


IMAGE_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                          PublicRedirect, PublicHTTPSHandler)



def probe_image_size(url):
    # Las URLs de imagen las controla el creador del token: nunca se consultan hosts internos.
    if not public_https(url):
        return None
    try:
        request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT, 'Range': 'bytes=0-65535'})
        with IMAGE_OPENER.open(request, timeout=2) as response:
            return image_dimensions(response.read(65536))
    except (OSError, ValueError, http.client.HTTPException):
        return None


def image_quality(size):
    if not size or min(size)<=0:return (0,0)
    w,h=size;ratio=w/h
    # Wide high-resolution header first, then a sharp square logo.
    if 1.5<=ratio<=4 and w>=1280 and h>=480:level=3
    elif .75<=ratio<=1.33 and min(w,h)>=512:level=2
    elif min(w,h)>=256:level=1
    else:level=0
    return level,w*h


def image_url(value):
    if not isinstance(value,str) or len(value)>2048:return False
    try:
        parsed=urllib.parse.urlsplit(value)
        return parsed.scheme=='https' and bool(parsed.hostname) and not parsed.username
    except ValueError:return False


def safe_link(label, url):
    if not isinstance(url,str) or len(url)>2048:
        return None
    try:
        parsed=urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username:
        return None
    return f'<a href="{html.escape(url,quote=True)}">{esc(label)}</a>'


SOCIAL_DOMAINS = {
    'TG': ('t.me', 'telegram.me'), 'Discord': ('discord.gg', 'discord.com'),
    'X': ('x.com', 'twitter.com'), 'Reddit': ('reddit.com', 'redd.it'),
    'WhatsApp': ('whatsapp.com', 'wa.me'), 'YouTube': ('youtube.com', 'youtu.be'),
    'Instagram': ('instagram.com',), 'TikTok': ('tiktok.com',),
    'Facebook': ('facebook.com', 'fb.com'), 'GitHub': ('github.com',),
}


def project_links(info, pair):
    links = {}

    def add(url, website=False):
        if not safe_link('link', url):
            return
        host = urllib.parse.urlsplit(url).hostname.lower()
        label = next((name for name, domains in SOCIAL_DOMAINS.items()
                      if any(host == domain or host.endswith('.' + domain) for domain in domains)), None)
        if not label and website:
            label = 'Web'
        if label and label not in links:
            links[label] = safe_link(label, url)

    social = info.get('link')
    if isinstance(social, dict):
        add(social.get('website'), website=True)
        for url in social.values():
            add(url)
        username = social.get('twitter_username')
        if isinstance(username, str) and re.fullmatch(r'@?[A-Za-z0-9_]{1,15}', username):
            add('https://x.com/' + username.lstrip('@'))
    for metadata in (pair.get('info'), (pair.get('activity_extra') or {}).get('info')):
        if not isinstance(metadata, dict):
            continue
        for key in ('websites', 'socials'):
            rows = metadata.get(key)
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, dict):
                        add(row.get('url'), website=key == 'websites')
    return [links[label] for label in ('Web', *SOCIAL_DOMAINS) if label in links]


def age_text(timestamp, now):
    value=number(timestamp)
    if value is None or value<=0 or value>now:
        return '—'
    seconds=now-value
    if seconds>=86400: return str(int(seconds//86400))+'d'
    if seconds>=3600: return str(int(seconds//3600))+'h'
    return str(int(seconds//60))+'m'


def caption_length(text):
    """Longitud visible del texto en unidades UTF-16 (límite del pie de foto de Telegram)."""
    return len(html.unescape(re.sub(r'<[^>]+>','',text)).encode('utf-16-le'))//2


def metric(label, value):
    if value is None or value in ('—', NA):
        return ''
    return f'{label}: <b>{value}</b>'


def section(title, rows, *, branches=False):
    visible = [row for row in rows if row]
    if visible and branches:
        visible = [f"├ {row}" for row in visible[:-1]] + [f"└ {visible[-1]}"]
    return [title, *visible] if visible else []


def activity_lines(pair):
    extra=pair.get('activity_extra') or (pair if pair.get('source')=='DexScreener' else {})
    liq=number((pair.get('liquidity') or {}).get('usd'))
    mc=number(pair.get('marketCap'))
    volume=number((pair.get('volume') or {}).get('h24'))
    liquidity_ratio=f'{100*liq/mc:.2f}%' if liq is not None and liq>=0 and mc is not None and mc>0 else '—'
    turnover=f'{volume/liq:.2f}×' if volume is not None and volume>=0 and liq is not None and liq>0 else '—'
    boosts=extra.get('boosts') if isinstance(extra.get('boosts'),dict) else {}
    active=number(boosts.get('active'))
    boost_text=compact(active) if active is not None and active>=0 and active.is_integer() else '—'
    return section('⚡ <b>ACTIVIDAD DEL PAR</b>', [
        metric('Liquidez / MC', liquidity_ratio),
        metric('Volumen / liquidez 24 h', turnover),
        metric('Boosts DEX', boost_text),
    ], branches=True)


def comparison_snapshot(mint,pair,fetched,info):
    return {'mint':mint,'chain':pair.get('chainId'),'source':pair.get('source'),
            'pool':pair.get('pairAddress'),'time':fetched,'price':number(pair.get('priceUsd')),
            'liquidity':number((pair.get('liquidity') or {}).get('usd')),
            'holders':number(info.get('holder_count')),
            'top10':number((info.get('stat') or {}).get('top_10_holder_rate'))}


def comparison_text(old,new):
    if not old or any(old.get(k) != new.get(k) for k in ('mint', 'chain', 'source', 'pool')):
        return ''
    elapsed = max(0, int(new['time'] - old['time']))
    age = f'{elapsed}s' if elapsed < 60 else f'{elapsed // 60} min' if elapsed < 3600 else f'{elapsed // 3600}h {(elapsed % 3600) // 60} min'
    rows = []
    comparable = False
    for key, label in [('price', 'Precio'), ('liquidity', 'Liquidez'), ('holders', 'Holders'), ('top10', 'Top 10')]:
        before, after = number(old.get(key)), number(new.get(key))
        if before is None or after is None or min(before, after) < 0:
            continue
        if key == 'top10':
            if max(before, after) > 1:
                continue
            previous, current = f'{before * 100:.2f}%', f'{after * 100:.2f}%'
            value = f'{previous} → {current}' if previous != current else ''
        elif key == 'holders':
            value = f'{after - before:+.0f}'
        elif before > 0:
            value = f'{(after / before - 1) * 100:+.2f}%'
        elif after == 0:
            value = ''
        else:
            continue
        comparable = True
        if value and value not in ('+0', '-0', '+0.00%', '-0.00%'):
            rows.append(metric(label, value))
    if rows:
        return '\n'.join(section(f'🔄 <b>CAMBIOS · {age}</b>', rows, branches=True))
    return f'🔄 <b>Sin cambios · {age}</b>' if comparable else ''


def audit_summary(chain,sources,market=None):
    result=security_assessment(chain,sources,market)
    providers=[name for name in ('GoPlus','Honeypot.is','RugCheck') if sources.get(name)]
    label=' + '.join(providers) if providers else 'SCAN'
    score=result['score'] if providers else None
    if score is None:
        value='⚪ <b>—</b>'
    else:
        color='🟢' if score>=SCORE_OK else '🟠' if score>=SCORE_WARN else '🔴'
        value=f'{color} <b>{score}/100</b>'
        if result['verdict']=='RIESGO CRÍTICO':value+=' · ⚠️ Crítico'
    return '🛡️ <b>AUDIT '+label.upper()+'</b>: '+value+' · Índice SCAN'


def bold_metric(text):
    return re.sub(r'(?<![\w>])(?:[0-9]+(?:\.[0-9]+)?%|—)',r'<b>\g<0></b>',text)


def card(mint, pair, fetched, info=None):
    base=pair.get('baseToken') or {}
    info=info or pair.get('gmgn_info') or {}
    stat=info.get('stat') or {}
    dev=info.get('dev') or {}
    changes=pair.get('priceChange') or {}
    tx=(pair.get('txns') or {}).get('h24') or {}
    current=number(pair.get('priceUsd'))
    ath=number(info.get('ath_price'))
    chain=pair.get('chainId') or 'solana'
    ratio=lambda v:fmt(v,ratio=True) if number(v) is not None and 0<=number(v)<=1 else '—'
    short=lambda v: (v[:6]+'…'+v[-4:]) if valid_contract(v) else '—'
    supply=number(info.get('total_supply'))
    supply_text=compact(supply) if supply is not None and supply>=0 else '—'
    age=age_text(info.get('creation_timestamp'),fetched)
    name=esc(base.get('name') or 'Token',45)
    symbol=esc(base.get('symbol') or '?',18)
    network = [esc(chain.title())]
    if pair.get('dexId'):
        network.append(esc(pair['dexId'], 25))
    if age != '—':
        network.append('🌱 ' + age)
    lines = [f'<b>{name} (${symbol})</b>', ' · '.join(network)]
    stats = [
        metric('Capitalización', compact(pair.get('marketCap'), True)),
        metric('Precio actual', fmt(current, money=True)),
    ]
    if ath is not None and ath > 0 and (current is None or current <= ath):
        circulating = number(info.get('circulating_supply'))
        if circulating is not None and circulating >= 0:
            stats.append(metric('Capitalización al ATH', '≈ ' + compact(ath * circulating, True)))
        stats.append(metric('Precio ATH', fmt(ath, money=True)))
        if current is not None:
            stats.append(metric('Desde el ATH', change((current / ath - 1) * 100)))
    stats.extend([
        metric('Supply total', supply_text),
        metric('Liquidez', compact((pair.get('liquidity') or {}).get('usd'), True)),
        metric('Volumen 24 h', compact((pair.get('volume') or {}).get('h24'), True)),
        ' · '.join(filter(None, [metric('5 min', change(changes.get('m5'))),
                                metric('1 hora', change(changes.get('h1')))])),
        metric('24 horas', change(changes.get('h24'))),
    ])
    buys, sells = compact(tx.get('buys')), compact(tx.get('sells'))
    if buys != '—' and sells != '—':
        stats.append(metric('Compras / Ventas 24 h', f'{buys} / {sells}'))
    else:
        stats.extend([metric('Compras 24 h', buys), metric('Ventas 24 h', sells)])
    stats.append(metric('Holders', compact(info.get('holder_count'))))
    lines += section('🟩 <b>TOKEN STATS</b>', stats, branches=True)
    lines += activity_lines(pair)
    distribution = [metric('Top 10', ratio(stat.get('top_10_holder_rate')))]
    for key in ('sniper_text', 'bundler_text'):
        value = pair.get(key)
        if value and '%' in value:
            distribution.append(bold_metric(value.removeprefix('🎯 ')))
    distribution.extend([metric('Equipo', ratio(stat.get('dev_team_hold_rate'))),
                         metric('Par', short(pair.get('pairAddress'))),
                         metric('DEV', short(dev.get('creator_address')))])
    sale = pair.get('dev_sell_text')
    if sale and sale != '⚪ Sin verificar':
        distribution.append(metric('Ventas del DEV', sale))
    lines += section('🟦 <b>DISTRIBUCIÓN Y DEV</b>', distribution, branches=True)
    paid = pair.get('dex_paid')
    if isinstance(paid, bool):
        lines.append(metric('🦉 DEX pagado', '🟢 Sí' if paid else '🔴 No'))
    summary = aser_summary(pair.get('aser_signals'))
    if summary:
        lines.append(summary)
    links = project_links(info, pair)
    if links: lines += ['🌐 <b>SOCIALS</b>', ' · '.join(links)]
    lines += [f'📝 <b>CONTRATO</b> <code>{mint}</code>','<i>🔄 <b>ÚLTIMA CONSULTA</b>: <b>'+datetime.fromtimestamp(fetched,timezone.utc).strftime('%d/%m/%Y %H:%M:%S UTC')+'</b></i>']
    return '\n'.join(line for line in lines if line)


def sources_text(pair, fetched, gmgn_note=''):
    lines = ['<b>Fuentes y alcance</b>', f'Mercado de esta ficha: {esc(pair.get("source","GMGN"))}. Red: {esc(pair.get("chainId","solana"))}. Imágenes: ASER, GMGN, DexScreener (cabeceras, imagen del par y perfiles) y GeckoTerminal/CoinGecko. Coincidencia por contrato y red; cobertura variable. Fuentes de reserva solo si falla el envío de las imágenes prioritarias.',
             'Con GMGN: MC = precio × suministro circulante; FDV = precio × suministro total. Con DexScreener: valores reportados, sin sustituir MC por FDV.',
             'Precio y actividad: GMGN. Variaciones calculadas con sus precios al inicio de cada período. Liquidez del pool principal indicado por GMGN.',
             'Holders, Top 10 y etiquetas sniper: GMGN cuando está disponible. Una etiqueta no prueba que sea un bot.',
             'ATH de precio: reportado por GMGN. MC al precio ATH marcado ≈ es una estimación con suministro circulante actual, no el MC histórico. Snipers: suma de participaciones de holders etiquetados por GMGN, consulta limitada a 100 carteras; una lista de 100 es parcial.',
             'Compras / Ventas: cantidad de operaciones en 24 horas, no dólares ni personas únicas. Actividad del par: LIQ/MC = liquidez / capitalización × 100; VOL/LIQ = volumen 24h / liquidez. Boosts DEX: promociones activas según DexScreener, solo para el mismo pool y red; son promoción, no garantía de calidad. Son relaciones descriptivas, no medidas de seguridad.',
             'DEV SELL: cartera creadora identificada por GMGN. Sí indica estado sell en token info o una venta del token en su historial de actividad. No detectado indica que la consulta filtrada por ventas devuelve una lista vacía sin más páginas; no certifica que nunca vendió ni cubre otras carteras del equipo, transferencias o ventas fuera del historial del proveedor. No es una valoración de seguridad. Sin verificar significa que faltan datos o no se pudo consultar.',
             'Desde la consulta anterior compara la última ficha enviada o editada con éxito en ese mensaje. Si el servidor pierde el registro local, la comparación comienza en la siguiente actualización. Cambios de proveedor o pool se muestran como — para no mezclar referencias.',
             'AUDIT: índice SCAN (0–100) calculado por Miguelote Scan con GoPlus, Honeypot.is y RugCheck según la red; no es una nota del proveedor, ni una auditoría, ni un consejo de inversión. — significa datos insuficientes. El botón Escáner muestra el detalle.',
             'Edad: fecha de creación del token según GMGN; no se sustituye por la edad del pool. Equipo: suministro en carteras etiquetadas como equipo. No se equipara volumen de bundlers con suministro retenido. Bubble Maps abre el mapa externo si el proyecto tiene cobertura.']
    lines.append('ASER: señales y tesis devueltas para el contrato exacto en Solana. Las tesis son opiniones de usuarios, no señales oficiales. La primera call es la señal más antigua del historial devuelto por ASER, no la primera publicación del grupo ni una garantía de cobertura histórica completa. No implica que fuera una recomendación de compra. Si falta espacio bajo la imagen, el resumen queda en el botón ASER. Caché de hasta 60 segundos; Actualizar renueva la consulta salvo pausa por errores o cuota.')
    created = number((pair.get('activity_extra') or pair).get('pairCreatedAt'))
    if created and 0 < created / 1000 <= time.time():
        lines.append(f'Creación del par (no del token): {stamp(created / 1000)}')
    gmgn_note = gmgn_note or pair.get('gmgn_error', '')
    if gmgn_note:
        lines.append('Estado GMGN: ' + esc(gmgn_note, 300))
    lines += [f'Consulta de mercado: {stamp(fetched)}.',
              'La hora de consulta no garantiza la frescura del proveedor. — significa dato no disponible, nunca cero.']
    return '\n\n'.join(lines)


def holders_text(data):
    rows = data.get('list')
    if not isinstance(rows, list):
        raise DataError('Lista de holders no disponible en GMGN.')
    lines = ['<b>Top holders · reportado por GMGN</b>']
    for row in rows:
        if len(lines) > 10:
            break
        if not isinstance(row, dict) or not valid_contract(row.get('address')):
            continue
        addr = row['address']
        kind = 'Exchange / pool' if row.get('addr_type') == 2 else 'Sin clasificar'
        lines.append(f'{len(lines)}. <code>{addr[:6]}…{addr[-4:]}</code> '
                     f'· {fmt(row.get("amount_percentage"), ratio=True)} · {fmt(row.get("balance"))} tokens · {kind}')
    if len(lines) == 1:
        lines.append('No hay filas válidas disponibles; no implica cero holders.')
    lines += ['', 'No se infiere que carteras relacionadas sean del mismo dueño. Clasificación del proveedor.',
              f'Consulta/caché de hasta 60 s · {stamp(time.time())}']
    return '\n'.join(lines)


HELP = ('<b>Miguelote Scan · Multired</b>\n'
        'Pega un contrato, escribe $CHOP o utiliza /scan RED:CONTRATO. Ejemplo: base:0x…\n'
        '/chart — elegir DexScreener o DEXTools\n'
        '/holders CONTRATO — top holders GMGN\n'
        '/snipers CONTRATO — detección GMGN\n'
        '/security CONTRATO — escáner de riesgos\n'
        '/ath CONTRATO — máximo del historial disponible\n\n'
        'Los charts se abren en el navegador. Bubble Maps depende de cobertura externa. '
        'Datos: GMGN. ATH de precio reportado por el proveedor; no certificado independientemente.')



# Original 100px WEBP artwork, in the order of the associated Telegram emoji.
PACK_EMOJI = ('📊','🏔','⚡','🦉','🟦','📡','🌐','📝','🔄','🛡','🕒','📈')
PACK_ART = ('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')
def create_icon_set(token, username, owner):
    import base64
    import uuid
    boundary = uuid.uuid4().hex
    body = bytearray()
    def field(name, value, filename=None):
        body.extend(('--'+boundary+'\r\nContent-Disposition: form-data; name="'+name+'"').encode())
        if filename:
            body.extend(('; filename="'+filename+'"\r\nContent-Type: image/webp').encode())
        body.extend(b'\r\n\r\n'+value+b'\r\n')
    name = 'scan_icons_v1_by_' + username
    fields = {'name':name,'title':'Miguelote Scan','user_id':str(owner),'sticker_type':'custom_emoji',
              'stickers':json.dumps([{'sticker':'attach://i'+str(i),'format':'static','emoji_list':[e]}
                                    for i,e in enumerate(PACK_EMOJI)])}
    for key,value in fields.items():
        field(key,value.encode())
    for i,data in enumerate(PACK_ART):
        field('i'+str(i),base64.b64decode(data),str(i)+'.webp')
    body.extend(('--'+boundary+'--\r\n').encode())
    req=urllib.request.Request('https://api.telegram.org/bot'+token+'/createNewStickerSet',
        data=bytes(body),headers={'Content-Type':'multipart/form-data; boundary='+boundary})
    with urllib.request.urlopen(req,timeout=20) as response:
        if not json.load(response).get('ok'):
            raise DataError('No se pudo crear el pack.')

def sticker_ids(pack):
    if pack.get('sticker_type') != 'custom_emoji':
        return {}
    mapping = {str(row.get('emoji','')).replace('️',''):row.get('custom_emoji_id')
               for row in pack.get('stickers',[]) if isinstance(row,dict)}
    return mapping if all(str(mapping.get(e,'')).isdigit() for e in PACK_EMOJI) else {}

def icon_markup(payload, ids):
    if not ids:
        return payload
    result = dict(payload)
    headings = (('🟩','TOKEN STATS',0),('🏔','ATH',1),('⚡','ACTIVIDAD DEL PAR',2),
      ('🦉','DEX PAGADO',3),('🟦','DISTRIBUCIÓN',4),('📡','ASER',5),('🌐','SOCIALS',6),
      ('📝','CONTRATO',7),('🔄','ÚLTIMA CONSULTA',10),('🔄','CAMBIOS',11),('🔄','Sin cambios',11))
    for field in ('text','caption'):
        if field in result:
            for old,title,i in headings:
                glyph=PACK_EMOJI[i]
                result[field]=result[field].replace(old+' <b>'+title,
                    '<tg-emoji emoji-id="'+ids[glyph]+'">'+glyph+'</tg-emoji> <b>'+title)
            if '🦉 DEX pagado' in result[field]:
                glyph = PACK_EMOJI[3]
                result[field] = result[field].replace('🦉 DEX pagado',
                    f'<tg-emoji emoji-id="{ids[glyph]}">{glyph}</tg-emoji> DEX pagado')
    keyboard=payload.get('reply_markup',{}).get('inline_keyboard')
    if keyboard:
        labels={'🔍 Escáner':9,'📡 ASER':5,'🔄 Actualizar':8,'🏔 ATH':1}
        def button(b):
            i=labels.get(b.get('text'))
            return b if i is None else dict(b,text=b['text'].split(' ',1)[1],icon_custom_emoji_id=ids[PACK_EMOJI[i]])
        result['reply_markup']={'inline_keyboard':[[button(b) for b in row] for row in keyboard]}
    return result


class Bot:
    def __init__(self, token, scanner, allowed=None):
        self.token, self.scanner = token, scanner
        self.allowed = allowed or set()
        self.last_request = {}
        self.username = None
        self.lock = threading.RLock()
        self.callback_lock = threading.Lock()
        self._delivery_snapshot = None

        self.icon_ids = {}
        if os.getenv('SCAN_OWNER_ID','').isdigit():
            threading.Thread(target=self.load_icons,daemon=True).start()

    def load_icons(self):
        try:
            username=self.own_username()
            if username:
                pack=self.api('getStickerSet',{'name':'scan_icons_v1_by_'+username})
                self.icon_ids=sticker_ids(pack)
        except DataError:
            pass
        return bool(self.icon_ids)

    def activate_icons(self, chat):
        if self.load_icons():
            return self.send(chat,'Los 12 emojis de Miguelote Scan están activos.')
        try:
            username=self.own_username()
            if not username:
                raise DataError('No se pudo identificar el bot.')
            create_icon_set(self.token,username,chat)
        except (OSError, ValueError, DataError):
            pass
        if self.load_icons():
            return self.send(chat,'Pack activado. Envía un contrato para ver los iconos.')
        return self.send(chat,'Telegram no confirmó el pack. Comprueba los permisos de la cuenta propietaria y vuelve a enviar /iconos.')

    def api(self, method, payload):
        if method in ('sendPhoto','sendMessage','editMessageText','editMessageCaption') and self.icon_ids:
            styled=icon_markup(payload,self.icon_ids)
            try:
                return self._telegram(method,styled)
            except TelegramRequestError as error:
                if error.status != 400 or styled == payload:
                    raise
        return self._telegram(method,payload)

    def _telegram(self, method, payload):
        try:
            response = fetch(f'https://api.telegram.org/bot{self.token}/{method}', payload,
                             timeout=40 if method == 'getUpdates' else 12)
        except RateLimitError as error:
            if method in ('sendMessage', 'sendPhoto', 'editMessageText', 'editMessageCaption'):
                raise DeliveryRetryError(method, payload, error.retry_after) from None
            raise
        if isinstance(response, dict) and response.get('error_code') == 429:
            delay = number((response.get('parameters') or {}).get('retry_after')) or 30
            if method in ('sendMessage', 'sendPhoto', 'editMessageText', 'editMessageCaption'):
                raise DeliveryRetryError(method, payload, delay)
            raise RateLimitError('Telegram: límite de consultas.', delay)
        if not isinstance(response, dict) or not response.get('ok'):
            raise TelegramRequestError('Telegram rechazó la petición; revisa configuración y permisos.', response.get('error_code') if isinstance(response, dict) else None)
        return response.get('result')

    def send(self, chat, text, markup=None):
        payload = {'chat_id': chat, 'text': text, 'parse_mode': 'HTML',
                   'link_preview_options': {'is_disabled': True}}
        if markup:
            payload['reply_markup'] = markup
        return self.api('sendMessage', payload)

    def send_card(self, chat, text, markup, logo, fallback=None):
        logos = logo if isinstance(logo, list) else [logo]
        if self.scanner and hasattr(self.scanner,'rank_images'):
            logos,sharp=self.scanner.rank_images(logos)
            if not sharp and fallback:
                logos,_=self.scanner.rank_images(logos+fallback())
                fallback=None
        fits = caption_length(text) <= CAPTION_LIMIT
        sent_photo = limited = False
        for logo in logos:
            if not isinstance(logo,str) or not logo.startswith('https://') or len(logo)>=2048:
                continue
            payload = {'chat_id': chat, 'photo': logo}
            if fits:
                payload.update(caption=text, parse_mode='HTML')
                if markup:
                    payload['reply_markup'] = markup
            try:
                result = self.api('sendPhoto', payload)
            except DeliveryRetryError as error:
                if not fits:
                    message = {'chat_id': chat, 'text': text, 'parse_mode': 'HTML',
                               'link_preview_options': {'is_disabled': True}}
                    if markup:
                        message['reply_markup'] = markup
                    error.steps.append({'method': 'sendMessage', 'payload': message})
                raise
            except RateLimitError:
                raise
            except TelegramRequestError as error:
                if error.status == 400:
                    continue  # rejected image: try a reserve URL
                raise  # unknown delivery outcome or permission error: never send another photo
            except DataError:
                continue
            if fits:
                return result
            sent_photo = True
            break
        if not sent_photo and fallback and not limited:
            return self.send_card(chat,text,markup,fallback())
        return self.send(chat, text, markup)

    def edit_card(self,msg,text,markup):
        payload={'chat_id':msg['chat']['id'],'message_id':msg['message_id'],
                 'parse_mode':'HTML','reply_markup':markup}
        if msg.get('photo'):
            # Keep the existing image. Never post a replacement card after an edit failure.
            if caption_length(text)>CAPTION_LIMIT:
                raise DataError('La ficha actualizada supera el espacio de esta foto. Se conserva la anterior.')
            payload['caption']=text
            return self.api('editMessageCaption',payload)
        payload.update(text=text,link_preview_options={'is_disabled':True})
        return self.api('editMessageText',payload)

    def callback_notice(self, callback, text=None, alert=True):
        if not isinstance(callback, dict):
            return None
        with self.callback_lock:
            if callback.get('_answered'):
                return None
            callback['_answered'] = True
        try:
            payload = {'callback_query_id': callback['id']}
            if text:
                payload.update(text=text[:180], show_alert=alert)
            return self.api('answerCallbackQuery', payload)
        except Exception:
            return None

    def network_keyboard(self, chat, mint, pair, user):
        chain=self.scanner.chain
        ref=self.scanner.store.reference({'chat':chat,'mint':mint,'chain':chain})
        data='ref_'+ref
        markup=keyboard(mint,pair.get('pairAddress'),self.scanner.store.preference(user))
        for row in markup['inline_keyboard']:
            for button in row:
                if ':' in button.get('callback_data',''):
                    verb=button['callback_data'].split(':')[0]
                    direct='refresh:'+chain+':'+mint
                    button['callback_data']=direct if verb=='scan' and len(direct.encode())<=64 else verb+':'+data
        if chain=='solana':
            label='📡 ASER'
            markup['inline_keyboard'][4].append({'text':label,'callback_data':'aser:'+data})
            return markup
        q=urllib.parse.quote
        pool=pair.get('pairAddress')
        charts=[{'text':'DexScreener','url':f'https://dexscreener.com/{chain}/{q(pool or mint,safe="")}'}]
        dt={'ethereum':'ether','bsc':'bnb','base':'base','arbitrum':'arbitrum','avalanche':'avalanche','polygon':'polygon'}
        if pool and chain in dt:
            charts.append({'text':'DEXTools','url':f'https://www.dextools.io/app/en/{dt[chain]}/pair-explorer/{q(pool,safe="")}'})
        map_chains = {'ethereum':'eth', 'bsc':'bsc', 'base':'base', 'arbitrum':'arbitrum',
                      'avalanche':'avalanche', 'polygon':'polygon', 'hyperevm':'hyperevm',
                      'arc':'arc', 'robinhood':'robinhood', 'monad':'monad', 'sonic':'sonic',
                      'aptos':'aptos', 'tron':'tron', 'ton':'ton'}
        holders = [markup['inline_keyboard'][1][1]]
        if chain in map_chains:
            query = urllib.parse.urlencode({'chain':map_chains[chain], 'address':mint})
            holders.insert(0, {'text':'🫧 Mapa', 'url':'https://v2.bubblemaps.io/map?' + query})
        rows = [charts, holders, markup['inline_keyboard'][2]]
        providers = []
        if chain in GMGN_CHAINS:
            providers.append({'text':'GMGN','url':f'https://gmgn.ai/{GMGN_CHAINS[chain]}/token/{mint}'})
        explorers = {'ethereum':('Etherscan','etherscan.io'), 'base':('BaseScan','basescan.org'),
                     'bsc':('BscScan','bscscan.com'), 'arbitrum':('Arbiscan','arbiscan.io'),
                     'polygon':('PolygonScan','polygonscan.com'), 'optimism':('OP Mainnet','optimistic.etherscan.io')}
        if chain in explorers:
            name, host = explorers[chain]
            providers.append({'text':name, 'url':f'https://{host}/token/{q(mint, safe="")}'})
        if providers:
            rows.append(providers)
        rows+=markup['inline_keyboard'][4:]
        return {'inline_keyboard':rows}

    def settings(self, chat):
        self.send(chat, 'Elige tu gráfico preferido. Siempre tendrás disponibles los dos botones.',
                  {'inline_keyboard': [[{'text': 'DexScreener', 'callback_data': 'pref:dexscreener'},
                                        {'text': 'DEXTools', 'callback_data': 'pref:dextools'}]]})

    def handle(self, update):
        """Permanent/malformed failures cannot poison the queue; 429 deliveries remain pending."""
        if not isinstance(update, dict):
            return
        with self.lock:
            self._delivery_snapshot = None
            callback = update.get('callback_query')
            timer = None
            key = 'delivery:' + str(update['update_id']) if type(update.get('update_id')) is int else None
            store = self.scanner.store
            try:
                pending = store.get(key) if key else None
                if pending:
                    return self._resume_delivery(key, json.loads(pending))
                if callback:
                    callback.pop('_answered', None)
                    # Quick errors can still show their specific notice; slow requests get an ACK.
                    timer = threading.Timer(3, self.callback_notice,
                                            args=(callback, 'Procesando…', False))
                    timer.daemon = True
                    timer.start()
                return self._handle(update)
            except DeliveryRetryError as error:
                if key and not store.get(key):
                    store.put(key, json.dumps({'steps': error.steps,
                              'retry_at': time.time() + error.retry_after,
                              'snapshot': self._delivery_snapshot}))
                self.callback_notice(callback, 'Telegram pide esperar; se reintentará automáticamente.')
                raise
            except Exception as error:
                # Never log provider bodies, URLs, tokens, or user content.
                print('Error en update ' + str(update.get('update_id')) + ': ' + type(error).__name__, flush=True)
                self._report_failure(update)
            finally:
                if timer:
                    timer.cancel()
                self.callback_notice(callback)
                self._delivery_snapshot = None

    def _resume_delivery(self, key, pending):
        """Retry exact unsent operations, not market queries or already-sent photos."""
        remaining = pending['retry_at'] - time.time()
        if remaining > 0:
            first = pending['steps'][0]
            raise DeliveryRetryError(first['method'], first['payload'], remaining)
        store = self.scanner.store
        result = None
        while pending['steps']:
            step = pending['steps'][0]
            try:
                result = self.api(step['method'], step['payload'])
            except DeliveryRetryError as error:
                pending['retry_at'] = time.time() + error.retry_after
                store.put(key, json.dumps(pending))
                raise
            except DataError:
                # Unknown network outcome: do not blindly repeat a possibly delivered message.
                store.delete(key)
                raise
            pending['steps'].pop(0)
            pending['result'] = result
            store.put(key, json.dumps(pending))
        snapshot = pending.get('snapshot')
        result = pending.get('result', result)
        if snapshot:
            message_id = snapshot.get('message_id') or (result.get('message_id') if isinstance(result, dict) else None)
            if message_id:
                store.card_snapshot(snapshot['chat'], message_id, snapshot['value'])
        store.delete(key)
        return result

    def _report_failure(self, update):
        callback = update.get('callback_query')
        if callback:
            self.callback_notice(callback, 'No se pudo completar. Se conserva la ficha anterior.')
            return
        try:
            msg = update.get('message') or {}
            chat = (msg.get('chat') or {}).get('id')
            if chat is None or (self.allowed and chat not in self.allowed):
                return
            self.send(chat, '⚠️ No se pudo completar la consulta. Inténtalo de nuevo en unos segundos.')
        except Exception:
            pass

    def housekeeping(self):
        """Acota memoria: peticiones recientes por usuario y caché del escáner."""
        if len(self.last_request) > 1000:
            cutoff = time.monotonic() - 3600
            self.last_request = {k: v for k, v in self.last_request.items() if v > cutoff}
        prune = getattr(self.scanner, 'prune', None)
        if prune:
            prune()

    def own_username(self):
        if self.username is None:
            try:
                self.username = (self.api('getMe', {}) or {}).get('username') or ''
            except DataError:
                return None
        return self.username or None

    def _handle(self, update):
        callback = update.get('callback_query')
        msg = (callback or {}).get('message') if callback else update.get('message')
        if not msg or 'chat' not in msg:
            return
        chat = msg['chat']['id']
        if not callback and msg['chat'].get('type')=='private' and msg.get('text','').strip()=='/miid':
            return self.send(chat,'Tu ID de Telegram es <code>'+str(chat)+'</code>.')
        if (not callback and msg['chat'].get('type')=='private' and msg.get('text','').strip()=='/iconos'
                and str(chat)==os.getenv('SCAN_OWNER_ID') and msg.get('from',{}).get('id')==chat):
            return self.activate_icons(chat)
        if self.allowed and chat not in self.allowed:
            return
        user = ((callback or msg).get('from') or {}).get('id', chat)
        self.housekeeping()
        if callback:
            action, _, arg = (callback.get('data') or '').partition(':')
        else:
            text = (msg.get('text') or msg.get('caption') or '').strip()
            if text.startswith('/'):
                parts = text.split(None, 1)
                command, _, mention = parts[0].partition('@')
                if mention and mention.lower() != (self.own_username() or '').lower():
                    return  # comando dirigido a otro bot del grupo
                action = command[1:].lower()
                arg = parts[1].strip() if len(parts) > 1 else ''
            elif valid_contract(text) or network_contract(text):
                action, arg = 'scan', text
            else:
                candidates = re.findall(r'(?<![A-Za-z0-9])(?:0x[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?|[1-9A-HJ-NP-Za-km-z]{32,44})(?![A-Za-z0-9])', text)
                arg = next((x for x in candidates if valid_contract(x)), '')
                if not arg:
                    tickers=re.findall(r'(?<![A-Za-z0-9_])\$([A-Za-z][A-Za-z0-9_]{0,19})(?![A-Za-z0-9_])',text)
                    if not tickers:return
                    if len(set(t.upper() for t in tickers))>1:
                        return self.send(chat,'Envía un solo ticker por consulta, por ejemplo $CHOP.')
                    arg='$'+tickers[0]
                action = 'scan'
        if action=='scan' and re.fullmatch(r'\$[A-Za-z][A-Za-z0-9_]{0,19}',arg):
            if time.monotonic()-max(self.last_request.get(user,-100),self.last_request.get(('ticker',user),-100))<3:
                return self.send(chat,'Espera unos segundos antes de la siguiente consulta.')
            try:matches=self.scanner.search_ticker(arg)
            except DataError as error:return self.send(chat,esc(str(error),200))
            if len(matches)==1:
                arg=matches[0]['chain']+':'+matches[0]['mint']
            else:
                self.last_request[('ticker',user)]=time.monotonic()
                if not matches:return self.send(chat,'No encuentro ese ticker exacto. Envía el contrato para consultarlo.')
                rows=[]
                for result in matches[:30]:
                    address=result['mint']
                    direct='scan:'+result['chain']+':'+address
                    if len(direct.encode())>64:
                        ref=self.scanner.store.reference({'chat':chat,'chain':result['chain'],'mint':address})
                        direct='scan:ref_'+ref
                    label=result['name'][:22]+' · '+result['chain'].title()+' · '+address[:5]+'…'+address[-5:]
                    rows.append([{'text':label,'callback_data':direct}])
                return self.send(chat,'🔎 <b>¿Qué '+esc(arg.upper())+' quieres consultar?</b>\nElige por nombre, red y contrato. Resultados indexados; si no aparece, pega el contrato.',{'inline_keyboard':rows})
        explicit_refresh=bool(callback and action=='refresh')
        if explicit_refresh:action='scan'
        refreshing=explicit_refresh or bool(callback and action=='scan' and any(
            'Actualizar' in b.get('text','')
            for row in (msg.get('reply_markup') or {}).get('inline_keyboard',[]) for b in row))
        if action == 'missingpool':
            message = 'GMGN no ha devuelto un pool válido para abrir este gráfico. Puedes usar el botón GMGN.'
            return self.callback_notice(callback, message) if callback else self.send(chat, message)
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
        if action not in ('scan', 'ath', 'holders', 'snipers', 'sources', 'security', 'srefresh', 'aser'):
            # Solo en privado se responde a comandos desconocidos; en grupos pueden ser de otros bots.
            if not callback and msg['chat'].get('type') == 'private':
                return self.send(chat, HELP)
            return None
        chain = None
        if arg.startswith('ref_'):
            ref=self.scanner.store.reference(key=arg[4:])
            if not ref and callback:
                # Old buttons refer to local state, which Render may discard on restart.
                body=msg.get('text') or msg.get('caption') or ''
                addresses=[line.strip() for line in body.splitlines() if valid_contract(line.strip())]
                network=re.search(r'^([A-Za-z0-9-]+) ·',body,re.M) or re.search(r'^Red:\s*([A-Za-z0-9-]+)',body,re.M)
                if len(addresses)==1 and network:
                    ref={'chat':chat,'chain':network.group(1).lower(),'mint':addresses[0]}
            if not ref or ref.get('chat') != chat:
                message='Esta ficha ha caducado. Envía de nuevo el contrato.'
                return self.callback_notice(callback,message) if callback else self.send(chat,message)
            chain,arg=ref['chain'],ref['mint']
        elif ':' in arg:
            chain,arg=arg.split(':',1)
            chain=canonical_chain(chain)
        if not valid_contract(arg):
            return self.send(chat,'Formato no reconocido. Usa /scan RED:CONTRATO con la dirección completa.')
        arg=normalized(arg)
        self.scanner.chain='solana'
        try:
            if chain is None:
                if valid_address(arg):
                    chain='solana'
                else:
                    try:
                        chains=sorted({p['chainId'] for p in self.scanner.dex_pairs(arg)})
                    except DataError:
                        # Network discovery is optional: explicit choice can still reach GMGN.
                        chains=[]
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
        except DeliveryRetryError:
            raise
        except DataError as error:
            return self.send(chat,esc(str(error),500))
        self.scanner.chain=chain
        if time.monotonic() - self.last_request.get(user, -100) < 3:
            message = 'Espera unos segundos antes de la siguiente consulta.'
            return self.callback_notice(callback, message) if callback else self.send(chat, message)
        self.last_request[user] = time.monotonic()
        if callback and not refreshing:
            self.callback_notice(callback)  # quita el indicador de carga del botón
        try:
            if action == 'scan':
                pair, _, fetched = (self.scanner.refresh_market(arg) if refreshing else self.scanner.market(arg))
                pair, logos = self.scanner.card_inputs(arg, pair, refreshing)
                info = pair.get('gmgn_info') or {}
                current=comparison_snapshot(arg,pair,fetched,info)
                self._delivery_snapshot = {'chat': chat, 'value': current,
                                           'message_id': msg.get('message_id') if refreshing else None}
                text=card(arg,pair,fetched,info)
                markup=self.network_keyboard(chat,arg,pair,user)
                if refreshing:
                    previous=self.scanner.store.card_snapshot(chat,msg['message_id'])
                    delta = comparison_text(previous,current)
                    if delta:
                        text += '\n' + delta
                    result=self.edit_card(msg,text,markup)
                    if result:
                        self.scanner.store.card_snapshot(chat,msg['message_id'],current)
                    return result
                result=self.send_card(chat,text,markup,logos,
                                      fallback=lambda:self.scanner.extra_images(arg))
                if isinstance(result,dict) and result.get('message_id'):
                    self.scanner.store.card_snapshot(chat,result['message_id'],current)
                return result
            if action=='aser':
                data=self.scanner.aser_signals(arg)
                return self.send(chat,aser_report(arg,data),{'inline_keyboard':[[{'text':'Abrir ASER','url':'https://aser.trade/#/coin/'+arg}]]})
            if action in ('security','srefresh'):
                sources=self.scanner.security_evidence(chain,arg,deep=True,force=action=='srefresh')
                try:
                    pair,_,_=self.scanner.market(arg)
                except DataError:
                    pair=None
                report=security_text(arg,chain,sources,pair)
                ref=self.scanner.store.reference({'chat':chat,'mint':arg,'chain':chain})
                markup={'inline_keyboard':[[{'text':'🔄 Reescanear','callback_data':'srefresh:ref_'+ref}],
                                          [{'text':'Quick Intel (web)','url':'https://app.quickintel.io/scanner'}]]}
                if chain=='solana':
                    markup['inline_keyboard'].append([{'text':'RugCheck (web)',
                      'url':'https://rugcheck.xyz/tokens/'+urllib.parse.quote(arg,safe='')}])
                if action=='srefresh':
                    return self.edit_card(msg,report,markup)
                return self.send(chat,report,markup)
            if action == 'sources':
                pair, _, fetched = self.scanner.market(arg)
                return self.send(chat, sources_text(pair, fetched))
            if action == 'ath':
                return self.send(chat, self.scanner.history(arg))
            if action == 'holders':
                return self.send(chat, holders_text(self.scanner.gmgn_query('holders', arg)))
            if action == 'snipers':
                return self.send(chat, self.scanner.current_snipers(arg) +
                                 '\nParticipación actual del suministro en carteras etiquetadas. GMGN: hasta 100 carteras; Aser: solo lecturas completas y recientes. No mide las compras al lanzamiento.\n' +
                                 f'Consulta/caché de hasta 60 s · {stamp(time.time())}')
        except DeliveryRetryError:
            raise
        except DataError as error:
            if refreshing:return self.callback_notice(callback,'No se pudo actualizar: '+str(error))
            return self.send(chat, esc(str(error), 500))

    def ensure_polling(self):
        """getUpdates no funciona con un webhook activo (error 409)."""
        try:
            info = self.api('getWebhookInfo', {}) or {}
        except DataError:
            return
        if not info.get('url'):
            return
        if os.environ.get('DELETE_WEBHOOK') == '1':
            self.api('deleteWebhook', {})
            print('Webhook eliminado; el bot usará long polling.', flush=True)
            return
        raise SystemExit('Este bot tiene un webhook activo y no se puede usar a la vez con getUpdates. '
                         'Ejecútalo en modo webhook o arranca con DELETE_WEBHOOK=1 para pasar a polling.')

    def run(self):
        self.username = (self.api('getMe', {}) or {}).get('username') or ''
        self.ensure_polling()
        print('Bot iniciado. Pulsa Ctrl+C para detenerlo.', flush=True)
        offset = self.scanner.store.offset()
        next_prune = time.monotonic() + 86400
        while True:
            try:
                updates = self.api('getUpdates', {'offset': offset, 'timeout': 25,
                                   'allowed_updates': ['message', 'callback_query']})
            except RateLimitError as error:
                print('Telegram pide esperar ' + str(int(error.retry_after)) + ' s.', flush=True)
                time.sleep(min(max(error.retry_after, 1), 300))
                continue
            except DataError as error:
                print('Servicio temporalmente no disponible: ' + str(error) + ' Reintento en 10 s.', flush=True)
                time.sleep(10)
                continue
            for update in updates or []:
                try:
                    self.handle(update)
                except DeliveryRetryError as error:
                    time.sleep(min(error.retry_after, 30))
                    break  # keep offset: the exact pending delivery is retried next poll
                offset = update['update_id'] + 1
                self.scanner.store.offset(offset)
            if time.monotonic() >= next_prune:
                self.scanner.store.prune()
                next_prune = time.monotonic() + 86400


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scan', help='Consultar sin Telegram (GMGN si está activo; si no, DexScreener/GeckoTerminal)')
    parser.add_argument('--chain', default='solana', help='Red para --scan: solana, ethereum, base, bsc…')
    args = parser.parse_args()
    store = Store(os.environ.get('BOT_DB', 'veraz.sqlite3'))
    scanner = Scanner(store, gmgn=os.environ.get('ENABLE_GMGN') == '1')
    if args.scan:
        if not valid_contract(args.scan):
            parser.exit(1, 'Contrato no válido.\n')
        scanner.chain = canonical_chain(args.chain)
        mint = normalized(args.scan)
        try:
            pair, _, fetched = scanner.market(mint)
            print(card(mint, pair, fetched))
            print(json.dumps(keyboard(mint, pair.get('pairAddress')), ensure_ascii=False, indent=2))
        except DataError as error:
            parser.exit(1, f'{error}\n')
        return
    token = os.environ.get('TELEGRAM_BOT_TOKEN', '')
    if not re.fullmatch(r'\d+:[A-Za-z0-9_-]+', token):
        parser.exit(1, 'Falta TELEGRAM_BOT_TOKEN. Ejecuta python iniciar.py para introducirlo de forma privada.\n')
    allowed = set()
    for item in os.environ.get('ALLOWED_CHAT_IDS', '').split(','):
        if not item.strip():
            continue
        try:
            allowed.add(int(item.strip()))
        except ValueError:
            # Falla cerrado: un valor mal escrito no debe dejar el bot abierto a todo el mundo.
            parser.exit(1, 'ALLOWED_CHAT_IDS debe contener solo ids numéricos separados por comas.\n')
    if not allowed:
        print('AVISO: ALLOWED_CHAT_IDS está vacío; cualquiera puede usar este bot y gastar tu cuota de GMGN.', flush=True)
    try:
        Bot(token, scanner, allowed).run()
    except KeyboardInterrupt:
        print('Bot detenido.')


if __name__ == '__main__':
    main()
