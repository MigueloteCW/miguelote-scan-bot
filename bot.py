"""Miguelote Scan: read-only multichain scanner. Python 3.11+, stdlib only."""
import argparse
import struct
from concurrent.futures import ThreadPoolExecutor
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


def fetch(url, payload=None, timeout=20, extra_headers=None):
    headers = {'User-Agent': 'VerazBot/0.1', 'Accept': 'application/json'}
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

    def card_snapshot(self,chat,message_id,value=None):
        key=f'card:{chat}:{message_id}'
        if value is not None:
            self.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',(key,json.dumps(value)))
            self.db.commit()
            return
        row=self.db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone()
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
        key=('dex', normalized(mint))
        if key in self.cache and time.time()-self.cache[key][0]<60:
            return self.cache[key][1]
        if time.time()<self.cache.get(('dex_pause',),0):
            raise DataError('DexScreener en pausa temporal por límite de consultas.')
        try:
            data=self.transport('https://api.dexscreener.com/latest/dex/search?q='+urllib.parse.quote(mint,safe=''))
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
            result=self.transport('https://aser.trade/api/'+key[1]+'/'+urllib.parse.quote(mint,safe=''))
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
            if len(key)>=3 and key[0] in ('gmgn','aser') and key[-1]==normalized(mint):
                self.cache.pop(key,None)
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
        except DataError:pass
        try:
            rows=[p for p in self.dex_pairs(mint) if p['chainId']==self.chain]
            if rows:
                pair=dict(max(rows,key=lambda p:number((p.get('liquidity') or {}).get('usd')) or 0))
                pair.update(gmgn_info={},source='DexScreener')
                return pair,rows,self.cache[('dex',normalized(mint))][0]
        except DataError:pass
        try:
            return self.gecko_market(mint)
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

    def gmgn_query(self, command, mint, wallet=None):
        if not valid_contract(mint) or self.chain not in GMGN_CHAINS:
            raise DataError('Sin cobertura de GMGN para esta red.')
        if not self.gmgn:
            raise DataError('GMGN pendiente de configurar: hace falta su clave API de consulta.')
        if command=='dev_sales' and not valid_contract(wallet):raise DataError('Cartera DEV no identificada.')
        key = ('gmgn', self.chain, command, normalized(wallet), normalized(mint)) if command=='dev_sales' else ('gmgn', self.chain, command, normalized(mint))
        if key in self.cache and time.time() - self.cache[key][0] < 60:
            return self.cache[key][1]
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


def tax_line(chain,sources):
    tax=tax_details(chain,sources)
    if chain=='solana':
        return '🧾 TAX C/V: — · Fee transferencia: '+percentage(tax['transfer'])
    return '🧾 TAX C/V: '+percentage(tax['buy'])+' / '+percentage(tax['sell'])


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
    elif score<45:verdict='RIESGO ALTO'
    elif score<75:verdict='PRECAUCIÓN'
    elif evidence<5 or len(sources)<2:verdict='ANÁLISIS PARCIAL'
    else:verdict='SIN ALERTAS CRÍTICAS DETECTADAS'
    return {'score':score,'verdict':verdict,'flags':[name for name,_ in flags],
            'coverage':'parcial' if evidence<5 or len(sources)<2 else 'múltiples fuentes'}


def security_text(mint,chain,sources,market=None):
    result=security_assessment(chain,sources,market)
    tax=tax_details(chain,sources)
    lines=['🔍 <b>MIGUELOTE SCAN · SEGURIDAD</b>',
           f'Red: <b>{esc(chain.upper())}</b>',f'<code>{esc(mint,96)}</code>','',
           '🛡️ <b>Audit automático · índice heurístico</b>']
    if result['score'] is None:
        lines.append('Puntuación: — · '+result['verdict'])
    else:
        lines.append(f'Puntuación parcial: <b>{result["score"]}/100</b> · {result["verdict"]}')
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
        parts.append(str(ns)+' señal'+('es' if ns!=1 else '')+' · 1ª call MC '+value)
    if nt:parts.append(str(nt)+' mención'+('es' if nt!=1 else '')+' comunidad')
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


def probe_image_size(url):
    try:
        request=urllib.request.Request(url,headers={'User-Agent':'MigueloteScan/1.0','Range':'bytes=0-65535'})
        with urllib.request.urlopen(request,timeout=2) as response:
            return image_dimensions(response.read(65536))
    except (OSError,ValueError):return None


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
            f'├ LIQ/MC: <b>{liquidity_ratio}</b>',
            f'├ VOL/LIQ 24h: <b>{turnover}</b>',
            f'└ Boosts DEX: <b>{count(boosts.get("active"))}</b>']


def comparison_snapshot(mint,pair,fetched,info):
    return {'mint':mint,'chain':pair.get('chainId'),'source':pair.get('source'),
            'pool':pair.get('pairAddress'),'time':fetched,'price':number(pair.get('priceUsd')),
            'liquidity':number((pair.get('liquidity') or {}).get('usd')),
            'holders':number(info.get('holder_count')),
            'top10':number((info.get('stat') or {}).get('top_10_holder_rate'))}


def comparison_text(old,new):
    if not old or any(old.get(k)!=new.get(k) for k in ('mint','chain')):
        return '🔄 <b>Desde la consulta anterior</b>\nComparación disponible en la próxima actualización.'
    elapsed=max(0,int(new['time']-old['time']))
    age=f'{elapsed}s' if elapsed<60 else f'{elapsed//60} min' if elapsed<3600 else f'{elapsed//3600}h {(elapsed%3600)//60} min'
    comparable=old.get('source')==new.get('source') and old.get('pool')==new.get('pool')
    def percent(key):
        a,b=number(old.get(key)),number(new.get(key))
        return f'{(b/a-1)*100:+.2f}%' if comparable and a is not None and a>0 and b is not None and b>=0 else '—'
    a,b=number(old.get('holders')),number(new.get('holders'))
    holders=f'{b-a:+.0f}' if comparable and a is not None and b is not None and min(a,b)>=0 else '—'
    a,b=number(old.get('top10')),number(new.get('top10'))
    top=f'{a*100:.2f}% → {b*100:.2f}%' if comparable and a is not None and b is not None and 0<=a<=1 and 0<=b<=1 else '—'
    return (f'🔄 <b>Desde la consulta anterior · {age}</b>\n'
            f'Precio: {percent("price")}\nLiquidez: {percent("liquidity")}\n'
            f'Holders: {holders}\nTop 10: {top}')


def audit_summary(chain,sources,market=None):
    result=security_assessment(chain,sources,market)
    status={
        'RIESGO CRÍTICO':'🔴 Crítico',
        'RIESGO ALTO':'🔴 Alto',
        'PRECAUCIÓN':'🟠 Precaución',
        'ANÁLISIS PARCIAL':'🟡 Parcial',
        'SIN DATOS SUFICIENTES':'⚪ Sin datos',
        'SIN ALERTAS CRÍTICAS DETECTADAS':'🟢 Sin alertas críticas',
    }[result['verdict']]
    if result['coverage']=='parcial' and result['verdict'] in ('RIESGO CRÍTICO','RIESGO ALTO','PRECAUCIÓN'):
        status+=' · parcial'
    return '🛡️ <b>Audit automático</b>: '+status


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
           '🟩 <b>Token Stats</b>',
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
    if links: lines += ['', '🌐 <b>Socials</b>', ' · '.join(links)]
    lines += ['', audit_summary(chain,pair.get('security_sources') or {},pair), tax_line(chain,pair.get('security_sources') or {}), '🟦 <b>Distribución</b>',
              f'👥 Top 10: <b>{ratio(stat.get("top_10_holder_rate"))}</b>',
              '🎯 '+pair.get('sniper_text','🎯 Snipers —').replace('🎯 ',''),
              '📦 '+pair.get('bundler_text','Bundled —').replace('🎯 ',''),
              f'🧑‍💻 Equipo: {ratio(stat.get("dev_team_hold_rate"))}',
              '', f'P: <code>{short(pair.get("pairAddress"))}</code>',
              f'DEV: <code>{short(dev.get("creator_address"))}</code>',
              'DEV SELL: <b>'+pair.get('dev_sell_text','⚪ Sin verificar')+'</b>',
              '',f'<code>{mint}</code>',
              '<i>🔄 Última consulta: '+datetime.fromtimestamp(fetched,timezone.utc).strftime('%d/%m/%Y %H:%M:%S UTC')+'</i>']
    text='\n'.join(line for line in lines if line)
    summary=aser_summary(pair.get('aser_signals'))
    if summary:
        position=next(i for i,line in enumerate(lines) if line.startswith('P: <code>'))
        extended='\n'.join(line for line in lines[:position]+[summary]+lines[position:] if line)
        visible=html.unescape(re.sub(r'<[^>]+>','',extended))
        if len(visible.encode('utf-16-le'))//2<=1024:text=extended
    return text


def sources_text(pair, fetched, gmgn_note=''):
    lines = ['<b>Fuentes y alcance</b>', f'Mercado de esta ficha: {esc(pair.get("source","GMGN"))}. Red: {esc(pair.get("chainId","solana"))}. Imágenes: ASER, GMGN, DexScreener (cabeceras, imagen del par y perfiles) y GeckoTerminal/CoinGecko. Coincidencia por contrato y red; cobertura variable. Fuentes de reserva solo si falla el envío de las imágenes prioritarias.',
             'Con GMGN: MC = precio × suministro circulante; FDV = precio × suministro total. Con DexScreener: valores reportados, sin sustituir MC por FDV.',
             'Precio y actividad: GMGN. Variaciones calculadas con sus precios al inicio de cada período. Liquidez del pool principal indicado por GMGN.',
             'Holders, Top 10 y etiquetas sniper: GMGN cuando está disponible. Una etiqueta no prueba que sea un bot.',
             'ATH de precio: reportado por GMGN. MC al precio ATH marcado ≈ es una estimación con suministro circulante actual, no el MC histórico. Snipers: suma de participaciones de holders etiquetados por GMGN, consulta limitada a 100 carteras; una lista de 100 es parcial.',
             'Actividad del par: C/V son cantidades de compras/ventas, no dólares ni personas únicas. Ventanas 5m y 1h, edad del par y boosts: DexScreener, solo para el mismo pool y red. Boosts son promoción, no garantía de calidad. LIQ/MC = liquidez / capitalización × 100; VOL/LIQ = volumen 24h / liquidez. Son relaciones descriptivas, no medidas de seguridad.',
             'DEV SELL: cartera creadora identificada por GMGN. Sí indica estado sell en token info o una venta del token en su historial de actividad. No detectado indica que la consulta filtrada por ventas devuelve una lista vacía sin más páginas; no certifica que nunca vendió ni cubre otras carteras del equipo, transferencias o ventas fuera del historial del proveedor. No es una valoración de seguridad. Sin verificar significa que faltan datos o no se pudo consultar.',
             'Desde la consulta anterior compara la última ficha enviada o editada con éxito en ese mensaje. Si el servidor pierde el registro local, la comparación comienza en la siguiente actualización. Cambios de proveedor o pool se muestran como — para no mezclar referencias.',
             'Edad: fecha de creación del token según GMGN; no se sustituye por la edad del pool. Equipo: suministro en carteras etiquetadas como equipo. No se calcula una puntuación de auditoría ni se equipara volumen de bundlers con suministro retenido. Bubble Maps abre el mapa externo si el proyecto tiene cobertura.']
    lines.append('ASER: señales y tesis devueltas para el contrato exacto en Solana. Las tesis son opiniones de usuarios, no señales oficiales. La primera call es la señal más antigua del historial devuelto por ASER, no la primera publicación del grupo ni una garantía de cobertura histórica completa. No implica que fuera una recomendación de compra. Si falta espacio bajo la imagen, el resumen queda en el botón ASER. Caché de hasta 60 segundos; Actualizar renueva la consulta salvo pausa por errores o cuota.')
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
        'Pega un contrato, escribe $CHOP o utiliza /scan RED:CONTRATO. Ejemplo: base:0x…\n'
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

    def send_card(self, chat, text, markup, logo, fallback=None):
        logos = logo if isinstance(logo, list) else [logo]
        if self.scanner and hasattr(self.scanner,'rank_images'):
            logos,sharp=self.scanner.rank_images(logos)
            if not sharp and fallback:
                logos,_=self.scanner.rank_images(logos+fallback())
                fallback=None
        sent_photo=False
        for logo in logos:
            if not isinstance(logo,str) or not logo.startswith('https://') or len(logo)>=2048:
                continue
            payload = {'chat_id': chat, 'photo': logo}
            visible = html.unescape(re.sub(r'<[^>]+>', '', text))
            fits = len(visible.encode('utf-16-le')) // 2 <= 1024
            if fits:
                payload.update(caption=text, parse_mode='HTML', reply_markup=markup)
            try:
                result = self.api('sendPhoto', payload)
                if fits:
                    return result
                sent_photo=True
                break
            except DataError:
                continue
        if not sent_photo and fallback:
            return self.send_card(chat,text,markup,fallback())
        return self.send(chat, text, markup)

    def edit_card(self,msg,text,markup):
        payload={'chat_id':msg['chat']['id'],'message_id':msg['message_id'],
                 'parse_mode':'HTML','reply_markup':markup}
        if msg.get('photo'):
            # Keep the existing image. Never post a replacement card after an edit failure.
            visible=html.unescape(re.sub(r'<[^>]+>','',text))
            if len(visible.encode('utf-16-le'))//2>1024:
                raise DataError('La ficha actualizada supera el espacio de esta foto. Se conserva la anterior.')
            payload['caption']=text
            return self.api('editMessageCaption',payload)
        payload.update(text=text,link_preview_options={'is_disabled':True})
        return self.api('editMessageText',payload)

    def callback_notice(self,callback,text):
        try:return self.api('answerCallbackQuery',{'callback_query_id':callback['id'],'text':text[:180],'show_alert':True})
        except DataError:return None

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
            try:self.api('answerCallbackQuery', {'callback_query_id': callback['id']})
            except DataError:pass
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
        if action not in ('scan', 'ath', 'holders', 'snipers', 'sources', 'security', 'srefresh', 'aser'):
            return self.send(chat, HELP)
        chain = None
        if arg.startswith('ref_'):
            ref=self.scanner.store.reference(key=arg[4:])
            if not ref and (refreshing or action in ('security','srefresh','aser')):
                # Old buttons refer to local state, which Render may discard on restart.
                body=msg.get('text') or msg.get('caption') or ''
                addresses=[line.strip() for line in body.splitlines() if valid_contract(line.strip())]
                network=re.search(r'^([A-Za-z0-9-]+) ·',body,re.M) or re.search(r'^Red:\s*([A-Za-z0-9-]+)',body,re.M)
                if len(addresses)==1 and network:
                    ref={'chat':chat,'chain':network.group(1).lower(),'mint':addresses[0]}
            if not ref or ref.get('chat') != chat:
                if refreshing:return self.callback_notice(callback,'Esta ficha ha caducado. Envía de nuevo el contrato.')
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
        except DataError as error:
            return self.send(chat,esc(str(error),500))
        self.scanner.chain=chain
        if time.monotonic() - self.last_request.get(user, -100) < 3:
            if refreshing:return self.callback_notice(callback,'Espera unos segundos antes de actualizar.')
            return self.send(chat, 'Espera unos segundos antes de la siguiente consulta.')
        self.last_request[user] = time.monotonic()
        try:
            if action == 'scan':
                pair, _, fetched = (self.scanner.refresh_market(arg) if refreshing else self.scanner.market(arg))
                pair = self.scanner.enrich_activity(arg,pair)
                info = pair['gmgn_info']
                pair['security_sources']=self.scanner.security_evidence(chain,arg,force=refreshing)
                try:
                    pair['sniper_text'] = self.scanner.current_snipers(arg)
                except DataError:
                    pair['sniper_text'] = '🎯 Snipers —'
                try:
                    pair['bundler_text']=self.scanner.current_tag_holdings(arg,'bundler')
                except DataError:
                    pair['bundler_text']='Bundled —'
                pair['dev_sell_text']=self.scanner.dev_sell(arg,info)
                if chain=='solana':
                    try:pair['aser_signals']=self.scanner.aser_signals(arg)
                    except DataError:pass
                current=comparison_snapshot(arg,pair,fetched,info)
                text=card(arg,pair,fetched,info)
                markup=self.network_keyboard(chat,arg,pair,user)
                if refreshing:
                    previous=self.scanner.store.card_snapshot(chat,msg['message_id'])
                    text+='\n'+comparison_text(previous,current)
                    result=self.edit_card(msg,text,markup)
                    if result:
                        self.scanner.store.card_snapshot(chat,msg['message_id'],current)
                    return result
                result=self.send_card(chat,text,markup,self.scanner.images(arg,info),
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
            if refreshing:return self.callback_notice(callback,'No se pudo actualizar: '+str(error))
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

