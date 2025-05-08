from flask import Flask, render_template, request, jsonify
import aiohttp
import asyncio
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin
import socket
import dns.asyncresolver
import whois
from datetime import datetime
import json
from aiohttp import ClientSession, ClientTimeout
import logging
import concurrent.futures
import ssl
import OpenSSL
from collections import defaultdict
import hashlib
import urllib.robotparser
import tldextract
import requests
import os
from pathlib import Path
import time
import random

app = Flask(__name__)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
REQUEST_HEADERS = {'User-Agent': USER_AGENT}
TIMEOUT = ClientTimeout(total=15)
MAX_CONCURRENT_TASKS = 15
JS_ANALYSIS_DEPTH = 3
MAX_JS_FILES_PER_PAGE = 50
JS_CACHE_DIR = "js_cache"

os.makedirs(JS_CACHE_DIR, exist_ok=True)

JS_ANALYSIS_PATTERNS = {
    'api_endpoints': [
        r'(?:https?:)?//[a-zA-Z0-9\-\.]+(?:/[a-zA-Z0-9_\-\.~]+)+\??[a-zA-Z0-9_\-\.~=&]*',
        r'/(?:api|v[0-9]|rest|graphql|query|data|ws|socket|rpc|ajax|service)/[a-zA-Z0-9_\-\.~]+',
        r'\.(?:get|post|put|delete|patch|head|options|fetch|request)\(["\'][^"\']+["\']\)',
        r'fetch\(["\'][^"\']+["\']\)',
        r'axios\.(?:get|post|put|delete)\(["\'][^"\']+["\']\)',
        r'XMLHttpRequest\(\)\.open\(["\'][^"\']+["\']',
        r'\.(?:apiUrl|baseUrl|endpoint)\s*[:=]\s*["\'][^"\']+["\']',
        r'websocket\s*[:=]\s*["\']wss?://[^"\']+["\']',
        r'socket\.(?:on|emit|connect)\s*\(["\'][^"\']+["\']\)',
        r'\.(?:url|uri|path|route)\s*[:=]\s*["\'][^"\']+["\']',
        r'process\.env\.[A-Z0-9_]+\s*\+\s*["\'][^"\']+["\']'
    ],
    
    'sensitive_data': [
        r'(?:password|passwd|pwd|secret|token|key|credential|auth|login|session)\s*[:=]\s*["\'][^"\']{6,}["\']',
        r'(?:aws_access_key_id|aws_secret_access_key|api_key|client_secret|private_key|public_key)\s*[:=]\s*["\'][^"\']{10,}["\']',
        r'(?:bearer\s+[a-zA-Z0-9_\-\.=]{20,})',
        r'(?:basic\s+[a-zA-Z0-9=]{10,})',
        r'(?:encryption_key|decryption_key|salt|iv|nonce)\s*[:=]\s*["\'][^"\']{8,}["\']',
        r'(?:database|db)_(?:user|name|host|port|password)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?:stripe|paypal|braintree)_(?:key|secret|token)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?:oauth|saml)_(?:client_id|client_secret|redirect_uri)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?:jdbc|odbc|mongodb|postgresql|mysql|redis)://[a-zA-Z0-9_\-]+:[^@\s]+@',
        r'(?:access|refresh)_token\s*[:=]\s*["\'][^"\']{20,}["\']',
        r'(?:license|activation)_key\s*[:=]\s*["\'][^"\']{12,}["\']'
    ],
    
    'jwt_tokens': [
        r'eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}',
        r'(?:access|refresh|id)_token\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']',
        r'jwt\.(?:sign|verify)\s*\([^)]+\)',
        r'jsonwebtoken\.[a-zA-Z]+\s*\([^)]+\)'
    ],
    
    'debug_flags': [
        r'debug\s*=\s*true',
        r'debugMode\s*:\s*true',
        r'devMode\s*:\s*true',
        r'testing\s*=\s*true',
        r'console\.(?:log|debug|info|warn|error|trace|dir|table|group|groupEnd)\s*\([^)]+\)',
        r'logger\.(?:debug|info|warn|error)\s*\([^)]+\)',
        r'process\.env\.NODE_ENV\s*!==\s*["\']production["\']',
        r'process\.env\.DEBUG\s*=\s*["\'][^"\']+["\']',
        r'window\.DEBUG\s*=\s*true',
        r'localStorage\.debug\s*=\s*["\'][^"\']+["\']'
    ],
    
    'version_info': [
        r'version\s*[:=]\s*["\'][0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9]+)?["\']',
        r'@version\s*[:=]\s*["\'][0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9]+)?["\']',
        r'release\s*[:=]\s*["\'][0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9]+)?["\']',
        r'appVersion\s*[:=]\s*["\'][0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9]+)?["\']',
        r'build(?:Number|Version)\s*[:=]\s*["\'][0-9a-zA-Z\.\-]+["\']',
        r'git(?:hub)?_(?:sha|commit|tag|version)\s*[:=]\s*["\'][0-9a-fA-F]+["\']'
    ],
    
    'hardcoded_credentials': [
        r'user(name)?\s*[:=]\s*["\'][^"\']+["\']\s*,\s*pass(word)?\s*[:=]\s*["\'][^"\']+["\']',
        r'(?:username|user|login|email)\s*[:=]\s*["\'][^"\']+["\']\s*[\r\n]\s*(?:password|pass|pwd)\s*[:=]\s*["\'][^"\']+["\']',
        r'(?:db|database)_(?:user|pass|name)\s*[:=]\s*["\'][^"\']+["\']',
        r'mysql\.createConnection\s*\(\s*{[^}]*user\s*:\s*["\'][^"\']+["\'][^}]*password\s*:\s*["\'][^"\']+["\']',
        r'mongodb(?:\\+srv)?://[^:]+:[^@]+@',
        r'postgres(?:ql)?://[^:]+:[^@]+@',
        r'redis://[^:]+:[^@]+@'
    ],
    
    'crypto_issues': [
        r'crypto\.createCipher\s*\([^)]+\)',
        r'crypto\.createDecipher\s*\([^)]+\)',
        r'MD5\s*\([^)]+\)',
        r'SHA1\s*\([^)]+\)',
        r'createHash\s*\(\s*["\'](?:md5|sha1)["\']\s*\)',
        r'Math\.random\s*\(\s*\)\s*for\s*crypto',
        r'weak\s*crypto\s*[:=]\s*true',
        r'crypto\.getRandomValues\s*not\s*used',
        r'hardcoded\s*(?:iv|salt|key)\s*[:=]\s*["\'][^"\']+["\']',
        r'PBKDF2\s*with\s*low\s*iteration\s*count'
    ],
    
    'config_issues': [
        r'process\.env\.[A-Z0-9_]+\s*[:=]\s*["\'][^"\']+["\']',
        r'config\.(?:json|js|yaml|yml)\s*with\s*sensitive\s*data',
        r'(?:allow|enable)_(?:debug|test|admin)\s*[:=]\s*true',
        r'cors\s*[:=]\s*{\s*origin\s*:\s*["\']\\*["\']',
        r'secure\s*[:=]\s*false',
        r'httpOnly\s*[:=]\s*false',
        r'sameSite\s*[:=]\s*["\']none["\']',
        r'csrf\s*[:=]\s*false',
        r'rateLimit\s*[:=]\s*false',
        r'(?:disable|skip)_(?:auth|security)\s*[:=]\s*true'
    ],
    
    'ssrf_patterns': [
        r'(?:http|https)://(?:127\.0\.0\.1|localhost|192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1]))',
        r'(?:url|uri|endpoint)\s*[:=]\s*["\'](?:http|https)://(?:internal|private|dev)',
        r'request\s*\(\s*["\'][^"\']*localhost[^"\']*["\']',
        r'fetch\s*\(\s*["\'][^"\']*127\.0\.0\.1[^"\']*["\']',
        r'axios\.get\s*\(\s*["\'][^"\']*192\.168[^"\']*["\']',
        r'new\s+URL\s*\(\s*["\'][^"\']*internal[^"\']*["\']'
    ],
    
    'prototype_pollution': [
        r'Object\.assign\s*\(\s*[^,]+,\s*[^)]+\)',
        r'Object\.merge\s*\(\s*[^,]+,\s*[^)]+\)',
        r'Object\.deepAssign\s*\(\s*[^,]+,\s*[^)]+\)',
        r'JSON\.parse\s*\(\s*[^)]+\)\s*with\s*untrusted\s*input',
        r'for\s*\(\s*var\s+\w+\s+in\s+[^)]+\)\s*without\s*hasOwnProperty',
        r'__proto__\s*[:=]\s*[^;]+',
        r'constructor\.prototype\s*[:=]\s*[^;]+',
        r'merge\s*\(\s*[^,]+,\s*[^)]+\)\s*without\s*prototype\s*check'
    ],
    
    'deserialization': [
        r'JSON\.parse\s*\(\s*[^)]+\)\s*without\s*validation',
        r'eval\s*\(\s*[^)]+\)\s*for\s*deserialization',
        r'Function\s*\(\s*[^)]+\)\s*\(\s*[^)]+\)',
        r'vm\.runInThisContext\s*\(\s*[^)]+\)',
        r'deserialize\s*\(\s*[^)]+\)',
        r'XML\.parse\s*\(\s*[^)]+\)',
        r'YAML\.load\s*\(\s*[^)]+\)',
        r'CSV\.parse\s*\(\s*[^)]+\)'
    ],
    
    'log_injection': [
        r'console\.log\s*\(\s*[^)]+\)\s*with\s*untrusted\s*input',
        r'logger\.(?:info|warn|error)\s*\(\s*[^)]+\)\s*with\s*untrusted\s*input',
        r'log4js\.getLogger\s*\(\s*[^)]+\)\s*with\s*untrusted\s*input',
        r'winston\.createLogger\s*\(\s*[^)]+\)\s*with\s*untrusted\s*input',
        r'morgan\s*\(\s*[^)]+\)\s*with\s*untrusted\s*format'
    ],
    
    'regex_dos': [
        r'new\s+RegExp\s*\(\s*["\'][^"\']*\\+[^"\']*["\']\s*,\s*["\']g?i?m?["\']\s*\)',
        r'/([^/\\]*(?:\\.[^/\\]*)*)/(g?i?m?)\s*with\s*complex\s*regex',
        r'RegExp\s*\(\s*["\'][^"\']*{\d+,\d+}[^"\']*["\']\s*\)',
        r'/([^/\\]*(?:\\.[^/\\]*)*)/.test\s*\(\s*[^)]+\)\s*with\s*long\s*input',
        r'String\.prototype\.(?:match|replace|search|split)\s*\(\s*[^)]+\)\s*with\s*complex\s*regex'
    ]
}

TECH_DETECTION_PATTERNS = {
    'wordpress': [
        ('meta', {'name': 'generator', 'content': 'WordPress'}),
        ('link', {'href': re.compile(r'wp-(content|includes)')}),
        ('script', {'src': re.compile(r'wp-includes/js')}),
        re.compile(r'/wp-content/themes/'),
        re.compile(r'/wp-content/plugins/'),
        re.compile(r'wpNonce'),
        re.compile(r'wpAjax')
    ],
    'joomla': [
        ('meta', {'name': 'generator', 'content': 'Joomla'}),
        re.compile(r'/media/system/js/'),
        re.compile(r'/templates/'),
        ('script', {'src': re.compile(r'media/system/js/')}),
        re.compile(r'Joomla\.[a-zA-Z]')
    ],
    'drupal': [
        ('meta', {'name': 'Generator', 'content': 'Drupal'}),
        re.compile(r'/sites/default/files/'),
        re.compile(r'/misc/drupal.js'),
        re.compile(r'Drupal\.settings'),
        re.compile(r'Drupal\.behaviors')
    ],
    'laravel': [
        re.compile(r'/vendor/laravel/'),
        ('meta', {'name': 'csrf-token'}),
        re.compile(r'window\.Laravel\s*='),
        re.compile(r'axios\.defaults\.headers\.common\s*=\s*{[^}]*X-CSRF-TOKEN')
    ],
    'react': [
        ('script', {'src': re.compile(r'react(.min)?.js')}),
        re.compile(r'__reactInternalInstance'),
        re.compile(r'ReactDOM\.render\('),
        re.compile(r'createReactClass\(')
    ],
    'angular': [
        ('script', {'src': re.compile(r'angular(.min)?.js')}),
        re.compile(r'ng-[\w-]+'),
        re.compile(r'angular\.module\('),
        re.compile(r'\$scope\.')
    ],
    'vue': [
        ('script', {'src': re.compile(r'vue(.min)?.js')}),
        re.compile(r'v-[\w-]+'),
        re.compile(r'new Vue\('),
        re.compile(r'Vue\.component\(')
    ],
    'jquery': [
        ('script', {'src': re.compile(r'jquery(.min)?.js')}),
        re.compile(r'\$\([\'"].+[\'"]\)'),
        re.compile(r'jQuery\([\'"].+[\'"]\)')
    ],
    'bootstrap': [
        ('link', {'href': re.compile(r'bootstrap(.min)?.css')}),
        ('script', {'src': re.compile(r'bootstrap(.min)?.js')}),
        re.compile(r'data-toggle="[^"]+"'),
        re.compile(r'data-target="[^"]+"')
    ]
}

@app.template_filter('format_date')
def format_date_filter(date_str):
    if not date_str or date_str == 'Unknown':
        return date_str
    try:
        for fmt in ('%Y-%m-%d', '%Y%m%d%H%M%SZ', '%Y-%m-%d %H:%M:%S'):
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.strftime('%Y-%m-%d')
            except ValueError:
                continue
        return date_str
    except Exception:
        return date_str

@app.template_filter('format_ssl_date')
def format_ssl_date_filter(date_str):
    if not date_str or date_str == 'Unknown':
        return date_str
    try:
        if isinstance(date_str, bytes):
            date_str = date_str.decode('utf-8')
        dt = datetime.strptime(date_str, '%Y%m%d%H%M%SZ')
        return dt.strftime('%Y-%m-%d')
    except Exception:
        return date_str

def get_domain_info_sync(domain):
    try:
        w = whois.whois(domain)
        
        def process_date(date):
            if not date:
                return None
            if isinstance(date, list):
                return date[0] if date else None
            return date
        
        creation_date = process_date(w.creation_date)
        expiration_date = process_date(w.expiration_date)
        
        name_servers = w.name_servers
        if name_servers:
            if isinstance(name_servers, str):
                name_servers = [name_servers]
            name_servers = sorted(list(set(ns.lower() for ns in name_servers if ns)))
        
        return {
            'registrar': w.registrar if w.registrar else 'Unknown',
            'creation_date': creation_date.strftime('%Y-%m-%d') if creation_date else 'Unknown',
            'expiration_date': expiration_date.strftime('%Y-%m-%d') if expiration_date else 'Unknown',
            'name_servers': name_servers if name_servers else ['Unknown'],
            'updated_date': process_date(w.updated_date).strftime('%Y-%m-%d') if process_date(w.updated_date) else 'Unknown',
            'status': w.status if w.status else 'Unknown'
        }
    except Exception as e:
        logger.error(f"Error getting whois info for {domain}: {e}")
        return {
            'registrar': 'Unknown',
            'creation_date': 'Unknown',
            'expiration_date': 'Unknown',
            'name_servers': ['Unknown'],
            'updated_date': 'Unknown',
            'status': 'Unknown'
        }

async def fetch_url(session, url, method='GET', headers=None, allow_redirects=True):
    cache_key = hashlib.md5(url.encode()).hexdigest()
    cache_file = os.path.join(JS_CACHE_DIR, cache_key)
    
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            return f.read()
    
    try:
        async with session.request(
            method, 
            url, 
            headers=headers or REQUEST_HEADERS, 
            allow_redirects=allow_redirects,
            timeout=TIMEOUT
        ) as response:
            if response.status == 200:
                content = await response.text()
                
                with open(cache_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                return content
            return None
    except Exception as e:
        logger.error(f"Error fetching {url}: {e}")
        return None

async def get_subdomains_from_crtsh(domain):
    subdomains = set()
    max_retries = 2
    retry_delay = 1
    
    async def fetch_with_retry(url, is_json=True, verify_ssl=True, headers=None):
        for attempt in range(max_retries):
            try:
                connector = aiohttp.TCPConnector(
                    ssl=verify_ssl,
                    force_close=True,
                    enable_cleanup_closed=True
                )
                
                timeout = aiohttp.ClientTimeout(total=15)
                
                async with aiohttp.ClientSession(
                    connector=connector, 
                    timeout=timeout,
                    headers=headers or REQUEST_HEADERS
                ) as session:
                    async with session.get(url) as response:
                        if response.status == 200:
                            if is_json:
                                try:
                                    return await response.json()
                                except:
                                    text = await response.text()
                                    return json.loads(text)
                            return await response.text()
                        elif response.status >= 500:
                            logger.debug(f"Attempt {attempt + 1} for {url} failed with status {response.status}")
                        else:
                            break
            except Exception as e:
                logger.debug(f"Attempt {attempt + 1} for {url} failed: {str(e)}")
                if not verify_ssl and "SSL" in str(e):
                    break
            
            if attempt < max_retries - 1:
                await asyncio.sleep(retry_delay * (attempt + 1))
        
        if verify_ssl:
            logger.debug(f"Trying {url} without SSL verification")
            try:
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    headers=headers or REQUEST_HEADERS
                ) as session:
                    async with session.get(url) as response:
                        if response.status == 200:
                            if is_json:
                                return await response.json()
                            return await response.text()
            except Exception as e:
                logger.debug(f"Failed to fetch {url} without SSL: {str(e)}")
        
        return None

    reliable_sources = [
        {
            'url': f"https://crt.sh/?q=%25.{domain}&output=json",
            'is_json': True,
            'parser': lambda data: {name.lower() for item in data if isinstance(data, list) 
                                  for name in item.get('name_value', '').split('\n') 
                                  if name.strip() and not name.startswith('*')}
        },
        {
            'url': f"https://jldc.me/anubis/subdomains/{domain}",
            'is_json': True,
            'parser': lambda data: {f"{sub}.{domain}".lower() for sub in data} if isinstance(data, list) else set()
        },
        {
            'url': f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
            'is_json': True,
            'parser': lambda data: {name.lower() for entry in data if isinstance(data, list)
                                 for name in entry.get('dns_names', [])}
        },
        {
            'url': f"https://dns.bufferover.run/dns?q=.{domain}",
            'is_json': True,
            'parser': lambda data: {sub.lower() for sub in data.get('FDNS_A', []) if f".{domain}" in sub}
        },
        {
            'url': f"https://rapiddns.io/subdomain/{domain}?full=1",
            'is_json': False,
            'parser': lambda data: set(re.findall(rf">([a-zA-Z0-9.-]+\.{re.escape(domain)})<", data))
        },
        {
            'url': f"https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=100",
            'is_json': True,
            'parser': lambda data: {sub.lower() for sub in data.get('data', []) if isinstance(data.get('data'), list)}
        },
        {
            'url': f"https://sonar.omnisint.io/subdomains/{domain}",
            'is_json': True,
            'parser': lambda data: {sub.lower() for sub in data if isinstance(data, list)}
        },
        {
            'url': f"https://api.hackertarget.com/hostsearch/?q={domain}",
            'is_json': False,
            'parser': lambda data: {line.split(',')[0].lower() for line in data.split('\n') if line.strip()}
        },
        {
            'url': f"https://riddler.io/search/exportcsv?q=pld:{domain}",
            'is_json': False,
            'parser': lambda data: {line.split(',')[2].lower().strip('"') for line in data.split('\n')[1:] if line.strip()}
        },
        {
            'url': f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            'is_json': True,
            'parser': lambda data: {sub.lower() for sub in data.get('subdomains', [])}
        },
        {
            'url': f"https://www.pagesinventory.com/search/?s={domain}",
            'is_json': False,
            'parser': lambda data: set(re.findall(rf">([a-zA-Z0-9.-]+\.{re.escape(domain)})<", data))
        },
        {
            'url': f"https://census-labs.com/news/2020/12/15/web-archives-as-a-source-of-subdomains/",
            'is_json': False,
            'parser': lambda data: set(re.findall(rf"([a-zA-Z0-9.-]+\.{re.escape(domain)})", data))
        }
    ]
    
    fallback_sources = [
        {
            'url': f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            'is_json': True,
            'verify_ssl': True,
            'parser': lambda data: {f"{sub}.{domain}".lower() for sub in data.get('subdomains', [])}
        },
        {
            'url': f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
            'is_json': True,
            'verify_ssl': True,
            'parser': lambda data: {sub.lower() for sub in data.get('results', [])}
        },
        {
            'url': f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey",
            'is_json': True,
            'verify_ssl': False,
            'parser': lambda data: {url.split('/')[0].split(':')[0].lower() for url in data if isinstance(data, list) and len(url) > 0}
        },
        {
            'url': f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
            'is_json': True,
            'verify_ssl': True,
            'parser': lambda data: {result.get('page', {}).get('domain', '').lower() 
                                 for result in data.get('results', [])}
        }
    ]

    additional_sources = [
        {
            'url': f"https://www.sublist3r.com/search.php?domain={domain}",
            'is_json': False,
            'parser': lambda data: set(re.findall(rf">([a-zA-Z0-9.-]+\.{re.escape(domain)})<", data))
        },
        {
            'url': f"https://www.google.com/search?q=site:{domain}&num=100",
            'is_json': False,
            'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            'parser': lambda data: set(re.findall(rf"([a-zA-Z0-9-]+\.{re.escape(domain)})", data))
        },
        {
            'url': f"https://www.bing.com/search?q=site:{domain}&count=100",
            'is_json': False,
            'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            'parser': lambda data: set(re.findall(rf"([a-zA-Z0-9-]+\.{re.escape(domain)})", data))
        },
        {
            'url': f"https://search.yahoo.com/search?p=site:{domain}&n=100",
            'is_json': False,
            'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            'parser': lambda data: set(re.findall(rf"([a-zA-Z0-9-]+\.{re.escape(domain)})", data))
        },
        {
            'url': f"https://www.baidu.com/s?wd=site:{domain}&pn=0&rn=100",
            'is_json': False,
            'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            'parser': lambda data: set(re.findall(rf"([a-zA-Z0-9-]+\.{re.escape(domain)})", data))
        },
        {
            'url': f"https://www.shodan.io/search?query=hostname:{domain}",
            'is_json': False,
            'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            'parser': lambda data: set(re.findall(rf"([a-zA-Z0-9-]+\.{re.escape(domain)})", data))
        },
        {
            'url': f"https://www.zoomeye.org/searchResult?q=site:{domain}",
            'is_json': False,
            'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
            'parser': lambda data: set(re.findall(rf"([a-zA-Z0-9-]+\.{re.escape(domain)})", data))
        }
    ]

    all_sources = reliable_sources + additional_sources
    
    tasks = []
    for source in all_sources:
        task = asyncio.create_task(fetch_with_retry(
            source['url'],
            is_json=source.get('is_json', True),
            verify_ssl=source.get('verify_ssl', True),
            headers=source.get('headers', REQUEST_HEADERS)
        ))
        tasks.append((source, task))
    
    for source, task in tasks:
        try:
            content = await task
            if content and 'parser' in source:
                new_subs = source['parser'](content)
                subdomains.update(sub for sub in new_subs if sub and domain in sub)
        except Exception as e:
            logger.debug(f"Error processing {source['url']}: {e}")

    if len(subdomains) < 50:
        for source in fallback_sources:
            try:
                content = await fetch_with_retry(
                    source['url'],
                    is_json=source.get('is_json', True),
                    verify_ssl=source.get('verify_ssl', True)
                )
                
                if content and 'parser' in source:
                    new_subs = source['parser'](content)
                    subdomains.update(sub for sub in new_subs if sub and domain in sub)
            except Exception as e:
                logger.debug(f"Error processing fallback {source['url']}: {e}")

    domain_parts = domain.split('.')
    main_domain = '.'.join(domain_parts[-2:]) if len(domain_parts) > 2 else domain
    clean_subs = set()

    for sub in subdomains:
        sub = sub.lower().strip()
        if not sub or '*' in sub:
            continue
        
        sub = sub.replace('*.', '').replace('.*', '')
    
        if sub.endswith(f".{domain}") or sub == domain:
            clean_subs.add(sub)
        elif sub.endswith(f".{main_domain}") and main_domain != domain:
            clean_subs.add(sub)
    
    return sorted(clean_subs)

async def get_ip_address(domain):
    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(domain, 'A')
        return answers[0].address if answers else None
    except Exception as e:
        logger.error(f"Error resolving IP for {domain}: {e}")
        try:
            return socket.gethostbyname(domain)
        except:
            return None

async def get_page_title(session, url):
    try:
        html = await fetch_url(session, url, headers=REQUEST_HEADERS)
        if html:
            soup = BeautifulSoup(html, 'html.parser')
            title = soup.title.string if soup.title else "No title"
            return title.strip()
        return "Error loading title"
    except Exception as e:
        logger.error(f"Error getting title for {url}: {e}")
        return "Error loading title"

async def get_server_info(session, url):
    try:
        async with session.head(url, headers=REQUEST_HEADERS) as response:
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', 'Unknown')
            
            security_headers = {
                'CSP': {
                    'value': response.headers.get('Content-Security-Policy', 'Not set'),
                    'description': 'Protection against XSS, injection, and other attacks',
                    'recommendation': 'Set a strict CSP policy with restrictions on script, style, and other resource sources',
                    'severity': 'high'
                },
                'HSTS': {
                    'value': response.headers.get('Strict-Transport-Security', 'Not set'),
                    'description': 'Enforces HTTPS usage',
                    'recommendation': 'Set HSTS with max-age of at least 31536000 (1 year) and includeSubDomains',
                    'severity': 'high'
                },
                'X-Frame-Options': {
                    'value': response.headers.get('X-Frame-Options', 'Not set'),
                    'description': 'Protection against clickjacking',
                    'recommendation': 'Set to DENY or SAMEORIGIN',
                    'severity': 'medium'
                },
                'X-Content-Type-Options': {
                    'value': response.headers.get('X-Content-Type-Options', 'Not set'),
                    'description': 'Prevents MIME-sniffing',
                    'recommendation': 'Set to nosniff',
                    'severity': 'medium'
                },
                'Referrer-Policy': {
                    'value': response.headers.get('Referrer-Policy', 'Not set'),
                    'description': 'Controls referrer information leakage',
                    'recommendation': 'Set to strict-origin-when-cross-origin or stricter',
                    'severity': 'low'
                },
                'Permissions-Policy': {
                    'value': response.headers.get('Permissions-Policy', 'Not set'),
                    'description': 'Controls access to browser APIs',
                    'recommendation': 'Restrict access to geolocation, camera, microphone and other sensitive APIs',
                    'severity': 'medium'
                },
                'X-XSS-Protection': {
                    'value': response.headers.get('X-XSS-Protection', 'Not set'),
                    'description': 'Legacy XSS protection (deprecated but still encountered)',
                    'recommendation': 'If used, set to "1; mode=block"',
                    'severity': 'low'
                },
                'Feature-Policy': {
                    'value': response.headers.get('Feature-Policy', 'Not set'),
                    'description': 'Controls access to browser APIs (deprecated, replaced by Permissions-Policy)',
                    'recommendation': 'Replace with Permissions-Policy',
                    'severity': 'low'
                },
                'Cross-Origin-Embedder-Policy': {
                    'value': response.headers.get('Cross-Origin-Embedder-Policy', 'Not set'),
                    'description': 'Controls cross-origin resource loading',
                    'recommendation': 'Set to require-corp for strict isolation',
                    'severity': 'medium'
                },
                'Cross-Origin-Opener-Policy': {
                    'value': response.headers.get('Cross-Origin-Opener-Policy', 'Not set'),
                    'description': 'Window/tab isolation',
                    'recommendation': 'Set to same-origin to prevent Spectre attacks',
                    'severity': 'medium'
                },
                'Cross-Origin-Resource-Policy': {
                    'value': response.headers.get('Cross-Origin-Resource-Policy', 'Not set'),
                    'description': 'Controls cross-site resource access',
                    'recommendation': 'Set to same-site or same-origin',
                    'severity': 'low'
                },
                'Cache-Control': {
                    'value': response.headers.get('Cache-Control', 'Not set'),
                    'description': 'Cache management',
                    'recommendation': 'For sensitive data, set to no-store, no-cache, must-revalidate',
                    'severity': 'medium'
                },
                'Clear-Site-Data': {
                    'value': response.headers.get('Clear-Site-Data', 'Not set'),
                    'description': 'Clears site data on logout',
                    'recommendation': 'Set to clear cookies, storage, and cache',
                    'severity': 'low'
                }
            }
            
            has_security_policy = any(
                security_headers[key]['value'] != 'Not set' 
                for key in ['CSP', 'HSTS', 'X-Frame-Options', 'X-Content-Type-Options']
            )
            
            if security_headers['CSP']['value'] != 'Not set':
                csp = security_headers['CSP']['value'].lower()
                security_headers['CSP']['analysis'] = {
                    'unsafe_inline': 'unsafe-inline' in csp,
                    'unsafe_eval': 'unsafe-eval' in csp,
                    'strict_dynamic': 'strict-dynamic' in csp,
                    'has_default_src': 'default-src' in csp,
                    'has_script_src': 'script-src' in csp,
                    'has_object_src': 'object-src' in csp,
                    'has_frame_src': 'frame-src' in csp
                }
            
            if security_headers['HSTS']['value'] != 'Not set':
                hsts = security_headers['HSTS']['value'].lower()
                security_headers['HSTS']['analysis'] = {
                    'max_age': int(re.search(r'max-age=(\d+)', hsts).group(1)) if 'max-age' in hsts else 0,
                    'include_subdomains': 'includesubdomains' in hsts,
                    'preload': 'preload' in hsts
                }
            
            security_score = 100
            for header, data in security_headers.items():
                if data['value'] == 'Not set':
                    if data['severity'] == 'high':
                        security_score -= 10
                    elif data['severity'] == 'medium':
                        security_score -= 5
                    else:
                        security_score -= 2
            
            vulnerable_headers = {
                'Server': server,
                'X-Powered-By': powered_by,
                'X-AspNet-Version': response.headers.get('X-AspNet-Version', None),
                'X-AspNetMvc-Version': response.headers.get('X-AspNetMvc-Version', None)
            }
            
            return {
                'server': server,
                'powered_by': powered_by,
                'security_headers': security_headers,
                'security_score': max(0, security_score),
                'vulnerable_headers': {k: v for k, v in vulnerable_headers.items() if v != 'Unknown' and v is not None},
                'all_headers': dict(response.headers),
                'has_security_policy': has_security_policy
            }
    except Exception as e:
        logger.error(f"Error getting server info for {url}: {e}")
        return {
            'server': 'Unknown', 
            'powered_by': 'Unknown',
            'security_headers': {},
            'security_score': 0,
            'vulnerable_headers': {},
            'all_headers': {},
            'has_security_policy': False
        }

async def get_ssl_cert_info(domain):
    try:
        hostname = domain.split('//')[-1].split('/')[0]
        cert = ssl.get_server_certificate((hostname, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        
        return {
            'issuer': x509.get_issuer().CN,
            'subject': x509.get_subject().CN,
            'version': x509.get_version(),
            'serial_number': x509.get_serial_number(),
            'not_before': x509.get_notBefore().decode('utf-8'),
            'not_after': x509.get_notAfter().decode('utf-8'),
            'signature_algorithm': x509.get_signature_algorithm().decode('utf-8'),
            'expires_in_days': (datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ') - datetime.now()).days
        }
    except Exception as e:
        logger.error(f"Error getting SSL cert for {domain}: {e}")
        return {'error': str(e)}

async def scan_subdomain(session, subdomain, target_domain):
    try:
        url = f"http://{subdomain}" if not subdomain.startswith(('http://', 'https://')) else subdomain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        if not domain.endswith(target_domain):
            logger.info(f"Skipping external domain: {domain}")
            return None
        
        ip_task = asyncio.create_task(get_ip_address(domain))
        server_info_task = asyncio.create_task(get_server_info(session, url))
        
        ip = await ip_task
        server_info = await server_info_task
        
        title = await get_page_title(session, url) if ip else "Unreachable"
        
        js_urls = await extract_js_urls(session, url, target_domain)
        
        return {
            'subdomain': subdomain,
            'ip': ip,
            'server': server_info['server'],
            'powered_by': server_info['powered_by'],
            'security_headers': server_info['security_headers'],
            'title': title,
            'alive': bool(ip),
            'js_files': js_urls[:10]
        }
    except Exception as e:
        logger.error(f"Error scanning subdomain {subdomain}: {e}")
        return {
            'subdomain': subdomain,
            'ip': None,
            'server': 'Unknown',
            'powered_by': 'Unknown',
            'security_headers': {},
            'title': 'Error',
            'alive': False,
            'js_files': []
        }

async def extract_js_urls(session, url, target_domain, depth=0, max_depth=JS_ANALYSIS_DEPTH):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        html = await fetch_url(session, url, headers=REQUEST_HEADERS)
        if not html:
            return []
            
        soup = BeautifulSoup(html, 'html.parser')
        
        js_urls = []
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                full_url = src if src.startswith('http') else urljoin(url, src)
                parsed_js = urlparse(full_url)
                
                if parsed_js.netloc.endswith(target_domain):
                    js_urls.append(full_url)
        
        js_urls = js_urls[:MAX_JS_FILES_PER_PAGE]
        
        if depth < max_depth:
            additional_js_urls = []
            for js_url in js_urls:
                try:
                    js_content = await fetch_url(session, js_url, headers=REQUEST_HEADERS)
                    if js_content:
                        nested_js = re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', js_content)
                        for nested_url in nested_js:
                            full_nested_url = nested_url if nested_url.startswith('http') else urljoin(js_url, nested_url)
                            parsed_nested = urlparse(full_nested_url)
                            
                            if parsed_nested.netloc.endswith(target_domain):
                                additional_js_urls.append(full_nested_url)
                except Exception as e:
                    logger.warning(f"Error analyzing JS file {js_url} for nested JS: {e}")
                    continue
            
            for new_js in additional_js_urls:
                if new_js not in js_urls:
                    js_urls.append(new_js)
        
        return list(set(js_urls))
    except Exception as e:
        logger.error(f"Error extracting JS URLs: {e}")
        return []

async def analyze_js_file(session, js_url, domain):
    try:
        js_content = await fetch_url(session, js_url, headers=REQUEST_HEADERS)
        if not js_content:
            return None
        
        content_hash = hashlib.sha256(js_content.encode()).hexdigest()
        
        findings = {
            'url': js_url,
            'content_hash': content_hash,
            'content_length': len(js_content),
            'subdomains': [],
            'api_keys': [],
            'sensitive_paths': [],
            'interesting_comments': [],
            'endpoints': [],
            'hardcoded_creds': [],
            'jwt_tokens': [],
            'cloud_resources': [],
            'ip_addresses': [],
            'version_info': [],
            'cors_misconfig': [],
            'debug_flags': [],
            'technologies': [],
            'obfuscated_code': False,
            'minified': False,
            'source_map': None,
            'suspicious_patterns': []
        }
        
        if len(js_content) > 1000 and '\n' not in js_content[:1000]:
            findings['minified'] = True
        
        if re.search(r'(?:eval\(function\(p,a,c,k,e,d\)|\\x[0-9a-fA-F]{2})', js_content):
            findings['obfuscated_code'] = True
        
        source_map = re.search(r'//# sourceMappingURL=([^\s]+)', js_content)
        if source_map:
            findings['source_map'] = urljoin(js_url, source_map.group(1))
        
        subdomain_pattern = r'(?:https?://)?([a-zA-Z0-9-]+\.)+' + re.escape(domain) + r'(?![a-zA-Z0-9-])'
        subdomains = re.findall(subdomain_pattern, js_content)
        findings['subdomains'] = list(set([s.lower() for s in subdomains]))
        
        api_key_patterns = [
            r'(?:"|\'|`)(?:api[_-]?key|access[_-]?token|secret[_-]?key|aws[_-]?access[_-]?key|aws[_-]?secret[_-]?key|google[_-]?api[_-]?key|facebook[_-]?app[_-]?secret)(?:"|\'|`)\s*[:=]\s*(?:"|\'|`)([a-zA-Z0-9_\-]{20,})(?:"|\'|`)',
            r'(?:api|key|token|secret|password|credential)[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
            r'(?:aws|google|azure|facebook|twitter)[_ -]?(?:access|api|secret)[_ -]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
            r'(?:secret|token|password|credential)["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
            r'[aA][pP][iI][_ -]?[kK][eE][yY]["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']'
        ]
        findings['api_keys'] = list(set([match for pattern in api_key_patterns 
                                      for match in re.findall(pattern, js_content, re.I) if not is_false_positive(match)]))
        
        sensitive_paths = re.findall(
            r'/(?:admin|api|auth|config|token|login|secret|backup|dev|test|staging|prod|v[0-9])[/a-zA-Z0-9_\-\.~]*',
            js_content, re.I)
        findings['sensitive_paths'] = list(set([p for p in sensitive_paths if not p.startswith('//') and len(p) > 3]))
        
        comments = re.findall(
            r'//\s*(?:TODO|FIXME|SECURITY|HACK|WARNING|DEBUG|TEST|XXX|NOTE|BUG|LEAK|PASSWORD|CREDENTIAL|TOKEN|KEY)\b.*',
            js_content)
        findings['interesting_comments'] = [c for c in comments if len(c) < 200]
        
        endpoint_pattern = r'(?:https?:)?//[a-zA-Z0-9\-\.]+(?:\.' + re.escape(domain) + r')?(?:/[a-zA-Z0-9_\-\./~]{2,})(?:\?[a-zA-Z0-9_\-\.=&]+)?'
        endpoints = re.findall(endpoint_pattern, js_content)
        findings['endpoints'] = list(set([e for e in endpoints 
                                       if not e.startswith('//jQ/') and 
                                       not e.startswith('//fv/') and
                                       not e.startswith('//C81j') and
                                       len(e.split('/')) > 3 and
                                       not re.search(r'/[a-zA-Z0-9]{1,3}/[a-zA-Z0-9]{1,3}/', e)]))
        
        hardcoded_creds = re.findall(
            r'(?:user|username|login|pass|password|pwd|credential)["\']?\s*[:=]\s*["\'][a-zA-Z0-9!@#$%^&*()_+\-]{6,}["\']',
            js_content, re.I)
        findings['hardcoded_creds'] = [cred for cred in hardcoded_creds 
                                     if not re.search(r'["\'][a-f0-9]{32}["\']', cred) and  # Фильтр хешей
                                     not re.search(r'["\'](?:null|undefined|true|false)["\']', cred, re.I)]
        
        jwt_tokens = re.findall(
            r'eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}',
            js_content)
        findings['jwt_tokens'] = jwt_tokens
        
        cloud_resources = re.findall(
            r'(?:s3|ec2|lambda|storage|blob)\.(?:amazonaws|googleapis|microsoftonline|azure|digitaloceanspaces)\.com[/a-zA-Z0-9_\-\.]*',
            js_content, re.I)
        findings['cloud_resources'] = list(set([r for r in cloud_resources if len(r.split('/')) > 2]))
        
        ip_addresses = re.findall(
            r'(?<!\.)(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?!\.)',
            js_content)
        findings['ip_addresses'] = list(set([ip for ip in ip_addresses 
                                          if not ip.startswith('0.') and 
                                          not ip.startswith('10.') and
                                          not ip.startswith('127.') and
                                          not ip.startswith('169.254.') and
                                          not ip.startswith('192.0.2.') and
                                          not ip.startswith('224.') and
                                          not ip.startswith('240.')]))
        
        version_info = re.findall(
            r'(?:version|v|ver|release|rev)\s*[:=]\s*["\'][0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[a-zA-Z0-9]+)?["\']',
            js_content, re.I)
        findings['version_info'] = [v for v in version_info if len(v) < 50]
    
        cors_misconfig = re.findall(
            r'Access-Control-Allow-Origin\s*:\s*["\']?\*["\']?',
            js_content, re.I)
        findings['cors_misconfig'] = cors_misconfig
        
        debug_flags = re.findall(
            r'(?:debug|dev|test|staging|verbose)\s*[:=]\s*(?:true|1|"true"|\'true\')',
            js_content, re.I)
        findings['debug_flags'] = debug_flags
        
        detected_tech = []
        for tech, patterns in TECH_DETECTION_PATTERNS.items():
            for pattern in patterns:
                if isinstance(pattern, re.Pattern):
                    if pattern.search(js_content):
                        detected_tech.append(tech)
                        break
                elif isinstance(pattern, tuple):
                    pass
        
        findings['technologies'] = list(set(detected_tech))
        
        suspicious_patterns = []
        for pattern_type, patterns in JS_ANALYSIS_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, js_content)
                if matches:
                    suspicious_patterns.append({
                        'type': pattern_type,
                        'pattern': pattern,
                        'matches': matches[:5]
                    })
        
        findings['suspicious_patterns'] = suspicious_patterns
        
        return findings
        
    except Exception as e:
        logger.error(f"Error analyzing JS file {js_url}: {str(e)}", exc_info=True)
        return None

def is_false_positive(match):
    if isinstance(match, tuple):
        match = match[0]
    
    false_positives = [
        'example', 'test', 'demo', 'sample', 'placeholder', 'dummy',
        'changeme', 'your_', 'xxxx', 'aaaa', '1234', '0000', 'false',
        'true', 'null', 'undefined'
    ]
    
    if len(match) < 10:
        return True
    
    if any(fp in match.lower() for fp in false_positives):
        return True
    
    if re.search(r'(.)\1{5,}', match):
        return True
    
    return False

async def extract_emails_and_phones(content):
    try:
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
        phones = re.findall(r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,3}\)?[-.\s]?\d{2,3}[-.\s]?\d{2,4}\b', content)
        return {
            'emails': list(set(emails)),
            'phones': list(set(phones))
        }
    except Exception as e:
        logger.error(f"Error extracting contacts: {e}")
        return {'emails': [], 'phones': []}

async def analyze_robots_and_sitemap(session, domain):
    try:
        base_url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
        results = {'robots': {}, 'sitemap': {}}
        
        robots_url = f"{base_url}/robots.txt"
        robots_content = await fetch_url(session, robots_url)
        if robots_content:
            results['robots']['exists'] = True
            results['robots']['content'] = robots_content.split('\n')
            
            sitemap_lines = [line for line in robots_content.split('\n') if line.lower().startswith('sitemap:')]
            results['robots']['sitemaps'] = [line.split(':', 1)[1].strip() for line in sitemap_lines]
        else:
            results['robots']['exists'] = False
        
        sitemap_url = f"{base_url}/sitemap.xml"
        sitemap_content = await fetch_url(session, sitemap_url)
        if sitemap_content:
            results['sitemap']['exists'] = True
            try:
                soup = BeautifulSoup(sitemap_content, 'xml')
                urls = [loc.text for loc in soup.find_all('loc')]
                results['sitemap']['url_count'] = len(urls)
                results['sitemap']['sample_urls'] = urls[:5]
            except:
                results['sitemap']['raw_content'] = sitemap_content
        else:
            results['sitemap']['exists'] = False
        
        return results
    except Exception as e:
        logger.error(f"Error analyzing robots/sitemap: {e}")
        return {'robots': {'error': str(e)}, 'sitemap': {'error': str(e)}}

async def detect_technologies(session, url):
    try:
        tech_found = defaultdict(list)
        html = await fetch_url(session, url, headers=REQUEST_HEADERS)
        
        if not html:
            return dict(tech_found)
        
        soup = BeautifulSoup(html, 'html.parser')
        
        for tech, patterns in TECH_DETECTION_PATTERNS.items():
            for pattern in patterns:
                try:
                    if isinstance(pattern, tuple):
                        found = soup.find_all(pattern[0], pattern[1])
                        if found:
                            for f in found:
                                value = f.get('content') or f.get('src') or f.get('href')
                                if value:
                                    tech_found[tech].append(value)
                    elif isinstance(pattern, re.Pattern):
                        if pattern.search(html):
                            tech_found[tech].append(pattern.pattern)
                except Exception as e:
                    logger.warning(f"Error checking pattern {pattern} for {tech}: {e}")
                    continue
        
        try:
            async with session.head(url, headers=REQUEST_HEADERS) as response:
                powered_by = response.headers.get('X-Powered-By', '').lower()
                if powered_by:
                    if 'php' in powered_by:
                        tech_found['php'].append(powered_by)
                    elif 'asp.net' in powered_by:
                        tech_found['asp.net'].append(powered_by)
                
                server = response.headers.get('Server', '').lower()
                if server:
                    if 'apache' in server:
                        tech_found['apache'].append(server)
                    elif 'nginx' in server:
                        tech_found['nginx'].append(server)
        except Exception as e:
            logger.warning(f"Error checking headers: {e}")
        
        return dict(tech_found)
    except Exception as e:
        logger.error(f"Error detecting technologies: {e}")
        return {}

async def process_domain_scan(domain):
    results = {
        'domain': domain,
        'domain_info': {},
        'subdomains_from_crt': [],
        'subdomains_details': [],
        'js_files': [],
        'js_analysis': [],
        'ssl_info': {},
        'contacts': {},
        'robots_sitemap': {},
        'technologies': {},
        'common_paths': {},
        'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'js_stats': {
            'total_files': 0,
            'files_with_findings': 0,
            'api_keys_found': 0,
            'sensitive_paths_found': 0,
            'dangerous_funcs_found': 0
        }
    }
    
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        results['domain_info'] = await loop.run_in_executor(pool, get_domain_info_sync, domain)
    
    async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
        results['ssl_info'] = await get_ssl_cert_info(domain)
        
        results['subdomains_from_crt'] = await get_subdomains_from_crtsh(domain)
        
        subdomain_tasks = []
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
        
        async def limited_scan_subdomain(subdomain):
            async with semaphore:
                return await scan_subdomain(session, subdomain, domain)
        
        for subdomain in results['subdomains_from_crt']:
            if subdomain.endswith(domain):
                task = asyncio.create_task(limited_scan_subdomain(subdomain))
                subdomain_tasks.append(task)
        
        subdomain_results = await asyncio.gather(*subdomain_tasks)
        results['subdomains_details'] = [r for r in subdomain_results if r is not None]
        
        target_url = domain if domain.startswith(('http://', 'https://')) else f'https://{domain}'
        main_js_files = await extract_js_urls(session, target_url, domain)
        results['js_files'] = main_js_files
        
        for subdomain_info in results['subdomains_details']:
            if subdomain_info['alive'] and subdomain_info['js_files']:
                results['js_files'].extend(subdomain_info['js_files'])
        
        results['js_files'] = list(set(results['js_files']))
        results['js_stats']['total_files'] = len(results['js_files'])
        
        js_analysis_tasks = []
        for js_url in results['js_files'][:100]:
            task = asyncio.create_task(analyze_js_file(session, js_url, domain))
            js_analysis_tasks.append(task)
        
        js_analysis_results = await asyncio.gather(*js_analysis_tasks)
        results['js_analysis'] = [r for r in js_analysis_results if r is not None]
        results['js_stats']['files_with_findings'] = len(results['js_analysis'])

        for js_result in results['js_analysis']:
            if js_result['api_keys']:
                results['js_stats']['api_keys_found'] += 1
            if js_result['sensitive_paths']:
                results['js_stats']['sensitive_paths_found'] += 1
        
        main_page_content = await fetch_url(session, target_url, headers=REQUEST_HEADERS)
        if main_page_content:
            results['contacts'] = await extract_emails_and_phones(main_page_content)
        
        results['robots_sitemap'] = await analyze_robots_and_sitemap(session, domain)
        
        results['technologies'] = await detect_technologies(session, target_url)
    
    return results

@app.route('/', methods=['GET', 'POST'])
async def index():
    if request.method == 'POST':
        domain = request.form['domain'].strip()
        if not domain:
            return render_template('index.html', error="Please enter a domain")
        
        try:
            extracted = tldextract.extract(domain)
            if not extracted.domain:
                return render_template('index.html', error="Invalid domain format")
            
            base_domain = f"{extracted.domain}.{extracted.suffix}"
            
            results = await process_domain_scan(base_domain)
            return render_template('index.html', results=results)
        except Exception as e:
            logger.error(f"Error processing domain scan: {e}")
            return render_template('index.html', error=f"An error occurred during scanning: {str(e)}")

    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
async def api_scan():
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400
    
    data = request.get_json()
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        extracted = tldextract.extract(domain)
        if not extracted.domain:
            return jsonify({'error': 'Invalid domain format'}), 400
        
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        results = await process_domain_scan(base_domain)
        return jsonify(results)
    except Exception as e:
        logger.error(f"API scan error: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    import nest_asyncio
    nest_asyncio.apply()
    
    app.run(debug=True)