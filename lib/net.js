'use strict';
/**
 * Client HTTP(S) minimal sans dépendance, compatible proxy d'entreprise (HTTPS_PROXY / NO_PROXY).
 * Le certificat d'entreprise est pris en compte par Node via NODE_EXTRA_CA_CERTS.
 */
const http = require('http');
const https = require('https');
const tls = require('tls');

function proxyFor(urlObj) {
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy;
  if (!proxy) return null;
  const noProxy = (process.env.NO_PROXY || process.env.no_proxy || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  const host = urlObj.hostname.toLowerCase();
  if (noProxy.some(np => np === '*' || host === np.replace(/^\./, '') || host.endsWith(np.startsWith('.') ? np : '.' + np))) return null;
  try { return new URL(proxy); } catch { return null; }
}

function tunnel(proxyUrl, host, port, timeout) {
  return new Promise((resolve, reject) => {
    const headers = { Host: `${host}:${port}` };
    if (proxyUrl.username) {
      headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(decodeURIComponent(proxyUrl.username) + ':' + decodeURIComponent(proxyUrl.password)).toString('base64');
    }
    const req = http.request({ host: proxyUrl.hostname, port: proxyUrl.port || 80, method: 'CONNECT', path: `${host}:${port}`, headers, timeout });
    req.on('connect', (res, socket) => {
      if (res.statusCode === 200) resolve(socket);
      else { socket.destroy(); reject(new Error('Proxy CONNECT refusé : ' + res.statusCode)); }
    });
    req.on('timeout', () => req.destroy(new Error('Délai dépassé (proxy)')));
    req.on('error', reject);
    req.end();
  });
}

/**
 * request(url, { method, headers, body, timeout, maxBytes }) -> { status, headers, body: Buffer }
 */
async function request(url, opts = {}, redirects = 0) {
  const u = new URL(url);
  const timeout = opts.timeout || 15000;
  const maxBytes = opts.maxBytes || 50 * 1024 * 1024;
  const isHttps = u.protocol === 'https:';
  const port = Number(u.port) || (isHttps ? 443 : 80);
  const headers = Object.assign({ 'User-Agent': 'skill-analyse-audit/1.0', Accept: 'application/json' }, opts.headers || {});
  let body = opts.body;
  if (body && typeof body !== 'string' && !Buffer.isBuffer(body)) {
    body = JSON.stringify(body);
    headers['Content-Type'] = 'application/json';
  }
  if (body) headers['Content-Length'] = Buffer.byteLength(body);

  const proxy = proxyFor(u);
  const reqOpts = { method: opts.method || 'GET', hostname: u.hostname, port, path: u.pathname + u.search, headers, timeout };
  if (proxy && isHttps) {
    const socket = await tunnel(proxy, u.hostname, port, timeout);
    reqOpts.createConnection = () => tls.connect({ socket, servername: u.hostname });
  } else if (proxy && !isHttps) {
    reqOpts.hostname = proxy.hostname; reqOpts.port = proxy.port || 80; reqOpts.path = url;
  }
  const lib = isHttps ? https : http;
  const res = await new Promise((resolve, reject) => {
    const req = lib.request(reqOpts, r => {
      const chunks = []; let size = 0;
      r.on('data', c => { size += c.length; if (size > maxBytes) { req.destroy(new Error('Réponse trop volumineuse')); return; } chunks.push(c); });
      r.on('end', () => resolve({ status: r.statusCode, headers: r.headers, body: Buffer.concat(chunks) }));
      r.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('Délai dépassé')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
  if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location && redirects < 3) {
    const next = new URL(res.headers.location, url).toString();
    if (isHttps && !/^https:/i.test(next)) throw new Error('Redirection HTTPS vers HTTP refusée');
    const h = Object.assign({}, opts.headers);
    if (new URL(next).host !== u.host) delete h.Authorization; // ne pas transmettre le token à un autre hôte
    return request(next, Object.assign({}, opts, { headers: h }), redirects + 1);
  }
  return res;
}

async function getJson(url, opts = {}) {
  const res = await request(url, opts);
  let json = null;
  try { json = JSON.parse(res.body.toString('utf8')); } catch { /* ignore */ }
  return { status: res.status, headers: res.headers, json };
}

/** Teste si un hôte répond (n'importe quel code HTTP = joignable). */
async function reachable(url, timeout = 6000) {
  try { const r = await request(url, { timeout, maxBytes: 1024 * 1024 }); return r.status > 0; } catch { return false; }
}

module.exports = { request, getJson, reachable };
