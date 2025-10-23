require('dotenv').config();
const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const cors = require('cors');
const { Redis } = require('@upstash/redis');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 5000;
const PROXY_URL = process.env.PROXY_URL || 'https://proxy-cloudy.onrender.com/proxy';

// ============================================================================
// REDIS
// ============================================================================
const redisClient = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
  automaticDeserialization: false
});

let redisConnected = false;

(async () => {
  try {
    await redisClient.ping();
    redisConnected = true;
    console.log('✅ Redis connecté');
  } catch (err) {
    console.warn('⚠️  Mode sans cache');
    redisConnected = false;
  }
})();

async function redisGet(key) {
  if (!redisConnected) return null;
  try {
    return await redisClient.get(key);
  } catch (err) {
    return null;
  }
}

async function redisSet(key, value, ttl) {
  if (!redisConnected) return false;
  try {
    if (ttl) {
      await redisClient.set(key, value, { ex: ttl });
    } else {
      await redisClient.set(key, value);
    }
    return true;
  } catch (err) {
    return false;
  }
}

// ============================================================================
// PROTECTION ANTI-SPAM
// ============================================================================
const requestCounts = new Map();

function cleanupOldRequests() {
  const now = Date.now();
  for (const [ip, data] of requestCounts.entries()) {
    if (now - data.timestamp > 60000) { // 1 minute
      requestCounts.delete(ip);
    }
  }
}

setInterval(cleanupOldRequests, 30000); // Nettoyage toutes les 30s

function checkRateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, { count: 1, timestamp: now });
    return next();
  }
  
  const data = requestCounts.get(ip);
  
  // Reset si > 1 minute
  if (now - data.timestamp > 60000) {
    requestCounts.set(ip, { count: 1, timestamp: now });
    return next();
  }
  
  // Max 100 requêtes par minute (largement suffisant pour famille)
  if (data.count >= 100) {
    console.warn(`⚠️  Rate limit: ${ip} (${data.count} req/min)`);
    return res.status(429).json({ error: 'Trop de requêtes, ralentis un peu' });
  }
  
  data.count++;
  next();
}

// ============================================================================
// CONFIGURATION
// ============================================================================
const ALLOWED_ORIGIN = 'https://cloudy-jit1.onrender.com'; // TON SITE UNIQUEMENT

// ============================================================================
// MIDDLEWARE
// ============================================================================
app.use(compression({ level: 6, threshold: 1024 }));

// CORS strict : UNIQUEMENT ton site peut accéder
app.use(cors({
  origin: (origin, callback) => {
    // Autoriser les requêtes sans origin (Postman, curl, etc.) en dev
    if (!origin) return callback(null, true);
    
    // Autoriser UNIQUEMENT ton site
    if (origin === ALLOWED_ORIGIN) {
      callback(null, true);
    } else {
      console.warn(`❌ Origin refusé: ${origin}`);
      callback(new Error('Non autorisé'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Range', 'Authorization', 'Accept-Encoding'],
  exposedHeaders: ['Content-Length', 'Content-Range', 'Accept-Ranges', 'X-Cache'],
  credentials: true
}));

// ============================================================================
// PROTECTION PAR MOT DE PASSE (DÉSACTIVÉ - CORS suffit)
// ============================================================================
// const API_KEY = process.env.API_KEY;
// 
// function checkAuth(req, res, next) {
//   if (!API_KEY) return next();
//   const key = req.headers['x-api-key'] || req.query.key;
//   if (key !== API_KEY) {
//     return res.status(403).json({ error: 'Non autorisé' });
//   }
//   next();
// }

// ============================================================================
// LOGS SIMPLES
// ============================================================================
let requestCount = 0;

app.use((req, res, next) => {
  requestCount++;
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    
    // Log seulement si erreur ou lent
    if (res.statusCode >= 400 || duration > 3000) {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
    }
  });
  
  next();
});

app.use(checkRateLimit);

// ============================================================================
// SÉCURITÉ : TOUS LES DOMAINES AUTORISÉS POUR LE STREAMING
// ============================================================================
// Pas de whitelist = ton site peut proxifier N'IMPORTE QUEL domaine de streaming
// C'est OK car seul ton site (via CORS) peut utiliser le proxy

function isValidUrl(string) {
  try {
    const url = new URL(string);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

async function fetchWithRetry(url, config, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await axios(url, { ...config, validateStatus: (status) => status < 500 });
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      if (error.response?.status === 404 || error.response?.status === 403) throw error;
      
      const delay = 500 * Math.pow(3, i);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// ============================================================================
// ROUTE: EXTRACTION IFRAME
// ============================================================================
app.get('/iframe', async (req, res) => {
  try {
    const { url } = req.query;

    if (!url || !isValidUrl(url)) {
      return res.status(400).json({ error: 'URL invalide' });
    }

    const cacheKey = `iframe_${url}`;
    const cached = await redisGet(cacheKey);
    
    if (cached) {
      return res.json({ url: cached, cached: true });
    }

    const response = await fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Referer': new URL(url).origin,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      timeout: 8000 // 8s au lieu de 10s
    });

    const $ = cheerio.load(response.data);
    let m3u8Url = null;
    
    $('script').each((i, script) => {
      const content = $(script).html();
      if (content && !m3u8Url) {
        const patterns = [
          /["']([^"']*\.m3u8[^"']*)["']/gi,
          /file\s*:\s*["']([^"']+\.m3u8[^"']*)["']/gi,
          /url\s*:\s*["']([^"']+\.m3u8[^"']*)["']/gi
        ];

        for (const pattern of patterns) {
          const matches = content.matchAll(pattern);
          for (const match of matches) {
            if (match[1]?.includes('.m3u8')) {
              m3u8Url = match[1];
              break;
            }
          }
          if (m3u8Url) break;
        }
      }
    });

    if (!m3u8Url) {
      $('source, video').each((i, elem) => {
        const src = $(elem).attr('src');
        if (src?.includes('.m3u8')) {
          m3u8Url = src;
          return false;
        }
      });
    }

    if (!m3u8Url) {
      return res.status(404).json({ error: 'M3U8 non trouvé' });
    }

    if (m3u8Url.startsWith('//')) {
      m3u8Url = 'https:' + m3u8Url;
    } else if (m3u8Url.startsWith('/')) {
      const baseUrl = new URL(url);
      m3u8Url = `${baseUrl.protocol}//${baseUrl.host}${m3u8Url}`;
    } else if (!m3u8Url.startsWith('http')) {
      const baseUrl = new URL(url);
      m3u8Url = `${baseUrl.protocol}//${baseUrl.host}/${m3u8Url}`;
    }

    const proxifiedUrl = `${PROXY_URL}?url=${encodeURIComponent(m3u8Url)}`;
    await redisSet(cacheKey, proxifiedUrl, 300);

    res.json({ url: proxifiedUrl, cached: false });

  } catch (error) {
    console.error('Erreur:', error.message);
    res.status(error.response?.status || 500).json({ error: 'Erreur extraction' });
  }
});

// ============================================================================
// ROUTE: PROXY STREAMING
// ============================================================================
app.get('/proxy', async (req, res) => {
  try {
    const { url } = req.query;

    if (!url || !isValidUrl(url)) {
      return res.status(400).json({ error: 'URL invalide' });
    }

    const isM3U8 = url.includes('.m3u8');
    const isTS = url.includes('.ts');

    // SEGMENTS TS
    if (isTS) {
      const cached = await redisGet(`segment_${url}`);
      if (cached) {
        const buffer = Buffer.from(cached, 'base64');
        
        res.setHeader('Content-Type', 'video/mp2t');
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('X-Cache', 'HIT');
        
        return res.send(buffer);
      }

      const headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Referer': new URL(url).origin,
        'Origin': new URL(url).origin,
        'Accept': '*/*'
      };

      if (req.headers.range) {
        headers['Range'] = req.headers.range;
      }

      const response = await fetchWithRetry(url, {
        method: 'GET',
        responseType: 'arraybuffer',
        headers,
        timeout: 15000 // 15s au lieu de 30s
      });

      res.setHeader('Content-Type', 'video/mp2t');
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('X-Cache', 'MISS');
      
      if (response.headers['content-length']) {
        res.setHeader('Content-Length', response.headers['content-length']);
      }
      
      if (response.headers['content-range']) {
        res.setHeader('Content-Range', response.headers['content-range']);
      }

      if (!req.headers.range && response.data.byteLength > 0) {
        await redisSet(`segment_${url}`, Buffer.from(response.data).toString('base64'), 86400);
      }

      return res.status(response.status).send(response.data);
    }

    // FICHIERS M3U8
    if (isM3U8) {
      const cacheKey = `m3u8_${url}`;
      const cached = await redisGet(cacheKey);
      
      if (cached) {
        res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
        res.setHeader('Cache-Control', 'public, max-age=30');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('X-Cache', 'HIT');
        return res.send(cached);
      }

      const response = await fetchWithRetry(url, {
        method: 'GET',
        responseType: 'text',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Referer': new URL(url).origin,
          'Origin': new URL(url).origin,
          'Accept': 'application/vnd.apple.mpegurl,*/*'
        },
        timeout: 15000
      });

      let content = response.data;
      const baseUrl = url.substring(0, url.lastIndexOf('/') + 1);

      content = content.replace(
        /^([^#\n][^\n]*\.(?:ts|m3u8)[^\n]*)$/gm,
        (match) => {
          const absoluteUrl = match.startsWith('http') ? match : baseUrl + match.trim();
          return `${PROXY_URL}?url=${encodeURIComponent(absoluteUrl)}`;
        }
      );

      res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
      res.setHeader('Cache-Control', 'public, max-age=30');
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('X-Cache', 'MISS');
      
      await redisSet(cacheKey, content, 30);
      return res.send(content);
    }

    // Autres
    const response = await fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      }
    });

    res.status(response.status).send(response.data);

  } catch (error) {
    console.error('Erreur:', error.message);
    res.status(error.response?.status || 500).json({ error: 'Erreur proxy' });
  }
});

// ============================================================================
// ROUTE: HEALTH CHECK
// ============================================================================
app.get('/ping', (req, res) => {
  res.json({ 
    status: 'ok',
    redis: redisConnected ? 'connected' : 'disconnected',
    uptime: Math.floor(process.uptime()),
    requests: requestCount
  });
});

// ============================================================================
// 404
// ============================================================================
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ============================================================================
// START
// ============================================================================
app.listen(PORT, () => {
  console.log(`\n🚀 Proxy démarré sur le port ${PORT}\n`);
});

process.on('SIGINT', () => {
  console.log('\n👋 Arrêt...\n');
  process.exit(0);
});