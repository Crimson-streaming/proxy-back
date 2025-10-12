const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');

const app = express();
const PORT = process.env.PORT || 5000;

// URL du proxy à utiliser pour les réponses
const PROXY_URL = process.env.PROXY_URL || 'https://proxy-cloudy.onrender.com/proxy';

// Configuration du cache intelligent
// Cache M3U8 : 30 secondes (pour détecter les changements de playlist live)
const m3u8Cache = new NodeCache({ stdTTL: 30, checkperiod: 10 });

// Cache iframe : 5 minutes (les URLs changent rarement)
const iframeCache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

// Cache segments TS : 1 heure (les segments ne changent jamais)
const segmentCache = new NodeCache({ stdTTL: 3600, checkperiod: 120, maxKeys: 1000 });

// Statistiques
const stats = {
  requests: { total: 0, iframe: 0, m3u8: 0, segments: 0 },
  cache: { hits: 0, misses: 0 },
  errors: { total: 0, network: 0, timeout: 0 }
};

// Middleware CORS
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS', 'HEAD'],
  allowedHeaders: ['Content-Type', 'Range', 'Authorization', 'Accept-Encoding'],
  exposedHeaders: ['Content-Length', 'Content-Range', 'Accept-Ranges']
}));

// Rate limiting optimisé pour streaming
// Limite pour extraction iframe (peu fréquent)
const iframeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Trop de requêtes iframe, réessayez dans 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false
});

// Limite pour M3U8 (fréquent mais raisonnable)
const m3u8Limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 120, // 120 requêtes/minute
  message: { error: 'Trop de requêtes M3U8, ralentissez' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip si en cache
    const url = req.query.url;
    return url && m3u8Cache.has(`m3u8_${url}`);
  }
});

// Limite pour segments TS (très fréquent, limite haute)
const segmentLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 500, // 500 segments/minute (largement suffisant)
  message: { error: 'Trop de requêtes, ralentissez' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    const url = req.query.url;
    return url && segmentCache.has(url);
  }
});

// Middleware de logging léger
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (duration > 1000 || res.statusCode >= 400) {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
    }
  });
  next();
});

// Validation d'URL
function isValidUrl(string) {
  try {
    const url = new URL(string);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

// Fonction de retry avec backoff exponentiel
async function fetchWithRetry(url, config, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await axios(url, config);
    } catch (error) {
      stats.errors.total++;
      
      if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
        stats.errors.timeout++;
      } else if (error.response?.status >= 500) {
        stats.errors.network++;
      }

      // Dernier essai, on lance l'erreur
      if (i === maxRetries - 1) {
        throw error;
      }

      // Erreurs non récupérables
      if (error.response?.status === 404 || error.response?.status === 403) {
        throw error;
      }

      // Backoff exponentiel : 500ms, 1500ms, 3500ms
      const delay = 500 * Math.pow(3, i);
      console.log(`[RETRY] Tentative ${i + 2}/${maxRetries} après ${delay}ms - ${url.substring(0, 50)}...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// Route pour extraire l'URL M3U8 depuis l'iframe
app.get('/iframe', iframeLimiter, async (req, res) => {
  try {
    stats.requests.total++;
    stats.requests.iframe++;

    const { url } = req.query;

    if (!url) {
      return res.status(400).json({
        error: 'Paramètre URL manquant',
        usage: '/iframe?url=https://sharecloudy.com/iframe/aPgZqyX0gq'
      });
    }

    if (!isValidUrl(url)) {
      return res.status(400).json({ error: 'URL invalide' });
    }

    // Vérifier le cache
    const cacheKey = `iframe_${url}`;
    const cachedUrl = iframeCache.get(cacheKey);
    if (cachedUrl) {
      stats.cache.hits++;
      return res.json({ url: cachedUrl });
    }

    stats.cache.misses++;

    // Récupérer le contenu de l'iframe
    const response = await fetchWithRetry(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Referer': new URL(url).origin,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      },
      timeout: 10000
    });

    const html = response.data;
    const $ = cheerio.load(html);

    // Rechercher l'URL M3U8
    let m3u8Url = null;
    
    $('script').each((i, script) => {
      const content = $(script).html();
      if (content && !m3u8Url) {
        const patterns = [
          /["']([^"']*\.m3u8[^"']*)["']/gi,
          /file\s*:\s*["']([^"']+\.m3u8[^"']*)["']/gi,
          /sources?\s*:\s*\[?\s*{[^}]*file\s*:\s*["']([^"']+\.m3u8[^"']*)["']/gi,
          /url\s*:\s*["']([^"']+\.m3u8[^"']*)["']/gi
        ];

        for (const pattern of patterns) {
          const matches = content.matchAll(pattern);
          for (const match of matches) {
            if (match[1] && match[1].includes('.m3u8')) {
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
        if (src && src.includes('.m3u8')) {
          m3u8Url = src;
          return false;
        }
      });
    }

    if (!m3u8Url) {
      return res.status(404).json({
        error: 'URL M3U8 non trouvée',
        suggestion: 'Vérifiez que l\'URL de l\'iframe est correcte'
      });
    }

    // Construire l'URL complète
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

    // Mettre en cache
    iframeCache.set(cacheKey, proxifiedUrl);

    res.json({ url: proxifiedUrl });

  } catch (error) {
    console.error('✗ Erreur iframe:', error.message);
    res.status(error.response?.status || 500).json({
      error: 'Erreur lors de la récupération de l\'iframe',
      message: error.message
    });
  }
});

// Route proxy optimisée pour le streaming
app.get('/proxy', async (req, res) => {
  try {
    stats.requests.total++;

    const { url } = req.query;

    if (!url) {
      return res.status(400).json({
        error: 'Paramètre URL manquant',
        usage: '/proxy?url=https://example.com/video.m3u8'
      });
    }

    if (!isValidUrl(url)) {
      return res.status(400).json({ error: 'URL invalide' });
    }

    const isM3U8 = url.includes('.m3u8');
    const isTS = url.includes('.ts');

    // Appliquer le rate limiting approprié
    if (isM3U8) {
      stats.requests.m3u8++;
      await new Promise((resolve, reject) => {
        m3u8Limiter(req, res, (err) => err ? reject(err) : resolve());
      });
    } else if (isTS) {
      stats.requests.segments++;
      await new Promise((resolve, reject) => {
        segmentLimiter(req, res, (err) => err ? reject(err) : resolve());
      });
    }

    // Vérifier le cache pour les segments TS
    if (isTS) {
      const cachedSegment = segmentCache.get(url);
      if (cachedSegment) {
        stats.cache.hits++;
        
        // Headers optimisés pour le streaming
        res.setHeader('Content-Type', 'video/mp2t');
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('X-Cache', 'HIT');
        
        return res.send(cachedSegment);
      }
      stats.cache.misses++;
    }

    // Vérifier le cache pour M3U8
    if (isM3U8) {
      const cacheKey = `m3u8_${url}`;
      const cachedM3u8 = m3u8Cache.get(cacheKey);
      if (cachedM3u8) {
        stats.cache.hits++;
        res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
        res.setHeader('Cache-Control', 'public, max-age=30');
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('X-Cache', 'HIT');
        return res.send(cachedM3u8);
      }
      stats.cache.misses++;
    }

    // Headers pour la requête
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Referer': new URL(url).origin,
      'Origin': new URL(url).origin,
      'Accept': isM3U8 ? 'application/vnd.apple.mpegurl,*/*' : '*/*',
      'Connection': 'keep-alive'
    };

    // Ajouter le header Range pour le streaming adaptatif
    if (req.headers.range) {
      headers['Range'] = req.headers.range;
    }

    // Configuration axios optimisée
    const config = {
      method: 'GET',
      url: url,
      headers: headers,
      responseType: isTS ? 'arraybuffer' : 'text',
      timeout: isTS ? 30000 : 15000,
      maxRedirects: 5,
      validateStatus: (status) => status < 500
    };

    const response = await fetchWithRetry(url, config);

    // Headers optimisés pour le streaming
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Range, Content-Type');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
    res.setHeader('X-Cache', 'MISS');
    
    if (response.headers['content-type']) {
      res.setHeader('Content-Type', response.headers['content-type']);
    }
    
    if (response.headers['content-length']) {
      res.setHeader('Content-Length', response.headers['content-length']);
    }
    
    if (response.headers['content-range']) {
      res.setHeader('Content-Range', response.headers['content-range']);
    }

    // Pour les segments TS
    if (isTS) {
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      
      // Mettre en cache uniquement si la réponse est complète (pas un range)
      if (!req.headers.range && response.data.byteLength > 0) {
        segmentCache.set(url, response.data);
      }
      
      return res.status(response.status).send(response.data);
    }

    // Pour les fichiers M3U8
    if (isM3U8) {
      let content = response.data;
      const baseUrl = url.substring(0, url.lastIndexOf('/') + 1);

      // Remplacer les URLs relatives par des URLs proxifiées
      content = content.replace(
        /^([^#\n][^\n]*\.(?:ts|m3u8)[^\n]*)$/gm,
        (match) => {
          const absoluteUrl = match.startsWith('http') 
            ? match 
            : baseUrl + match.trim();
          return `${PROXY_URL}?url=${encodeURIComponent(absoluteUrl)}`;
        }
      );

      res.setHeader('Content-Type', 'application/vnd.apple.mpegurl');
      res.setHeader('Cache-Control', 'public, max-age=30');
      
      // Mettre en cache
      const cacheKey = `m3u8_${url}`;
      m3u8Cache.set(cacheKey, content);
      
      return res.status(response.status).send(content);
    }

    // Pour les autres types de fichiers
    res.status(response.status).send(response.data);

  } catch (error) {
    console.error('✗ Erreur proxy:', error.message);
    
    if (error.response) {
      res.status(error.response.status).json({
        error: 'Erreur lors de la récupération',
        status: error.response.status,
        message: error.message
      });
    } else {
      res.status(500).json({
        error: 'Erreur serveur',
        message: error.message,
        type: error.code || 'UNKNOWN'
      });
    }
  }
});

// Route health check avec statistiques
app.get('/health', (req, res) => {
  const uptime = process.uptime();
  const memoryUsage = process.memoryUsage();
  
  res.json({
    status: 'healthy',
    uptime: Math.floor(uptime),
    uptimeFormatted: `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m ${Math.floor(uptime % 60)}s`,
    timestamp: new Date().toISOString(),
    memory: {
      used: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
      total: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`
    },
    cache: {
      m3u8: {
        keys: m3u8Cache.keys().length,
        stats: m3u8Cache.getStats()
      },
      segments: {
        keys: segmentCache.keys().length,
        stats: segmentCache.getStats()
      },
      iframe: {
        keys: iframeCache.keys().length,
        stats: iframeCache.getStats()
      }
    },
    stats: stats
  });
});

// Route stats
app.get('/stats', (req, res) => {
  res.json({
    requests: stats.requests,
    cache: {
      ...stats.cache,
      hitRate: stats.cache.hits + stats.cache.misses > 0 
        ? ((stats.cache.hits / (stats.cache.hits + stats.cache.misses)) * 100).toFixed(2) + '%'
        : '0%'
    },
    errors: stats.errors,
    cacheSize: {
      m3u8: m3u8Cache.keys().length,
      segments: segmentCache.keys().length,
      iframe: iframeCache.keys().length
    }
  });
});

// Route d'information
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    version: '2.0.0',
    endpoints: {
      health: {
        url: '/health',
        description: 'État du serveur avec statistiques détaillées'
      },
      stats: {
        url: '/stats',
        description: 'Statistiques de performance'
      },
      iframe: {
        url: '/iframe?url=<URL_IFRAME>',
        description: 'Extrait l\'URL M3U8 depuis une iframe',
        rateLimit: '50 requêtes / 15 minutes'
      },
      proxy: {
        url: '/proxy?url=<URL_M3U8_OR_TS>',
        description: 'Proxifie les M3U8 et segments TS',
        rateLimit: 'M3U8: 120/min | Segments: 500/min'
      }
    },
    features: [
      'Cache intelligent multi-niveaux',
      'Rate limiting optimisé par type',
      'Retry automatique avec backoff',
      'Headers optimisés pour streaming',
      'Support Range requests',
      'Statistiques en temps réel',
      'Gestion d\'erreurs robuste'
    ],
    optimizations: {
      m3u8Cache: '30 secondes',
      segmentCache: '1 heure (max 1000 segments)',
      iframeCache: '5 minutes',
      retry: '3 tentatives avec backoff exponentiel',
      timeout: 'M3U8: 15s | Segments: 30s'
    }
  });
});

// Gestion des erreurs 404
app.use((req, res) => {
  res.status(404).json({
    error: 'Route non trouvée',
    availableRoutes: ['/', '/health', '/stats', '/iframe', '/proxy']
  });
});

// Démarrage du serveur
app.listen(PORT, () => {
  console.log('\n🚀 Serveur proxy streaming démarré!');
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log(`🔗 Proxy URL: ${PROXY_URL}`);
  console.log('\n📊 Optimisations actives:');
  console.log('   ✓ Cache intelligent multi-niveaux');
  console.log('   ✓ Rate limiting optimisé');
  console.log('   ✓ Retry automatique (3x)');
  console.log('   ✓ Headers streaming optimisés');
  console.log('\n📋 Routes:');
  console.log('   - GET /health    → État + stats détaillées');
  console.log('   - GET /stats     → Statistiques de performance');
  console.log('   - GET /iframe    → Extraction M3U8');
  console.log('   - GET /proxy     → Proxy streaming\n');
});

// Gestion propre de l'arrêt
process.on('SIGINT', () => {
  console.log('\n📊 Statistiques finales:');
  console.log(`   Total requêtes: ${stats.requests.total}`);
  console.log(`   Cache hits: ${stats.cache.hits} (${((stats.cache.hits / (stats.cache.hits + stats.cache.misses || 1)) * 100).toFixed(1)}%)`);
  console.log(`   Erreurs: ${stats.errors.total}`);
  console.log('\n👋 Arrêt du serveur...');
  process.exit(0);
});