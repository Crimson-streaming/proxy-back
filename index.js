const express = require('express');
const axios = require('axios');
const cheerio = require('cheerio');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');

const app = express();
const PORT = process.env.PORT || 5000;

// URL du proxy à utiliser pour les réponses (modifiable via variable d'environnement)
const PROXY_URL = process.env.PROXY_URL || 'https://proxy-cloudy.onrender.com/proxy';

// Configuration du cache (TTL de 5 minutes)
const cache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

// Middleware CORS
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Range', 'Authorization']
}));

// Rate limiting pour éviter les abus
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limite de 100 requêtes par IP
  message: 'Trop de requêtes, veuillez réessayer plus tard.'
});

app.use(limiter);

// Middleware de logging
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
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

// Route pour extraire l'URL M3U8 depuis l'iframe
app.get('/iframe', async (req, res) => {
  try {
    const { url } = req.query;

    if (!url) {
      return res.status(400).json({
        error: 'Paramètre URL manquant',
        usage: '/iframe?url=https://sharecloudy.com/iframe/aPgZqyX0gq'
      });
    }

    if (!isValidUrl(url)) {
      return res.status(400).json({
        error: 'URL invalide'
      });
    }

    // Vérifier le cache
    const cacheKey = `iframe_${url}`;
    const cachedUrl = cache.get(cacheKey);
    if (cachedUrl) {
      console.log('✓ Données récupérées du cache');
      return res.json({ url: cachedUrl });
    }

    console.log(`→ Récupération de l'iframe: ${url}`);

    // Récupérer le contenu de l'iframe
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Referer': new URL(url).origin,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
      },
      timeout: 10000
    });

    const html = response.data;
    const $ = cheerio.load(html);

    // Rechercher l'URL M3U8 dans le code source
    let m3u8Url = null;
    
    // Méthode 1: Chercher dans les scripts
    $('script').each((i, script) => {
      const content = $(script).html();
      if (content) {
        // Rechercher des patterns courants pour M3U8
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

    // Méthode 2: Chercher dans les balises source/video
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
        error: 'URL M3U8 non trouvée dans l\'iframe',
        suggestion: 'Vérifiez que l\'URL de l\'iframe est correcte'
      });
    }

    // Construire l'URL complète si nécessaire
    if (m3u8Url.startsWith('//')) {
      m3u8Url = 'https:' + m3u8Url;
    } else if (m3u8Url.startsWith('/')) {
      const baseUrl = new URL(url);
      m3u8Url = `${baseUrl.protocol}//${baseUrl.host}${m3u8Url}`;
    } else if (!m3u8Url.startsWith('http')) {
      const baseUrl = new URL(url);
      m3u8Url = `${baseUrl.protocol}//${baseUrl.host}/${m3u8Url}`;
    }

    console.log(`✓ URL M3U8 trouvée: ${m3u8Url}`);

    // Construire l'URL avec le proxy
    const proxifiedUrl = `${PROXY_URL}?url=${encodeURIComponent(m3u8Url)}`;

    // Mettre en cache
    cache.set(cacheKey, proxifiedUrl);

    // Renvoyer l'URL proxifiée
    res.json({
      url: proxifiedUrl
    });

  } catch (error) {
    console.error('✗ Erreur:', error.message);
    res.status(500).json({
      error: 'Erreur lors de la récupération de l\'iframe',
      message: error.message,
      details: error.response?.status ? `Status HTTP: ${error.response.status}` : undefined
    });
  }
});

// Route proxy pour les requêtes M3U8 et segments TS
app.get('/proxy', async (req, res) => {
  try {
    const { url } = req.query;

    if (!url) {
      return res.status(400).json({
        error: 'Paramètre URL manquant',
        usage: '/proxy?url=https://example.com/video.m3u8'
      });
    }

    if (!isValidUrl(url)) {
      return res.status(400).json({
        error: 'URL invalide'
      });
    }

    console.log(`→ Proxy: ${url}`);

    // Déterminer le type de contenu
    const isM3U8 = url.includes('.m3u8');
    const isTS = url.includes('.ts');

    // Headers pour la requête
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Referer': new URL(url).origin,
      'Origin': new URL(url).origin,
      'Accept': isM3U8 ? 'application/vnd.apple.mpegurl,*/*' : '*/*',
      'Accept-Encoding': 'gzip, deflate',
      'Connection': 'keep-alive'
    };

    // Ajouter le header Range si présent
    if (req.headers.range) {
      headers['Range'] = req.headers.range;
    }

    // Configuration Axios
    const config = {
      method: 'GET',
      url: url,
      headers: headers,
      responseType: isTS ? 'stream' : 'text',
      timeout: 30000,
      maxRedirects: 5,
      validateStatus: (status) => status < 500
    };

    const response = await axios(config);

    // Définir les headers de réponse
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Range, Content-Type');
    
    if (response.headers['content-type']) {
      res.setHeader('Content-Type', response.headers['content-type']);
    }
    
    if (response.headers['content-length']) {
      res.setHeader('Content-Length', response.headers['content-length']);
    }
    
    if (response.headers['content-range']) {
      res.setHeader('Content-Range', response.headers['content-range']);
    }

    // Pour les fichiers M3U8, modifier les URLs relatives
    if (isM3U8) {
      let content = response.data;
      const baseUrl = url.substring(0, url.lastIndexOf('/') + 1);

      // Remplacer les URLs relatives par des URLs absolues via notre proxy
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
      res.status(response.status).send(content);
    } else {
      // Pour les segments TS, streamer directement
      res.status(response.status);
      response.data.pipe(res);
    }

  } catch (error) {
    console.error('✗ Erreur proxy:', error.message);
    
    if (error.response) {
      res.status(error.response.status).json({
        error: 'Erreur lors de la récupération de la ressource',
        status: error.response.status,
        message: error.message
      });
    } else {
      res.status(500).json({
        error: 'Erreur serveur',
        message: error.message
      });
    }
  }
});

// Route health check
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
      keys: cache.keys().length,
      stats: cache.getStats()
    }
  });
});

// Route pour vérifier que le serveur fonctionne
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    version: '1.0.0',
    endpoints: {
      health: {
        url: '/health',
        description: 'Vérifier l\'état du serveur',
        example: '/health'
      },
      iframe: {
        url: '/iframe?url=<URL_IFRAME>',
        description: 'Extrait l\'URL M3U8 depuis une iframe',
        example: `/iframe?url=https://sharecloudy.com/iframe/aPgZqyX0gq`
      },
      proxy: {
        url: '/proxy?url=<URL_M3U8>',
        description: 'Proxifie les requêtes M3U8 et segments TS',
        example: `/proxy?url=https://example.com/video.m3u8`
      }
    },
    features: [
      'CORS activé',
      'Rate limiting',
      'Cache (5 minutes)',
      'Support HLS/M3U8',
      'Streaming des segments TS',
      'Gestion des erreurs',
      'Health check'
    ]
  });
});

// Gestion des erreurs 404
app.use((req, res) => {
  res.status(404).json({
    error: 'Route non trouvée',
    availableRoutes: ['/', '/health', '/iframe', '/proxy']
  });
});

// Démarrage du serveur
app.listen(PORT, () => {
  console.log('\n🚀 Serveur proxy démarré!');
  console.log(`📡 Port: ${PORT}`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log(`🔗 Proxy URL: ${PROXY_URL}`);
  console.log('\n📋 Routes disponibles:');
  console.log(`   - GET /              → Informations du serveur`);
  console.log(`   - GET /health        → État de santé du serveur`);
  console.log(`   - GET /iframe?url=   → Extraction M3U8 depuis iframe`);
  console.log(`   - GET /proxy?url=    → Proxy pour M3U8 et segments\n`);
});

// Gestion propre de l'arrêt
process.on('SIGINT', () => {
  console.log('\n👋 Arrêt du serveur...');
  process.exit(0);
});