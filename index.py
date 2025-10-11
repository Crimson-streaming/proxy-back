from flask import Flask, request, Response, stream_with_context
import requests
import logging
from urllib.parse import unquote, urljoin, urlparse
import re

app = Flask(__name__)

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Headers pour contourner les restrictions
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Mobile Safari/537.36',
    'Accept': '*/*',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
    'DNT': '1',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'sec-ch-ua': '"Chromium";v="141", "Not?A_Brand";v="8"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"'
}

@app.after_request
def after_request(response):
    """Ajouter les headers CORS à toutes les réponses"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, HEAD'
    response.headers['Access-Control-Allow-Headers'] = 'Origin, Range, Content-Type, Accept, Authorization'
    response.headers['Access-Control-Expose-Headers'] = 'Content-Length, Content-Range, Accept-Ranges'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

def modify_m3u8_content(content, base_url, proxy_base):
    """
    Modifie le contenu M3U8 pour ajouter le proxy aux URLs relatives
    """
    lines = content.split('\n')
    modified_lines = []
    
    for line in lines:
        line = line.strip()
        
        # Si la ligne est vide ou est un commentaire (commence par #), on la garde
        if not line or line.startswith('#'):
            # Mais on doit aussi traiter les URI dans les tags
            if '#EXT-X-KEY' in line or '#EXT-X-MAP' in line:
                # Rechercher les URI dans ces tags
                uri_match = re.search(r'URI="([^"]+)"', line)
                if uri_match:
                    original_uri = uri_match.group(1)
                    if not original_uri.startswith('http'):
                        # URL relative, la rendre absolue puis proxifier
                        absolute_uri = urljoin(base_url, original_uri)
                        proxied_uri = f"{proxy_base}?url={absolute_uri}"
                        line = line.replace(f'URI="{original_uri}"', f'URI="{proxied_uri}"')
            modified_lines.append(line)
        else:
            # C'est une URL de segment
            if not line.startswith('http'):
                # URL relative, la rendre absolue
                absolute_url = urljoin(base_url, line)
                # Ajouter le proxy
                proxied_url = f"{proxy_base}?url={absolute_url}"
                modified_lines.append(proxied_url)
            else:
                # URL absolue, ajouter juste le proxy
                proxied_url = f"{proxy_base}?url={line}"
                modified_lines.append(proxied_url)
    
    return '\n'.join(modified_lines)

@app.route('/')
def index():
    """Page d'accueil avec documentation"""
    return """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>M3U8 CORS Proxy</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            .container {
                max-width: 900px;
                margin: 50px auto;
                background: white;
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            }
            h1 {
                color: #333;
                margin-bottom: 10px;
                font-size: 32px;
            }
            .badge {
                display: inline-block;
                background: #28a745;
                color: white;
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
                margin-bottom: 20px;
            }
            p {
                color: #666;
                line-height: 1.8;
                margin-bottom: 15px;
            }
            .code-box {
                background: #2d2d2d;
                color: #f8f8f2;
                padding: 20px;
                border-radius: 10px;
                margin: 20px 0;
                overflow-x: auto;
                font-family: 'Courier New', monospace;
                font-size: 14px;
            }
            .highlight {
                color: #50fa7b;
            }
            .section {
                margin: 30px 0;
                padding: 20px;
                background: #f8f9fa;
                border-radius: 10px;
                border-left: 4px solid #667eea;
            }
            h2 {
                color: #667eea;
                margin-bottom: 15px;
                font-size: 20px;
            }
            ul {
                margin-left: 20px;
                color: #555;
            }
            li {
                margin: 8px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🎬 M3U8 CORS Proxy</h1>
            <span class="badge">✓ EN LIGNE</span>
            
            <p>Serveur proxy professionnel pour contourner les restrictions CORS sur les fichiers M3U8 et les flux vidéo.</p>
            
            <div class="section">
                <h2>📖 Utilisation</h2>
                <p>Format de l'URL proxy :</p>
                <div class="code-box">
                    http://127.0.0.1:5000/proxy?url=<span class="highlight">VOTRE_URL_M3U8</span>
                </div>
                
                <p><strong>Exemple :</strong></p>
                <div class="code-box">
                    http://127.0.0.1:5000/proxy?url=https://share31960.sharecloudy.com/files/aa/VvaY1tly1pFxqrDgWXB38lIpPbGx4CZZ89Xrq.m3u8
                </div>
            </div>

            <div class="section">
                <h2>✨ Fonctionnalités</h2>
                <ul>
                    <li>✅ Contournement CORS complet</li>
                    <li>✅ Réécriture automatique des URLs M3U8</li>
                    <li>✅ Support des URLs relatives et absolues</li>
                    <li>✅ Support des requêtes Range (streaming par morceaux)</li>
                    <li>✅ Headers personnalisés pour simuler un navigateur réel</li>
                    <li>✅ Support M3U8, TS, MP4 et tous formats vidéo</li>
                    <li>✅ Streaming en temps réel</li>
                    <li>✅ Gestion automatique des redirections</li>
                </ul>
            </div>

            <div class="section">
                <h2>💻 Intégration HTML/JavaScript</h2>
                <div class="code-box">
&lt;video controls&gt;
    &lt;source src="http://127.0.0.1:5000/proxy?url=VOTRE_URL" type="application/x-mpegURL"&gt;
&lt;/video&gt;
                </div>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/proxy')
def proxy():
    """Route principale du proxy"""
    # Récupérer l'URL cible
    target_url = request.args.get('url')
    
    if not target_url:
        return Response(
            '{"error": "Paramètre URL manquant. Utilisation: /proxy?url=VOTRE_URL"}',
            status=400,
            mimetype='application/json'
        )
    
    # Décoder l'URL si elle est encodée
    target_url = unquote(target_url)
    
    logger.info(f"Proxying request to: {target_url}")
    
    try:
        # Préparer les headers
        headers = DEFAULT_HEADERS.copy()
        
        # Ajouter le Referer et Origin basés sur l'URL cible
        if 'sharecloudy.com' in target_url:
            headers['Referer'] = 'https://sharecloudy.com/'
            headers['Origin'] = 'https://sharecloudy.com'
        
        # Transférer le header Range si présent (pour le streaming)
        if 'Range' in request.headers:
            headers['Range'] = request.headers['Range']
        
        # Transférer If-None-Match et If-Modified-Since pour le cache
        if 'If-None-Match' in request.headers:
            headers['If-None-Match'] = request.headers['If-None-Match']
        if 'If-Modified-Since' in request.headers:
            headers['If-Modified-Since'] = request.headers['If-Modified-Since']
        
        # Faire la requête vers la ressource cible
        response = requests.get(
            target_url,
            headers=headers,
            stream=True,
            allow_redirects=True,
            timeout=30
        )
        
        # Vérifier si c'est un fichier M3U8
        content_type = response.headers.get('Content-Type', '').lower()
        is_m3u8 = (
            target_url.endswith('.m3u8') or 
            'mpegurl' in content_type or 
            'application/vnd.apple.mpegurl' in content_type or
            'application/x-mpegurl' in content_type
        )
        
        if is_m3u8:
            # Lire tout le contenu du M3U8
            content = response.content.decode('utf-8')
            
            # Obtenir l'URL de base pour résoudre les URLs relatives
            parsed_url = urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{'/'.join(parsed_url.path.split('/')[:-1])}/"
            
            # Obtenir l'URL du proxy
            proxy_base = f"http://{request.host}/proxy"
            
            # Modifier le contenu M3U8
            modified_content = modify_m3u8_content(content, base_url, proxy_base)
            
            logger.info(f"Modified M3U8 content with proxy URLs")
            
            # Retourner le contenu modifié
            return Response(
                modified_content,
                status=response.status_code,
                mimetype='application/vnd.apple.mpegurl'
            )
        else:
            # Pour les autres fichiers (segments TS, etc.), streamer directement
            excluded_headers = [
                'content-encoding', 
                'content-length', 
                'transfer-encoding', 
                'connection',
                'access-control-allow-origin',
                'access-control-allow-methods',
                'access-control-allow-headers',
                'access-control-expose-headers'
            ]
            
            response_headers = [
                (name, value) for name, value in response.raw.headers.items()
                if name.lower() not in excluded_headers
            ]
            
            return Response(
                stream_with_context(response.iter_content(chunk_size=8192)),
                status=response.status_code,
                headers=response_headers
            )
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error proxying request: {str(e)}")
        return Response(
            f'{{"error": "Erreur lors de la requête: {str(e)}"}}',
            status=500,
            mimetype='application/json'
        )

@app.route('/health')
def health():
    """Endpoint de santé"""
    return {"status": "ok", "service": "M3U8 CORS Proxy"}

@app.route('/proxy', methods=['OPTIONS'])
def proxy_options():
    """Répondre aux requêtes OPTIONS (preflight)"""
    response = Response()
    return response

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 M3U8 CORS Proxy Server")
    print("=" * 60)
    print("📍 Server: http://127.0.0.1:5000")
    print("📖 Documentation: http://127.0.0.1:5000")
    print("🔗 Usage: http://127.0.0.1:5000/proxy?url=YOUR_M3U8_URL")
    print("=" * 60)
    print("✨ Features:")
    print("   - Automatic M3U8 URL rewriting")
    print("   - CORS bypass for all resources")
    print("   - Support for relative and absolute URLs")
    print("=" * 60)
    print()
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )