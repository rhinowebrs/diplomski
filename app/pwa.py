from flask import Blueprint, render_template

bp = Blueprint('pwa', __name__)

@bp.route('/manifest.json')
def manifest():
    return {
        "name": "Flask PWA",
        "short_name": "PWA",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#ffffff",
        "theme_color": "#000000",
        "icons": [
            {
                "src": "/static/images/icon-192x192.png",
                "type": "image/png",
                "sizes": "192x192"
            }
        ]
    }
