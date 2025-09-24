"""
Core Routes
Handles homepage, robots.txt, sitemap.xml, and static files
"""

from flask import Blueprint, render_template, send_from_directory, current_app
from .utils import get_recent_searches

# Create blueprint
core_bp = Blueprint('core', __name__)

@core_bp.route('/')
def homepage():
    """Homepage with all tools"""
    recent_searches = get_recent_searches(10)
    return render_template('homepage.html', recent_searches=recent_searches)

@core_bp.route('/robots.txt')
def robots_txt():
    """Robots.txt for SEO"""
    return send_from_directory(current_app.static_folder, 'robots.txt')

@core_bp.route('/sitemap.xml')
def sitemap_xml():
    """Sitemap.xml for SEO"""
    return send_from_directory(current_app.static_folder, 'sitemap.xml')

@core_bp.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory(current_app.static_folder, filename)
