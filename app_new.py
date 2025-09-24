"""
NetHub Web Tools - Main Application
Modular Flask application with organized routes by function categories
"""

from flask import Flask, render_template, request, jsonify
from routes.core import core_bp
from routes.ssl_security import ssl_security_bp
from routes.network_tools import network_tools_bp
from routes.utility_tools import utility_tools_bp
from routes.utils import init_database, get_recent_searches

# Create Flask application
app = Flask(__name__)

# Initialize database
init_database()

# Register blueprints
app.register_blueprint(core_bp)
app.register_blueprint(ssl_security_bp)
app.register_blueprint(network_tools_bp)
app.register_blueprint(utility_tools_bp)

# Additional API routes that don't fit into categories
@app.route('/api/recent-searches')
def get_recent_searches_api():
    """Get recent searches for display"""
    limit = request.args.get('limit', 10, type=int)
    searches = get_recent_searches(limit)
    return jsonify(searches)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8084, debug=True)