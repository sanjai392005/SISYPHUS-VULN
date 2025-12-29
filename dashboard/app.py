"""
Dashboard Flask Application

Web-based dashboard for viewing vulnerability scan results.
"""

import os
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import VulnerabilityScanner, ScanResult


UPLOAD_FOLDER = '/tmp/vuln-scanner-uploads'
ALLOWED_EXTENSIONS = {'ipynb', 'txt', 'toml'}


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
    app.secret_key = os.urandom(24)
    
    # Ensure upload folder exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Store scan results in memory
    app.config['SCAN_RESULTS'] = {}
    
    @app.route('/')
    def index():
        """Main dashboard page."""
        # Check if there's a pre-loaded result from CLI
        preloaded_result = app.config.get('SCAN_RESULT')
        return render_template('index.html', result=preloaded_result)
    
    @app.route('/upload', methods=['POST'])
    def upload_file():
        """Handle file upload and scan."""
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Save file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Scan file
        scanner = VulnerabilityScanner()
        result = scanner.scan(filepath)
        
        # Store result
        result_id = os.urandom(8).hex()
        app.config['SCAN_RESULTS'][result_id] = result
        
        # Clean up uploaded file
        try:
            os.remove(filepath)
        except:
            pass
        
        return jsonify({
            'success': True,
            'result_id': result_id,
            'redirect': url_for('view_result', result_id=result_id)
        })
    
    @app.route('/result/<result_id>')
    def view_result(result_id):
        """View scan result."""
        result = app.config['SCAN_RESULTS'].get(result_id)
        if not result:
            return redirect(url_for('index'))
        return render_template('index.html', result=result)
    
    @app.route('/api/scan', methods=['POST'])
    def api_scan():
        """API endpoint for scanning."""
        data = request.get_json()
        if not data or 'path' not in data:
            return jsonify({'error': 'No path provided'}), 400
        
        scanner = VulnerabilityScanner()
        result = scanner.scan(data['path'])
        
        return jsonify(result.to_dict())
    
    @app.route('/api/result/<result_id>')
    def api_get_result(result_id):
        """Get scan result as JSON."""
        result = app.config['SCAN_RESULTS'].get(result_id)
        if not result:
            return jsonify({'error': 'Result not found'}), 404
        return jsonify(result.to_dict())
    
    return app


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Development server
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)
