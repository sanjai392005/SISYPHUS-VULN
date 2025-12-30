"""
Dashboard Flask Application

Web-based dashboard for viewing vulnerability scan results.
"""

import os
import shutil
import zipfile
import tempfile
from flask import Flask, render_template, request, jsonify, redirect, url_for
from werkzeug.utils import secure_filename

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import VulnerabilityScanner, ScanResult


UPLOAD_FOLDER = '/tmp/vuln-scanner-uploads'
ALLOWED_EXTENSIONS = {'ipynb', 'zip'}


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max for zip files
    app.secret_key = os.urandom(24)
    
    # Ensure upload folder exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    
    # Store scan results in memory
    app.config['SCAN_RESULTS'] = {}
    
    @app.route('/')
    def index():
        """Main dashboard page."""
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
            return jsonify({'error': 'File type not allowed. Use .ipynb or .zip'}), 400
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        scanner = VulnerabilityScanner()
        
        try:
            if filename.lower().endswith('.zip'):
                # Handle zip file - extract and scan as project
                result = handle_zip_upload(filepath, scanner)
            else:
                # Handle .ipynb directly
                result = scanner.scan(filepath)
        except Exception as e:
            return jsonify({'error': f'Scan failed: {str(e)}'}), 500
        finally:
            # Clean up uploaded file
            try:
                os.remove(filepath)
            except:
                pass
        
        # Store result
        result_id = os.urandom(8).hex()
        app.config['SCAN_RESULTS'][result_id] = result
        
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


def handle_zip_upload(zip_path, scanner):
    """
    Extract zip file and scan the project inside.
    
    Args:
        zip_path: Path to the uploaded zip file
        scanner: VulnerabilityScanner instance
        
    Returns:
        ScanResult from scanning the extracted project
    """
    # Create temp directory for extraction
    extract_dir = tempfile.mkdtemp(prefix='vuln-scan-')
    
    try:
        # Extract zip
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(extract_dir)
        
        # Check if zip contains a single directory (common pattern)
        contents = os.listdir(extract_dir)
        if len(contents) == 1:
            inner_path = os.path.join(extract_dir, contents[0])
            if os.path.isdir(inner_path):
                extract_dir = inner_path
        
        # Check if this is actually a notebook disguised as zip
        ipynb_files = [f for f in os.listdir(extract_dir) if f.endswith('.ipynb')]
        if len(ipynb_files) == 1 and len(os.listdir(extract_dir)) == 1:
            # Single notebook in zip - scan as notebook
            return scanner.scan(os.path.join(extract_dir, ipynb_files[0]))
        
        # Scan as project directory (uses Syft or fallback)
        return scanner.scan_project(extract_dir)
        
    finally:
        # Clean up extracted files
        try:
            shutil.rmtree(extract_dir, ignore_errors=True)
        except:
            pass


# Development server
if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='0.0.0.0', port=5000)

