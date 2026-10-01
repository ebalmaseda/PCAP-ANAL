import os
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from analyzer import analyze_pcap

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

current_file_path = None

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/reset', methods=['GET'])
def reset_filter():
    """Ruta limpia para recargar el reporte sin filtros de IP"""
    global current_file_path
    if current_file_path and os.path.exists(current_file_path):
        results = analyze_pcap(current_file_path, filter_ip=None)
        filename = os.path.basename(current_file_path)
        return render_template('report.html', results=results, filename=filename, filter_ip="")
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
def upload_file():
    global current_file_path
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            filename = secure_filename(file.filename)
            current_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(current_file_path)
    
    filter_ip = request.form.get('filter_ip', '').strip()
    
    if current_file_path and os.path.exists(current_file_path):
        results = analyze_pcap(current_file_path, filter_ip=filter_ip if filter_ip else None)
        filename = os.path.basename(current_file_path)
        return render_template('report.html', results=results, filename=filename, filter_ip=filter_ip)
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)