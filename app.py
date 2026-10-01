from flask import Flask, render_template, request, redirect, url_for, session
import os
from werkzeug.utils import secure_filename
from analyzer import analyze_pcap

app = Flask(__name__)
app.secret_key = "secret_key_diagnostico_n1"

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

current_pcap_path = None
current_filename = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    global current_pcap_path, current_filename
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            current_pcap_path = file_path
            current_filename = filename
            session['filter_ip'] = ''

    filter_ip = request.form.get('filter_ip', '').strip()
    if filter_ip:
        session['filter_ip'] = filter_ip
    else:
        filter_ip = session.get('filter_ip', '')

    if not current_pcap_path or not os.path.exists(current_pcap_path):
        return redirect(url_for('index'))

    results = analyze_pcap(current_pcap_path, filter_ip=filter_ip if filter_ip else None)
    return render_template('report.html', results=results, filename=current_filename, filter_ip=filter_ip)

@app.route('/reset')
def reset_filter():
    session['filter_ip'] = ''
    return redirect(url_for('upload_file'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)