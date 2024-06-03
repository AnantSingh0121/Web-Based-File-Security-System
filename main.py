import os
import hashlib
import datetime
from flask import Flask, request, render_template, send_file
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

load_dotenv()
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

MONGO_URI = os.getenv("MONGO_URI") or "mongodb://localhost:27017"
client = MongoClient(MONGO_URI)
db = client.file_security_db
files_collection = db.files
VT_API_KEY = os.getenv("VT_API_KEY")
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/"
MASTER_KEY = os.getenv("MASTER_KEY")
if MASTER_KEY:
    MASTER_KEY_BYTES = bytes.fromhex(MASTER_KEY)
else:
    MASTER_KEY_BYTES = os.urandom(32)  


def sha256_hash(file_path):
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def encrypt_file(input_path, output_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(input_path, 'rb') as f:
        data = f.read()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted_data)

def decrypt_file(input_path, output_path, key):
    with open(input_path, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    data = decryptor.update(encrypted_data) + decryptor.finalize()
    with open(output_path, 'wb') as f:
        f.write(data)

def scan_file_virustotal(file_path):
    headers = {"x-apikey": VT_API_KEY}
    with open(file_path, 'rb') as f:
        files = {"file": (os.path.basename(file_path), f)}
        resp = requests.post(VT_UPLOAD_URL, files=files, headers=headers)

    if resp.status_code == 200:
        analysis_id = resp.json()["data"]["id"]
        for _ in range(10):  
            report = requests.get(f"{VT_ANALYSIS_URL}{analysis_id}", headers=headers)
            if report.status_code == 200:
                result = report.json()
                status = result["data"]["attributes"]["status"]
                if status == "completed":
                    stats = result["data"]["attributes"]["stats"]
                    return {
                        "status": "completed",
                        "total": sum(stats.values()),
                        "positives": stats.get("malicious", 0)
                    }
        return {"status": "pending", "total": 0, "positives": 0}
    return {"status": "error", "total": 0, "positives": 0}


def store_metadata(filename, metadata):
    try:
        files_collection.update_one(
            {"filename": filename},
            {"$set": metadata},
            upsert=True
        )
        print(f"[INFO] Metadata stored for {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to store metadata: {e}")

def load_metadata(filename):
    return files_collection.find_one({"filename": filename})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    uploaded_file = request.files.get('file')
    if not uploaded_file:
        return "No file uploaded", 400
    orig_filename = secure_filename(uploaded_file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], orig_filename)
    uploaded_file.save(filepath)
    pre_hash = sha256_hash(filepath)
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    enc_filename = f"{orig_filename}_{timestamp}.enc"
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], enc_filename)
    encrypt_file(filepath, enc_path, MASTER_KEY_BYTES)
    vt_result = scan_file_virustotal(filepath)
    metadata = {
        "filename": enc_filename,
        "original_filename": orig_filename,
        "pre_sha256": pre_hash,
        "size": os.path.getsize(enc_path),
        "uploaded_at": datetime.utcnow(),
        "vt_scan": vt_result
    }
    store_metadata(enc_filename, metadata)
    return render_template('dashboard.html', filename=enc_filename, metadata=metadata, action="Encrypted")

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    uploaded_file = request.files.get('file')
    if not uploaded_file:
        return "No file uploaded", 400

    enc_filename = secure_filename(uploaded_file.filename)
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], enc_filename)
    uploaded_file.save(enc_path)
    stored_meta = load_metadata(enc_filename)
    if stored_meta and "original_filename" in stored_meta:
        dec_filename = stored_meta["original_filename"]
    else:
        dec_filename = enc_filename.replace(".enc", ".dec")

    dec_path = os.path.join(app.config['UPLOAD_FOLDER'], dec_filename)
    decrypt_file(enc_path, dec_path, MASTER_KEY_BYTES)

    return render_template('dashboard.html', filename=dec_filename, metadata=stored_meta, action="Decrypted")

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), as_attachment=True)
if __name__ == '__main__':
    app.run(debug=True, threaded=True, use_reloader=False)


