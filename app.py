from flask import Flask, request, send_file, render_template, redirect, url_for
from werkzeug.utils import secure_filename
import os
import rsa
import time

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Paths for saving RSA keys
PUBLIC_KEY_PATH = 'public_key.pem'
PRIVATE_KEY_PATH = 'private_key.pem'

# Generate RSA keys if not found
def generate_keys(key_size=2048):
    (public_key, private_key) = rsa.newkeys(key_size)
    with open(PUBLIC_KEY_PATH, 'wb') as pub_file:
        pub_file.write(public_key.save_pkcs1())
    with open(PRIVATE_KEY_PATH, 'wb') as priv_file:
        priv_file.write(private_key.save_pkcs1())
    return public_key, private_key

# Load public and private keys
def load_public_key():
    with open(PUBLIC_KEY_PATH, 'rb') as pub_file:
        return rsa.PublicKey.load_pkcs1(pub_file.read())

def load_private_key():
    with open(PRIVATE_KEY_PATH, 'rb') as priv_file:
        return rsa.PrivateKey.load_pkcs1(priv_file.read())

def encrypt_image(image_data, public_key):
    max_chunk_size = (public_key.n.bit_length() + 7) // 8 - 11  # 11 bytes for PKCS#1 v1.5 padding
    encrypted_chunks = []

    for i in range(0, len(image_data), max_chunk_size):
        chunk = image_data[i:i + max_chunk_size]
        encrypted_chunk = rsa.encrypt(chunk, public_key)
        encrypted_chunks.append(encrypted_chunk)

    return b"".join(encrypted_chunks)

def decrypt_image(encrypted_data, private_key):
    decrypted_chunks = []
    encrypted_chunk_size = rsa.common.byte_size(private_key.n)  # Adjust according to the key size
    for i in range(0, len(encrypted_data), encrypted_chunk_size):
        chunk = encrypted_data[i:i + encrypted_chunk_size]
        decrypted_chunk = rsa.decrypt(chunk, private_key)
        decrypted_chunks.append(decrypted_chunk)
    return b"".join(decrypted_chunks)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload_encrypt', methods=['POST'])
def upload_encrypt():
    if 'file' not in request.files:
        return redirect(url_for('index'))
    
    file = request.files['file']
    key_size = int(request.form['key_size'])

    if file.filename == '':
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    with open(file_path, 'rb') as f:
        image_data = f.read()

    # Generate RSA keys if not provided
    public_key, private_key = generate_keys(key_size)

    # Encrypt the image and measure time
    start_time = time.time()
    encrypted_data = encrypt_image(image_data, public_key)
    encryption_time = time.time() - start_time

    encrypted_filename = filename.split('.')[0] + '_encrypted.bin'
    encrypted_file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
    with open(encrypted_file_path, 'wb') as enc_file:
        enc_file.write(encrypted_data)

    return render_template('index.html', encryption_time=round(encryption_time, 2), encrypted_file=encrypted_filename)

@app.route('/upload_decrypt', methods=['POST'])
def upload_decrypt():
    if 'file' not in request.files:
        return redirect(url_for('index'))

    file = request.files['file']

    if file.filename == '':
        return redirect(url_for('index'))

    encrypted_data = file.read()

    # Load RSA keys
    try:
        private_key = load_private_key()
    except FileNotFoundError:
        return render_template('index.html', error="Private key not found. Encryption must be performed first.")

    try:
        # Decrypt the image and measure time
        start_time = time.time()
        decrypted_data = decrypt_image(encrypted_data, private_key)
        decryption_time = time.time() - start_time

        decrypted_image_filename = 'decrypted_image.jpg'
        decrypted_image_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_image_filename)

        with open(decrypted_image_path, 'wb') as img_file:
            img_file.write(decrypted_data)

        return render_template('index.html', decryption_time=round(decryption_time, 2), decrypted_file=decrypted_image_filename)

    except rsa.DecryptionError:
        return render_template('index.html', error="Decryption failed: Invalid key or corrupted data.")
    except Exception as e:
        return render_template('index.html', error="Decryption failed: " + str(e))

# Serve the encrypted and decrypted files for download
@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    
    # Generate keys if they do not exist
    if not os.path.exists(PUBLIC_KEY_PATH) or not os.path.exists(PRIVATE_KEY_PATH):
        generate_keys()
        
    app.run(debug=True)
