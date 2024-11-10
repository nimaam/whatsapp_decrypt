from flask import Flask, request, send_file, abort
import requests
import base64
import io
from Crypto.Cipher import AES
import os

app = Flask(__name__)

api_token = os.environ.get('API_TOKEN', 'your_api_token')  # Read API token from environment variable

@app.route('/decrypt_media', methods=['POST'])
def decrypt_media():
    # Validate API token
    token = request.headers.get('Authorization')
    if token != f'Bearer {api_token}':
        return abort(401, description='Unauthorized')

    data = request.get_json()

    # Required fields
    required_fields = ['url', 'mimetype', 'fileLength', 'fileEncSha256', 'mediaKey']
    if not all(field in data for field in required_fields):
        return abort(400, description='Missing required fields')

    try:
        # Download the encrypted file
        encrypted_file = requests.get(data['url'], stream=True)
        encrypted_file.raise_for_status()
        encrypted_content = encrypted_file.content

        # Decrypt the media
        decrypted_content = decrypt_whatsapp_media(
            encrypted_content,
            data['mediaKey'],
            data['fileEncSha256']
        )

        # Prepare the file for response
        return send_file(
            io.BytesIO(decrypted_content),
            mimetype=data['mimetype'],
            as_attachment=True,
            attachment_filename='decrypted_file'
        )

    except Exception as e:
        return abort(500, description=str(e))

def decrypt_whatsapp_media(encrypted_content, media_key_base64, file_enc_sha256_base64):
    # Decode base64 keys
    media_key = base64.b64decode(media_key_base64)
    file_enc_sha256 = base64.b64decode(file_enc_sha256_base64)

    # Derive keys
    derivative = HKDF(media_key, 112)

    iv = derivative[0:16]
    cipher_key = derivative[16:48]
    mac_key = derivative[48:80]

    # Decrypt the file
    cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_content[:-10])  # Exclude last 10 bytes (MAC)

    # Remove padding
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]

    return decrypted

def HKDF(key, length):
    # Simple HKDF implementation
    import hashlib
    from hmac import new as hmac_new

    salt = b'\x00' * hashlib.sha256().digest_size
    info = b'WhatsApp Media Keys'
    prk = hmac_new(salt, key, hashlib.sha256).digest()
    okm = b''
    prev = b''

    for i in range(1, -(-length // hashlib.sha256().digest_size) + 1):
        prev = hmac_new(prk, prev + info + bytes([i]), hashlib.sha256).digest()
        okm += prev

    return okm[:length]

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
