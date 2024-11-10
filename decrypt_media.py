from flask import Flask, request, send_file, abort
import requests
import base64
import io
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
import os

app = Flask(__name__)

# Read API token from environment variable
api_token = os.environ.get('API_TOKEN', 'your_api_token')  # Replace 'your_api_token' with your token

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
        encrypted_file_response = requests.get(data['url'], stream=True)
        encrypted_file_response.raise_for_status()
        encrypted_content = encrypted_file_response.content

        # Decrypt the media
        decrypted_content = decrypt_whatsapp_media(
            encrypted_content,
            data['mediaKey'],
            data['fileEncSha256'],
            data.get('fileSha256')  # Optional
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

def decrypt_whatsapp_media(encrypted_content, media_key_base64, file_enc_sha256_base64, file_sha256_base64=None):
    # Decode base64 keys
    media_key = base64.b64decode(media_key_base64)
    file_enc_sha256 = base64.b64decode(file_enc_sha256_base64)

    # Verify the SHA256 hash of the encrypted content (including MAC)
    calculated_enc_sha256 = SHA256.new(encrypted_content).digest()
    if calculated_enc_sha256 != file_enc_sha256:
        raise ValueError("Encrypted file SHA256 hash does not match fileEncSha256")

    # Derive keys using HKDF
    derivative = HKDF(
        master=media_key,
        key_len=112,
        salt=b'\x00' * 32,
        hashmod=SHA256,
        context=b'WhatsApp Media Keys'
    )

    iv = derivative[0:16]
    cipher_key = derivative[16:48]
    mac_key = derivative[48:80]
    # The remaining bytes (refKey) are not used in this context

    # Split encrypted content and MAC
    file_mac = encrypted_content[-10:]
    encrypted_content_no_mac = encrypted_content[:-10]

    # Verify MAC
    hmac = HMAC.new(mac_key, encrypted_content_no_mac, digestmod=SHA256)
    calc_mac = hmac.digest()[:10]

    if calc_mac != file_mac:
        raise ValueError("MAC verification failed")

    # Decrypt the file
    cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_content_no_mac)

    # Remove PKCS#7 padding
    pad_len = decrypted[-1]
    decrypted = decrypted[:-pad_len]

    # Optionally verify decrypted file's SHA256 hash
    if file_sha256_base64:
        file_sha256 = base64.b64decode(file_sha256_base64)
        calculated_file_sha256 = SHA256.new(decrypted).digest()
        if calculated_file_sha256 != file_sha256:
            raise ValueError("Decrypted file SHA256 hash does not match fileSha256")

    return decrypted

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
