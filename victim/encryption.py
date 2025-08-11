import rsa, base64, json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + chr(pad_len) * pad_len

def encrypt_message(message, rsa_public_key):
    try:
        if isinstance(message, str):
            message = message.encode("utf-8")
        elif not isinstance(message, bytes):
            message = str(message).encode("utf-8")
        aes_key = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_GCM)
        padded = pad(message.decode('utf8')).encode('utf8')
        ciphertext, tag = cipher.encrypt_and_digest(padded)
        encrypted_key = rsa.encrypt(aes_key, rsa_public_key)
        payload = {
            "key": base64.b64encode(encrypted_key).decode("utf8"),
            "nonce": base64.b64encode(cipher.nonce).decode("utf8"),
            "data": base64.b64encode(ciphertext).decode("utf8"),
            "tag": base64.b64encode(tag).decode("utf8")
        }
        return {"message": json.dumps(payload), "status": 200}
    except Exception as e:
        return {"message": "Failed to encrypt the message", "status": 401}

