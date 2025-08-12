import rsa, base64, json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# Pads data to a multiple of 16 bytes using PKCS7-like padding
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + chr(pad_len) * pad_len

# Encrypts a message using hybrid RSA + AES-GCM encryption
def encrypt_message(message, rsa_public_key):
    try:
        # Ensure message is bytes for encryption
        if isinstance(message, str):
            message = message.encode("utf-8")
        elif not isinstance(message, bytes):
            message = str(message).encode("utf-8")
        # Generate random AES key for symmetric encryption
        aes_key = get_random_bytes(16)
        cipher = AES.new(aes_key, AES.MODE_GCM)
        # Pad message before encryption
        padded = pad(message.decode('utf8')).encode('utf8')
        ciphertext, tag = cipher.encrypt_and_digest(padded)
        # Encrypt AES key with RSA public key for secure key exchange
        encrypted_key = rsa.encrypt(aes_key, rsa_public_key)
        # Prepare payload with all required fields, base64-encoded
        payload = {
            "key": base64.b64encode(encrypted_key).decode("utf8"),
            "nonce": base64.b64encode(cipher.nonce).decode("utf8"),
            "data": base64.b64encode(ciphertext).decode("utf8"),
            "tag": base64.b64encode(tag).decode("utf8")
        }
        return {"message": json.dumps(payload), "status": 200}
    except Exception as e:
        # Return error status if encryption fails
        return {"message": "Failed to encrypt the message", "status": 401}

