import rsa, json, base64
from Crypto.Cipher import AES

# Removes PKCS7 padding from decrypted data
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Decrypts a message using hybrid RSA + AES-GCM encryption
def decrypt_message(message, rsa_private_key):
    try:
        # Ensure message is a string for JSON parsing
        if isinstance(message, bytes):
            message = message.decode("utf8")
        obj = json.loads(message)
        # Decode base64-encoded fields from the message
        encrypted_key = base64.b64decode(obj["key"])
        nonce = base64.b64decode(obj["nonce"])
        ciphertext = base64.b64decode(obj["data"])
        tag = base64.b64decode(obj["tag"])
        # Decrypt AES key using RSA private key
        aes_key = rsa.decrypt(encrypted_key, rsa_private_key)
        # Initialize AES cipher in GCM mode for authenticated decryption
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        # Decrypt and verify the ciphertext
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        # Remove padding and decode to string
        return {"message": unpad(plaintext).decode("utf8", errors="replace"), "status": 200}
    except ValueError:
        # Raised if authentication tag verification fails
        return {"message": "Tag verification failed", "status": 403}
    except Exception as e:
        # General failure (e.g., wrong key, corrupted data)
        return {"message": "Failed to decrypt the message", "status": 401}