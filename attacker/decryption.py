import rsa, json, base64
from Crypto.Cipher import AES

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def decrypt_message(message, rsa_private_key):
    try:
        if isinstance(message, bytes):
            message = message.decode("utf8")
        obj = json.loads(message)
        encrypted_key = base64.b64decode(obj["key"])
        nonce = base64.b64decode(obj["nonce"])
        ciphertext = base64.b64decode(obj["data"])
        tag = base64.b64decode(obj["tag"])
        aes_key = rsa.decrypt(encrypted_key, rsa_private_key)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return {"message": unpad(plaintext).decode("utf8", errors="replace"), "status": 200}
    except ValueError:
        return {"message": "Tag verification failed", "status": 403}
    except Exception as e:
        return {"message": "Failed to decrypt the message", "status": 401}