import rsa, json, base64
from Crypto.Cipher import AES

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def decrypt_message(message, key):
    try:
        if isinstance(message, bytes):
            message = message.decode('utf8')

        key_and_data = json.loads(message)
        aes_key = base64.b64decode(key_and_data["key"])
        data = base64.b64decode(key_and_data["data"])
        decrypted_key = rsa.decrypt(aes_key, key)
        aes_cipher = AES.new(decrypted_key, AES.MODE_ECB)
        plaintext = aes_cipher.decrypt(data)
    
        return {"message": unpad(plaintext).decode('utf8'), "status": 200}
    except:
        return {"message": "Failed to decrypt the message, there is a possible problem with the key", "status": 401}
