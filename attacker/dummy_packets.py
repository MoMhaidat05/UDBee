import socket, struct, time, random, os, base64
from stun import build_stun_attribute
from message_fragmentation import fragment_message
from encryption import encrypt_message

def build_stun_message(message):
    message_types = [0x0102, 0x0111]
    message_type = random.choice(message_types)
    magic_cookie = 0x2112A442

    attribute = build_stun_attribute(message)
    transaction_id = os.urandom(12)  # Random 12-byte transaction ID
    attribute_length = len(attribute)
    header = struct.pack('!HHI12s', message_type, attribute_length, magic_cookie, transaction_id)
    return header + attribute



def send_dummy_stun(ip, target_port, rsa_key, chunk_size, delay, jitter):
    packets_sent = 0
    try:
        dummy_socket_ipv4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!@#$%^&*()=+[]{}|;:',.<>?/~`"
        message = ''.join(random.choice(alphabet) for _ in range(random.randint(30, 100)))
        encrypted_message = encrypt_message(message, rsa_key)["message"]
        encrypted_message = base64.b64encode(encrypted_message.encode('utf8')).decode('utf8')
        chunks = fragment_message(encrypted_message, chunk_size)
        for chunk in chunks:
            stun_message = build_stun_message(chunk)
            jitter_delay = delay + random.uniform(-jitter, jitter)
            jitter_delay = max(0, jitter_delay)
            time.sleep(jitter_delay)
            if random.choice([True, False]):
                dummy_socket_ipv4.sendto(stun_message, (ip, target_port))
                packets_sent += 1
        dummy_socket_ipv4.close()
        return packets_sent
            
    except:
        return packets_sent
    
