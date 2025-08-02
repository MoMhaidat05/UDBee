import random, socket

def get_available_port():
    port = random.randint(10000,50000)
    ip = "0.0.0.0"
    while True:
        try:
            test_port_socket =socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_port_socket.bind((ip, port))
            test_port_socket.close()
            return port
        except OSError:
            continue