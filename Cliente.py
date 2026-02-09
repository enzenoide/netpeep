from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Key import KeyManager
import psutil
import time
import platform
import socket
import json
import threading
import random
import ipaddress
import os
import struct
from pynput.mouse import Controller as MouseController, Button
from pynput.keyboard import Controller as KeyboardController
mouse = MouseController()
keyboard = KeyboardController()
def get_broadcast_address():
    for iface, addrs in psutil.net_if_addrs().items(): #pega a lista de redes de interface e items
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."): # se o endereço for ipv4 e não comecar com 127(ipv4 de loopback)
                ip = addr.address
                mask = addr.netmask
                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False) #Vai descobrir qual rede o cliente pertence 
                return str(network.broadcast_address)#vai retornar o broadcast
        return "<broadcast>"
BROADCAST_ADDR = get_broadcast_address()
BROADCAST_PORT = 50000
BASE_DIR = os.path.join(os.path.dirname(__file__), "Client")
keys = KeyManager(BASE_DIR)
private_key = keys.private_key
public_key = keys.public_key
class MonitorarSistema:
    def __init__(self,intervalo=2):
        self.set_intervalo(intervalo)
        self.tcp_port = random.randint(20000,40000)
        self.running = True
    def get_intervalo(self):
        return self.__intervalo
    def set_intervalo(self,intervalo):
        if intervalo < 0:
            raise ValueError ("O intervalo não pode ser negativo")
    def nucleos(self):
        return psutil.cpu_count(logical=False)
    def memoria(self):
        memoria =  psutil.virtual_memory()
        return memoria.free
    def disco(self):
        disco = psutil.disk_usage('/')
        return disco.free
    def sistema_op(self):
        return platform.system()
    def indentificar_tipo(self,nome):
        nome = nome.lower()
        if "loopback" in nome or nome == "lo": 
            return "Loopback"
        if "wi-fi" in nome or "wlan" in nome or "wifi" in nome: 
            return "Wifi"
        if "bluetooth" in nome:
            return "Bluetooth"
        return "Ethernet"
    def interfaces(self):
        interfaces_list = []
        interface = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for nome, info in interface.items():
            data = {
                "nome": nome,
                "status": "UP" if stats[nome].isup else "DOWN",
                "IP": None,
                "MAC": None,
                "tipo": self.indentificar_tipo(nome)
            }
            for addr in info:
                if addr.family == socket.AF_INET:
                    data["IP"] = addr.address
                elif addr.family == -1 or (hasattr(psutil, 'AF_LINK') and addr.family == psutil.AF_LINK):
                    data["MAC"] = addr.address
            interfaces_list.append(data)
        return interfaces_list
    def send_msg(self, sock, aesgcm, msg):
        payload = json.dumps(msg).encode()
        nonce = os.urandom(12)
        encrypted = aesgcm.encrypt(nonce, payload, None)

        body = nonce + encrypted
        header = struct.pack("!I", len(body))  # 4 bytes tamanho

        sock.sendall(header + body)

    def recv_msg(self, sock, aesgcm):
        header = self.recvall(sock, 4)
        msg_len = struct.unpack("!I", header)[0]

        body = self.recvall(sock, msg_len)

        nonce = body[:12]
        ciphertext = body[12:]

        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode())
    def verificar_servidor(self,public_pem_recebido,
                caminho_fingerprint = os.path.join(BASE_DIR, "server_fingerprint.txt")
):
        digest = hashes.Hash(hashes.SHA256())#Gera o SHA-256 da chave pública recebida
        digest.update(public_pem_recebido)
        fingerprint_recebido = digest.finalize().hex()

        
        with open(caminho_fingerprint, "r") as f:#Lê o fingerprint confiável salvo no cliente
            fingerprint_confiavel = f.read().strip()
        
        if fingerprint_recebido != fingerprint_confiavel:#Compara
            print("Servidor NÃO autenticado (fingerprint diferente)")
            return False
        print("Servidor autenticado com sucesso")
        return True
    def executar_controle(self, msg):
        device = msg.get("device")
        action = msg.get("action")

        if device == "keyboard":
            key_type = msg.get("key_type")
            key_val = msg.get("key")

            try:
                if key_type == "special":
                    k = getattr(keyboard.Key, key_val)
                else:
                    k = key_val
            except Exception as e:
                print("Erro ao resolver tecla:", e)
                return

            if action == "press":
                keyboard.press(k)
            elif action == "release":
                keyboard.release(k)
        elif device == "mouse":
            action = msg.get("action")

            if action == "move":
                dx = msg.get("dx", 0)
                dy = msg.get("dy", 0)
                mouse.move(dx, dy)

            elif action == "click":
                btn = msg.get("button")
                pressed = msg.get("pressed")

                button = Button.left if btn == "left" else Button.right
                if pressed:
                    mouse.press(button)
                else:
                    mouse.release(button)
    def recvall(self,sock, n):
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                raise ConnectionError("Conexão encerrada")
            data += packet
        return data
    def tcp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", self.tcp_port))
        sock.listen(5)

        while self.running:
            conn, addr = sock.accept()
            print(f"[TCP] Conexão de {addr}")

            try:
                # 1️⃣ envia chave pública do cliente
                client_public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                conn.sendall(client_public_pem)

                # 2️⃣ recebe chave pública do servidor
                header = self.recvall(conn, 4)
                pem_len = struct.unpack("!I", header)[0]
                server_public_pem = self.recvall(conn, pem_len)

                if not self.verificar_servidor(server_public_pem):
                    conn.close()
                    continue

                public_key_server = serialization.load_pem_public_key(server_public_pem)

                # 3️⃣ gera AES e envia criptografada
                aes_key = os.urandom(32)
                encrypted_aes = public_key_server.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                conn.sendall(encrypted_aes)

                aesgcm = AESGCM(aes_key)

                controle_ativo = False

                while True:
                    msg = self.recv_msg(conn, aesgcm)
                    tipo = msg.get("type")

                    if tipo == "GET_INVENTORY":
                        inventario = {
                            "SO": self.sistema_op(),
                            "cpu": self.nucleos(),
                            "ram": self.memoria(),
                            "disco": self.disco(),
                            "interfaces": self.interfaces()
                        }
                        self.send_msg(conn, aesgcm, {
                            "type": "INVENTORY_RESPONSE",
                            "data": inventario
                        })

                    elif tipo == "CONTROL_START":
                        controle_ativo = True
                        print("[CLIENTE] 🔒 Controle remoto ATIVADO")

                    elif tipo == "CONTROL_EVENT":
                        if controle_ativo:
                            self.executar_controle(msg)

                    elif tipo == "CONTROL_STOP":
                        controle_ativo = False
                        print("[CLIENTE] 🔓 Controle remoto ENCERRADO")

                    else:
                        print(f"[CLIENTE] Tipo desconhecido: {tipo}")
            except ConnectionError:
                print("[CLIENTE] Conexão perdida, encerrando controle")
    def send_broadcast(self):
        """ Grita na rede avisando que o cliente existe """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        sock.bind(('',0))
        print(f"[UDP] Broadcast iniciado na porta {self.tcp_port}")
        while self.running:
            msg = f"DISCOVER_REQUEST={self.tcp_port}"
            sock.sendto(msg.encode(), (BROADCAST_ADDR, BROADCAST_PORT))
            time.sleep(5) # Avisa a cada 5 segundos
    def run(self):
        print(f"Agente iniciado....")
        threading.Thread(target=self.send_broadcast,daemon=True).start()
        threading.Thread(target=self.tcp,daemon=True).start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Encerrando cliente")
            self.running = False    
    
            
           
if __name__ == "__main__":
    MonitorarSistema().run()
