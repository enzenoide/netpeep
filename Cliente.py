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

    def tcp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", self.tcp_port))
        sock.listen(5)
    

        while self.running:
            conn, addr = sock.accept()
            client_public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.sendall(client_public_pem)
            #O PROBLEMA SÃO ESSAS LINHAS ABAIXO, ESTÁ RECEBENDO A RESPOSTA DO AUTHORIZED E TRATANDO COMO SE FOSSE A CHAVE PUBLICA

            server_public_pem = conn.recv(4096) #recebe a chave publica por bytes PEM
            if not self.verificar_servidor(server_public_pem):
                conn.close()
            public_key_server = serialization.load_pem_public_key(server_public_pem) #converte bytes em objeto criptografico, agora o cliente pode criptografar

            
            
            aes_key = os.urandom(32) #32 random bytes
            encrypted_aes = public_key_server.encrypt( #criptografa a chave AES usando RSA, so o servidor com a chave privada consegue abrir
                aes_key,
                padding.OAEP( #define o padding moderno
            mgf=padding.MGF1(algorithm=hashes.SHA256()), #SHA-256 garante aleatoriedade e proteção contra ataque matematicos
            algorithm=hashes.SHA256(),
            label=None
                )
            )
            conn.sendall(encrypted_aes) #Envia a chave AES criptografada para o servidor

            payload = conn.recv(1024) #recebe dados criptografados via AES-GCM
            nonce = payload[:12] # separa a parte do payload que refere ao nonce
            ciphertext = payload[12:] # separa a parte do payload que refere a ciphertext + tag

            aesgcm = AESGCM(aes_key) # Cria o objeto AES usando chave compartilhada
            cmd = aesgcm.decrypt(nonce, ciphertext, None) # Descriptografa e valida se os dados foram alterados,se o nonce/chaves estao erradas,ciphertext e nonce morre aq

            try:
                if cmd == b"GET_INVENTORY": #b pq cmd é bytes
                    
                    inventario = {
                        "SO": self.sistema_op(),             
                        "cpu": self.nucleos(),       
                        "ram": self.memoria(),
                        "disco": self.disco(), 
                        "interfaces": self.interfaces()
                    }
                    
                    
                    import json
                    response = json.dumps(inventario) # converte dicionario para json
                    aesgcm = AESGCM(aes_key) #cria um objeto capaz de criptografar e descriptografar usando AES-GCM com essa chave

                    nonce = os.urandom(12)#novo nonce

                    ciphertext = aesgcm.encrypt(nonce,response.encode(),None) #nova mensagem criptografa
                    
                    conn.sendall(nonce + ciphertext)
                    print(f"[Enviado] Inventário completo enviado para {addr}")
            except Exception as e:
                print(f"ERRO: {e}")
            finally:
                conn.close()
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
