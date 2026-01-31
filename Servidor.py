from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Key import KeyManager
import socket
import threading
import time
import json
import psutil
import os
BROADCAST_PORT = 50000
BASE_DIR = os.path.join(os.path.dirname(__file__), "Server")
keys = KeyManager(BASE_DIR)
private_key = keys.private_key
public_key = keys.public_key
class ClientInfo:
    def __init__(self, ip, tcp_port):
        self.ip = ip
        self.tcp_port = tcp_port
        self.last_seen = time.time()
        self.last_msg = ""
        self.mac = None

    def update(self, msg):
        self.last_msg = msg
        self.last_seen = time.time()

    def __repr__(self):
        age = round(time.time() - self.last_seen, 1)
        return (f"{self.ip}:{self.tcp_port} | MAC={self.mac} | "
                f"UltimaMsg='{self.last_msg}' | {age}s atrás")


class DiscoveryServer:
    def __init__(self):
        self.clients = {}      # chave: (ip, tcp_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        self.sock.bind(("0.0.0.0", BROADCAST_PORT))

    # ----------------------------------------------------------------
    # ESCUTA BROADCASTS
    # ----------------------------------------------------------------
    
    def listen_broadcasts(self):
        print(f"[Servidor] Ouvindo broadcasts na porta {BROADCAST_PORT}...")

        while True:
            data, addr = self.sock.recvfrom(1024)
            msg = data.decode()
            ip = addr[0]

            if msg.startswith("DISCOVER_REQUEST"):
                tcp_port = int(msg.split("=")[1])
                key = (ip, tcp_port)

                # cadastra usando chave composta
                if key not in self.clients:
                    self.clients[key] = ClientInfo(ip, tcp_port)
                    print(f"[Novo cliente] {ip}:{tcp_port}")

                # atualiza keepalive
                self.clients[key].update(msg)

                # envia resposta UDP
                self.sock.sendto("DISCOVER_RESPONSE".encode(), addr)

    def verifica_cliente(self,public_pem):

        digest = hashes.Hash(hashes.SHA256())#Gera o SHA-256 da chave pública (fingerprint)
        digest.update(public_pem)
        fingerprint = digest.finalize().hex()

       
        auth_file = os.path.join("Server", "authorized_clients.txt")#Caminho do arquivo de clientes autorizados

        
        if not os.path.exists(auth_file): #Se o arquivo não existir, ninguém é autorizado
            return False

        
        with open(auth_file, "r") as f: #Lê todos os fingerprints autorizados
            autorizados = [
                linha.strip()
                for linha in f.readlines()
                if linha.strip()
            ]
        return fingerprint in autorizados
    def recv_exact(self,sock,size):
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Conexão encerrada antes de receber dados completos")
            data += chunk
        return data

    
    def solicitar_inventario(self, key):
        if key not in self.clients:
            print("Cliente não encontrado!")
            return

        ip, port = key
        print(f"\n[Servidor] Solicitando inventário completo de {ip}:{port}...")

        try:
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           
            sock.settimeout(5)
           
            sock.connect((ip, port))
            client_public_pem = sock.recv(4096)

            if not self.verifica_cliente(client_public_pem):
                print("Cliente NÃO autorizado")
                sock.close()
                return
            
            public_pem = public_key.public_bytes( # transforma a chave publica em bytes
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sock.sendall(public_pem) #envia a chave publica
            
            encrypted_aes = sock.recv(256) # recebe a chave AES criptografa
            aes_key = private_key.decrypt( #descriptografa a chave AES
            encrypted_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )
            )
            
            aesgcm = AESGCM(aes_key) #cria um objeto capaz de criptografar e descriptografar usando AES-GCM com essa chave
            
            nonce = os.urandom(12) #gera um novo nonce
            
            payload = aesgcm.encrypt(nonce,b"GET_INVENTORY",None) #criptografa a mensagem 
            
            sock.sendall(nonce + payload)

            
            payload = sock.recv(16384) #recebe o inventario
            nonce = payload[:12] #separa a parte do payload que refere ao nonce
            ciphertext = payload[12:]#separa a parte do payload que refere ao ciphertext
            aesgcm = AESGCM(aes_key)
            dados_json = aesgcm.decrypt(nonce,ciphertext,None)
            sock.close() #descriptografa os dados

            
            dados = json.loads(dados_json.decode())
            self.salvar_inventario(ip,dados)
            self.salvar_geral(ip,dados)
            disco_valor = dados.get('disco')
            self.clients[key].ultimo_disco = disco_valor

            print("\n" + "="*60)
            print(f"       RELATÓRIO DE INVENTÁRIO - {ip}")
            print("="*60)
            print(f"Sistema Operacional: {dados.get('SO')}")
            print(f"Núcleos de CPU:      {dados.get('cpu')}")
            print(f"Memória RAM Livre:   {dados.get('ram') / (1024**3):.2f} GB")
            print(f"Espaço em Disco:     {dados.get('disco') / (1024**3):.2f} GB")
            print("-" * 60)
            
            # --- FORMATAÇÃO DAS INTERFACES ---
            print(f"{'INTERFACE':<20} | {'STATUS':<6} | {'TIPO':<10} | {'IP'}")
            print("-" * 60)

           
            lista_interfaces = dados.get('interfaces', [])
            for rede in lista_interfaces:
                nome = rede.get('nome', 'N/A')
                status = rede.get('status', 'N/A')
                tipo = rede.get('tipo', 'N/A')
                
                ip_addr = rede.get('IP') if rede.get('IP') else "Sem IP"
                
                
                print(f"{nome[:30]:<25} | {status:<6} | {tipo:<10} | {ip_addr}")

            print("="*60 + "\n")

        except Exception as e:
            print(f"Erro ao obter inventário: {e}")
    def salvar_inventario(self,ip,dados):
        os.makedirs("data",exist_ok = True)
        filename = f"data/{ip}.json"
        registro = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "dados": dados
        }
        if os.path.exists(filename):
            with open(filename,"r",encoding="utf-8") as f:
                historico = json.load(f)
        else:
            historico = []
        historico.append(registro)
        with open(filename,"w") as arquivo:
            json.dump(historico,arquivo,indent=4,ensure_ascii=False)
    def salvar_geral(self, ip, dados):
        os.makedirs("data", exist_ok=True)
        filename = "data/geral.json"

        registro = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "dados": dados
        }

        
        if os.path.exists(filename):
            with open(filename, "r", encoding="utf-8") as f:
                geral = json.load(f)
        else:
            geral = {"clientes": {}}

        
        if ip not in geral["clientes"]:
            geral["clientes"][ip] = []

        
        geral["clientes"][ip].append(registro)

        
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(geral, f, indent=4, ensure_ascii=False)
    def calcular_media(self):
        soma = 0
        offline = 0
        online = 0
        contagem_dispositivos = 0
        agora = time.time()
        

        for dados in self.clients.values():
            tempo = agora - dados.last_seen

            if tempo > 30:
                offline += 1
            else:
                online += 1
            valor_disco = getattr(dados,'ultimo_disco',None)
            if valor_disco is not None:
                soma += valor_disco
                contagem_dispositivos += 1
        print("\n" + "="*45)
        print("      📊 RESUMO GERAL DA REDE")
        print("="*45)
        print(f"Dispositivos Online:  {online}")
        print(f"Dispositivos Offline: {offline}")
        print("-" * 45)

        if contagem_dispositivos > 0:
            media = (soma / contagem_dispositivos) / (1024**3)
            print(f"Média de Disco Livre: {media:.2f} GB")
            print(f"(Baseado em {contagem_dispositivos} clientes com dados)")
        else:
            print("A rede não possui nenhum cliente")
        
    # ----------------------------------------------------------------
    # MENU COM match-case
    # ----------------------------------------------------------------
    def menu(self):
        while True:
            print("\n=== MENU SERVIDOR ===")
            print("1 - Listar clientes")
            print("2 - Solicitar Inventario de um cliente(TCP)")
            print("3 - Solicitar Inventario de todos clientes (TCP)")
            print("0 - Sair")
            op = input("> ")

            match op:
                case "1":
                    print("\n--- CLIENTES ---")
                    agora = time.time()
                    for key,info in self.clients.items():
                        atraso = agora - info.last_seen
                        if atraso < 30:
                            status = "ONLINE"
                        else:
                            status = "OFFLINE"
                        print(f"IP: {info.ip}:{info.tcp_port:<10} | {status:<10} | {atraso}s")

                case "2":
                    ip = input("Digite o IP: ")
                    port = int(input("Digite a porta TCP do cliente: "))
                    self.solicitar_inventario((ip, port))

                case "3":
                    for key in self.clients:
                        self.solicitar_inventario(key)
                case "4":
                        self.calcular_media()
                case "0":
                    exit()

                case _:
                    print("Opção inválida.")

    def start(self):
        threading.Thread(target=self.listen_broadcasts, daemon=True).start()
        self.menu()


if __name__ == "__main__":
    DiscoveryServer().start()
    