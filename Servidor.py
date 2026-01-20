import socket
import threading
import time
import json
BROADCAST_PORT = 50000


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
        self.sock.bind(("", BROADCAST_PORT))

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

    # ----------------------------------------------------------------
    # SOLICITA MAC via TCP
    # ----------------------------------------------------------------
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

            
            sock.send(b"GET_INVENTORY") 
            
            
            response = sock.recv(8192).decode()
            sock.close()
            
            dados = json.loads(response)

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

            # IMPORTANTE: A chave correta é 'interfaces', conforme definido no seu cliente
            lista_interfaces = dados.get('interfaces', [])
            for rede in lista_interfaces:
                nome = rede.get('nome', 'N/A')
                status = rede.get('status', 'N/A')
                tipo = rede.get('tipo', 'N/A')
                # No seu cliente a chave de IP está em maiúsculo "IP"
                ip_addr = rede.get('IP') if rede.get('IP') else "Sem IP"
                
                # Alinhamos as colunas usando < (esquerda) e o número de espaços
                print(f"{nome[:30]:<25} | {status:<6} | {tipo:<10} | {ip_addr}")

            print("="*60 + "\n")

        except Exception as e:
            print(f"Erro ao obter inventário: {e}")

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
                    for key, info in self.clients.items():
                        print(f"{key} -> {info}")

                case "2":
                    ip = input("Digite o IP: ")
                    port = int(input("Digite a porta TCP do cliente: "))
                    self.solicitar_inventario((ip, port))

                case "3":
                    for key in self.clients:
                        self.solicitar_inventario(key)

                case "0":
                    exit()

                case _:
                    print("Opção inválida.")

    def start(self):
        threading.Thread(target=self.listen_broadcasts, daemon=True).start()
        self.menu()


if __name__ == "__main__":
    DiscoveryServer().start()