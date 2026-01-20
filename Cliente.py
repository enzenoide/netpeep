import psutil
import time
import platform
import socket
import json
import threading
import random
BROADCAST_PORT = 50000
BROADCAST_ADDR = "<broadcast>" #isso faz com que o socket entenda que deve usar a interface padrão para espalhar a mensagem de forma mais compatível com os protocolos de rede
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
        if "lo" in nome or "loopback" in nome: return "loopback"
        if "wlan" in nome or "wifi" in nome: return "wifi"

        return "ethernet"
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
    def tcp_server(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", self.tcp_port))
        sock.listen(5)

        while self.running:
            conn, addr = sock.accept()
            data = conn.recv(1024).decode()

            try:
                if data == "GET_INVENTORY":
                    
                    inventario = {
                        "SO": self.sistema_op(),             
                        "cpu": self.nucleos(),       
                        "ram": self.memoria(),
                        "disco": self.disco(), 
                        "interfaces": self.interfaces()
                    }
                    
                    
                    import json
                    response = json.dumps(inventario)
                    
                    conn.send(response.encode())
                    print(f"[Enviado] Inventário completo enviado para {addr}")
            except Exception as e:
                print(f"ERRO: {e}")
            finally:
                conn.close()
    def send_broadcast(self):
        """ Grita na rede avisando que o cliente existe """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        print(f"[UDP] Broadcast iniciado na porta {self.tcp_port}")
        while self.running:
            msg = f"DISCOVER_REQUEST;PORT={self.tcp_port}"
            sock.sendto(msg.encode(), (BROADCAST_ADDR, BROADCAST_PORT))
            time.sleep(5) # Avisa a cada 5 segundos
    def run(self):
        print(f"Agente iniciado....")
        threading.Thread(target=self.send_broadcast,daemon=True).start()
        threading.Thread(target=self.tcp_server,daemon=True).start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Encerrando cliente")
            self.running = False    
            
            
           
if __name__ == "__main__":
    MonitorarSistema().run()