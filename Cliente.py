import psutil
import time
import platform
import socket
class MonitorarSistema:
    def __init__(self,intervalo=2):
        self.set_intervalo(intervalo)
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
    def run(self):
        print(f"Agente iniciado....")
        while True:
            
            pacote = {
                "OS": self.sistema_op(),
                "cores": self.nucleos(),
                "ram": self.memoria(),
                "disco": self.disco(),
                "redes": self.interfaces()
            }

            
            self.tcp_server(pacote)
            
            time.sleep(self.__intervalo)
if __name__ == "__main__":
    MonitorarSistema().run()