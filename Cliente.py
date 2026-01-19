import psutil
import time
import platform
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
    def interfaces(self):
        interface = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for nome, info in interface.items():
            if stats[nome].isup:
                status = "UP"
            else:
                status = "DOWN"
            print(f"Interface: {nome} [{status}]")
            for endereco in info:
                if endereco.family == 2: 
                    print(f"IP: {endereco.address}") 
                if endereco.family == -1: 
                    print(f"MAC: {endereco.address}") 