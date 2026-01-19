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
        