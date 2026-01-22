def get_broadcast():

    try:
        # Cria um socket temporário para identificar qual interface sai para a internet
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Não precisa conectar de verdade, 8.8.8.8 é apenas um destino externo de exemplo
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        # Pega o IP (ex: 192.168.0.29) e troca o último número por 255
        prefixo = ".".join(local_ip.split(".")[:-1])
        return f"{prefixo}.255"
    except Exception:
        # Caso falhe (sem internet), volta para o padrão genérico
        return "<broadcast>"
