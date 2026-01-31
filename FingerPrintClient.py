import os
from cryptography.hazmat.primitives import hashes
class FingerPrintClient:
    def gerar_fingerprint_e_salvar_config_client(caminho_public_key="Client/keys/public.pem",pasta_cliente="Client",arquivo_config="hash.txt"):
            #Lê a chave pública do cliente em bytes
            with open(caminho_public_key, "rb") as f:
                public_pem = f.read()

            # 2. Gera o fingerprint SHA-256 da chave pública
            digest = hashes.Hash(hashes.SHA256())
            digest.update(public_pem)
            fingerprint = digest.finalize().hex()

            # 3. Garante que a pasta Client exista
            os.makedirs(pasta_cliente, exist_ok=True)

            # 4. Caminho final do arquivo
            caminho_arquivo = os.path.join(pasta_cliente, arquivo_config)

            # 5. Salva o fingerprint
            with open(caminho_arquivo, "w") as f:
                f.write(fingerprint)

            print("[OK] Fingerprint do cliente salvo em:", caminho_arquivo)
            return fingerprint
FingerPrintClient.gerar_fingerprint_e_salvar_config_client()