#!/usr/bin/env python3
"""Prova o mTLS do GHop de ponta a ponta, com os casos que devem falhar.

Sobe um servidor com o certificado de um agente e tenta conectar de quatro
maneiras. So a primeira pode dar certo:

  1. painel legitimo             -> aceita
  2. sem certificado nenhum      -> recusa (o agente exige certificado)
  3. certificado de outra CA     -> recusa (cadeia desconhecida)
  4. certificado de AGENTE       -> recusa (nao serve como cliente)

O caso 4 e o que prova o desenho: a identidade de um agente nao vale como
identidade de painel, mesmo tendo sido emitida pela mesma CA.

Uso:
  ./ca.sh criar && ./ca.sh agente <host> && ./ca.sh painel <nome>
  ./teste-mtls.py <host> <nome>

O diretorio da CA e ~/.ghop/ca, ou GHOP_CA_DIR. Uma segunda CA descartavel e
criada em um diretorio temporario para o caso 3.

A chave do painel e cifrada em disco: informe a senha em GHOP_PAINEL_SENHA,
a mesma usada em './ca.sh painel'. Sem ela o caso 1 nao consegue abrir a
chave e o teste acusa falha.
"""

import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading

PREFIXO_PAINEL = "ghop-painel-"
DIR_CA = os.environ.get("GHOP_CA_DIR", os.path.expanduser("~/.ghop/ca"))
CA_SH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ca.sh")


def nome_comum(certificado):
    for campo in (certificado or {}).get("subject", ()):
        for chave, valor in campo:
            if chave == "commonName":
                return valor
    return None


def agente(porta_publicada, visto, agente_crt, agente_key, ca_crt, conexoes):
    """O lado do agente: exige certificado e so aceita nome de painel."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexto.load_cert_chain(agente_crt, agente_key)
    contexto.load_verify_locations(ca_crt)
    contexto.verify_mode = ssl.CERT_REQUIRED

    escuta = socket.socket()
    escuta.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    escuta.bind(("127.0.0.1", 0))
    escuta.listen(5)
    porta_publicada.append(escuta.getsockname()[1])

    for _ in range(conexoes):
        bruto, _ = escuta.accept()
        try:
            with contexto.wrap_socket(bruto, server_side=True) as tls:
                nome = nome_comum(tls.getpeercert())
                if not nome or not nome.startswith(PREFIXO_PAINEL):
                    visto.append(("recusado-por-nome", nome))
                    continue
                tls.send(b"ok")
                visto.append(("aceito", nome))
        except ssl.SSLError as erro:
            visto.append(("recusado-no-tls", str(erro)[:60]))
        finally:
            bruto.close()
    escuta.close()


def painel(porta, esperado, ca_crt, cert=None, chave=None, senha=None):
    """O lado do painel: valida o agente pelo nome, nao por IP."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.check_hostname = False
    contexto.load_verify_locations(ca_crt)
    if cert:
        # A chave do painel e cifrada em disco; a do agente nao. Sem o
        # password= o ssl abriria um prompt e o teste travaria esperando.
        contexto.load_cert_chain(cert, chave, password=senha)
    with socket.create_connection(("127.0.0.1", porta), timeout=5) as bruto:
        with contexto.wrap_socket(bruto) as tls:
            nome = nome_comum(tls.getpeercert())
            if nome != esperado:
                raise ssl.SSLError(f"agente inesperado: {nome}")
            return tls.recv(16)


def main():
    if len(sys.argv) != 3:
        print(f"uso: {sys.argv[0]} <host-do-agente> <nome-do-painel>", file=sys.stderr)
        return 2
    agente_nome = "ghop-agente-" + sys.argv[1]
    painel_nome = PREFIXO_PAINEL + sys.argv[2]

    emitidos = os.path.join(DIR_CA, "emitidos")
    ca_crt = os.path.join(DIR_CA, "ca.crt")
    caminho = lambda nome, ext: os.path.join(emitidos, f"{nome}.{ext}")
    for arquivo in (ca_crt, caminho(agente_nome, "crt"), caminho(painel_nome, "crt")):
        if not os.path.exists(arquivo):
            print(f"Erro: {arquivo} nao encontrado. Emita antes com ca.sh.", file=sys.stderr)
            return 2

    senha_painel = os.environ.get("GHOP_PAINEL_SENHA")

    with tempfile.TemporaryDirectory() as rival:
        ambiente = dict(os.environ, GHOP_CA_DIR=rival,
                        GHOP_CA_SENHA="rival", GHOP_PAINEL_SENHA="rival")
        subprocess.run([CA_SH, "criar"], env=ambiente, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([CA_SH, "painel", "intruso"], env=ambiente, check=True, stdout=subprocess.DEVNULL)
        intruso = os.path.join(rival, "emitidos", "ghop-painel-intruso")

        porta_publicada, visto = [], []
        threading.Thread(
            target=agente,
            args=(porta_publicada, visto, caminho(agente_nome, "crt"),
                  caminho(agente_nome, "key"), ca_crt, 4),
            daemon=True,
        ).start()
        while not porta_publicada:
            pass
        porta = porta_publicada[0]

        casos = [
            ("painel legitimo", True,
             lambda: painel(porta, agente_nome, ca_crt,
                            caminho(painel_nome, "crt"), caminho(painel_nome, "key"),
                            senha_painel)),
            ("sem certificado nenhum", False,
             lambda: painel(porta, agente_nome, ca_crt)),
            ("certificado de outra CA", False,
             lambda: painel(porta, agente_nome, ca_crt, intruso + ".crt",
                            intruso + ".key", "rival")),
            ("certificado de AGENTE como cliente", False,
             lambda: painel(porta, agente_nome, ca_crt,
                            caminho(agente_nome, "crt"), caminho(agente_nome, "key"))),
        ]

        falhas = 0
        for descricao, deve_aceitar, tentativa in casos:
            try:
                tentativa()
                aceitou, detalhe = True, "conectou"
            except Exception as erro:
                aceitou = False
                detalhe = f"{type(erro).__name__}: {str(erro).split(']')[-1].strip()[:45]}"
            certo = aceitou == deve_aceitar
            falhas += not certo
            esperado = "aceitar" if deve_aceitar else "recusar"
            print(f"{'OK   ' if certo else 'FALHA'} {descricao:<36} esperado={esperado:<8} {detalhe}")

        print("\nvisto pelo lado do agente:")
        for registro in visto:
            print("   ", registro)
        print("\nfalhas:", falhas)
        return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
