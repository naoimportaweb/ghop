#!/usr/bin/env python3
"""Prova o agente do GHop de ponta a ponta, com os casos que devem falhar.

Sobe um ghop-agente.py de verdade, com certificado de verdade, sobre um banco
de teste, e bate nele de varias maneiras:

  1. painel legitimo pede 'resumo'      -> aceita e devolve os contadores
  2. sem certificado nenhum             -> recusa (o agente exige certificado)
  3. certificado de AGENTE como cliente -> recusa (nao serve como cliente)
  4. comando desconhecido               -> erro, e o agente continua de pe
  5. comando de execucao generica       -> erro (o conjunto e fechado)
  6. dia com ../ no nome                -> erro (nao le fora do GHOP_DIR)
  7. JSON invalido                      -> erro, e o agente continua de pe
  8. 'interfaces'                       -> devolve a lista; recusa argumento
  9. 'rotas'                            -> devolve rotas e regras de politica
 10. 'vizinhos'                         -> devolve a tabela ARP/NDP; recusa argumento
 10b. 'conexoes'                        -> o mapa acumulado, ou recusa explicando
 11. 'trafego'                          -> devolve a janela amostrada em memoria
 12. 'papeis'                           -> devolve a lista (vazia aqui) sem falhar
 13. leitura de papel ausente           -> recusa explicando, e nao explode
 14. acao em papel fora da tabela       -> recusa (lojmIt e agente nao entram)
 15. acao inventada                     -> recusa (a lista de acoes e fechada)

Os casos 3 e 5 sao os que provam o desenho: identidade de agente nao vale como
identidade de painel, e nao existe comando que execute coisa arbitraria.
Os casos 4, 6 e 7 provam que pedido ruim nao derruba nem vaza o agente.

Uso:
  ./ca.sh criar && ./ca.sh agente <host> && ./ca.sh painel <nome>
  GHOP_PAINEL_SENHA=... ./teste-agente.py <host> <nome>

O diretorio da CA e ~/.ghop/ca, ou GHOP_CA_DIR. A chave do painel e cifrada:
informe a senha em GHOP_PAINEL_SENHA.
"""

import json
import os
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
from datetime import datetime

DIR_CA = os.environ.get("GHOP_CA_DIR", os.path.expanduser("~/.ghop/ca"))
AGENTE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghop-agente.py")
DIA = datetime.now().strftime("%d_%m_%Y")

ESQUEMA = """
CREATE TABLE ips (
    ip TEXT NOT NULL, porta INTEGER NOT NULL, total INTEGER NOT NULL,
    primeiro TEXT NOT NULL, ultimo TEXT NOT NULL, PRIMARY KEY (ip, porta));
CREATE TABLE dominios (
    dominio TEXT NOT NULL PRIMARY KEY, total INTEGER NOT NULL,
    primeiro TEXT NOT NULL, ultimo TEXT NOT NULL);
INSERT INTO ips VALUES ('142.250.79.14', 443, 12, '2026-09-03 10:00:00', '2026-09-03 11:00:00');
INSERT INTO ips VALUES ('1.1.1.1', 853, 3, '2026-09-03 10:00:00', '2026-09-03 10:30:00');
INSERT INTO dominios VALUES ('exemplo.com.br', 7, '2026-09-03 10:00:00', '2026-09-03 11:00:00');
"""


def nome_comum(certificado):
    for campo in (certificado or {}).get("subject", ()):
        for chave, valor in campo:
            if chave == "commonName":
                return valor
    return None


def porta_livre():
    with socket.socket() as temporario:
        temporario.bind(("127.0.0.1", 0))
        return temporario.getsockname()[1]


def conecta(porta, agente_nome, ca_crt, cert=None, chave=None, senha=None):
    """Abre uma conexao de painel e devolve o socket TLS ja autenticado."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexto.check_hostname = False
    contexto.load_verify_locations(ca_crt)
    if cert:
        contexto.load_cert_chain(cert, chave, password=senha)
    bruto = socket.create_connection(("127.0.0.1", porta), timeout=10)
    tls = contexto.wrap_socket(bruto)
    visto = nome_comum(tls.getpeercert())
    if visto != agente_nome:
        tls.close()
        raise ssl.SSLError(f"agente inesperado: {visto}")
    return tls


def pergunta(tls, bruto_da_linha):
    """Manda uma linha crua e devolve a resposta decodificada."""
    tls.sendall(bruto_da_linha)
    fluxo = tls.makefile("rb")
    linha = fluxo.readline(64 * 1024)
    if not linha:
        raise EOFError("agente fechou sem responder")
    return json.loads(linha.decode("utf-8"))


def pede(tls, comando, argumentos=None, identificador="1"):
    corpo = {"id": identificador, "comando": comando, "argumentos": argumentos or {}}
    return pergunta(tls, json.dumps(corpo).encode("utf-8") + b"\n")


def espera_subir(porta, processo, segundos=10):
    limite = time.monotonic() + segundos
    while time.monotonic() < limite:
        if processo.poll() is not None:
            return False
        try:
            with socket.create_connection(("127.0.0.1", porta), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    if len(sys.argv) != 3:
        print(f"uso: {sys.argv[0]} <host-do-agente> <nome-do-painel>", file=sys.stderr)
        return 2
    agente_nome = "ghop-agente-" + sys.argv[1]
    painel_nome = "ghop-painel-" + sys.argv[2]
    senha_painel = os.environ.get("GHOP_PAINEL_SENHA")

    emitidos = os.path.join(DIR_CA, "emitidos")
    ca_crt = os.path.join(DIR_CA, "ca.crt")
    caminho = lambda nome, ext: os.path.join(emitidos, f"{nome}.{ext}")
    for arquivo in (ca_crt, caminho(agente_nome, "crt"), caminho(painel_nome, "crt")):
        if not os.path.exists(arquivo):
            print(f"Erro: {arquivo} nao encontrado. Emita antes com ca.sh.", file=sys.stderr)
            return 2

    with tempfile.TemporaryDirectory() as dados:
        banco = sqlite3.connect(os.path.join(dados, "REQUESTS_" + DIA))
        banco.executescript(ESQUEMA)
        banco.commit()
        banco.close()

        porta = porta_livre()
        ambiente = dict(
            os.environ,
            GHOP_PORTA=str(porta),
            GHOP_ESCUTA="127.0.0.1",
            GHOP_CERT=caminho(agente_nome, "crt"),
            GHOP_CHAVE=caminho(agente_nome, "key"),
            GHOP_CA=ca_crt,
            GHOP_DIR=dados,
        )
        processo = subprocess.Popen(
            [sys.executable, AGENTE], env=ambiente,
            stderr=subprocess.PIPE, text=True,
        )
        try:
            if not espera_subir(porta, processo):
                print("Erro: o agente nao subiu.", file=sys.stderr)
                print(processo.stderr.read() if processo.stderr else "", file=sys.stderr)
                return 2

            legitimo = dict(cert=caminho(painel_nome, "crt"),
                            chave=caminho(painel_nome, "key"), senha=senha_painel)
            falhas = 0

            def confere(descricao, condicao, detalhe=""):
                nonlocal falhas
                falhas += not condicao
                print(f"{'OK   ' if condicao else 'FALHA'} {descricao:<38} {detalhe}")

            # 1. painel legitimo
            try:
                with conecta(porta, agente_nome, ca_crt, **legitimo) as tls:
                    resposta = pede(tls, "resumo")
                dados_ok = (
                    resposta.get("ok") is True
                    and resposta.get("id") == "1"
                    and resposta["dados"]["ips"][0]["ip"] == "142.250.79.14"
                    and resposta["dados"]["ips"][0]["total"] == 12
                    and resposta["dados"]["dominios"][0]["dominio"] == "exemplo.com.br"
                )
                confere("painel legitimo pede resumo", dados_ok,
                        f"{len(resposta['dados']['ips'])} ips, "
                        f"{len(resposta['dados']['dominios'])} dominios")
            except Exception as erro:
                confere("painel legitimo pede resumo", False, f"{type(erro).__name__}: {erro}")

            # 2. sem certificado
            try:
                with conecta(porta, agente_nome, ca_crt) as tls:
                    pede(tls, "resumo")
                confere("sem certificado nenhum", False, "conectou -- nao devia")
            except Exception as erro:
                confere("sem certificado nenhum", True, type(erro).__name__)

            # 3. certificado de agente como cliente
            try:
                with conecta(porta, agente_nome, ca_crt,
                             caminho(agente_nome, "crt"), caminho(agente_nome, "key")) as tls:
                    pede(tls, "resumo")
                confere("certificado de AGENTE como cliente", False, "conectou -- nao devia")
            except Exception as erro:
                confere("certificado de AGENTE como cliente", True, type(erro).__name__)

            # 4, 5, 6, 7: pedidos ruins de um painel legitimo. O agente tem de
            # recusar cada um e continuar vivo para o proximo.
            with conecta(porta, agente_nome, ca_crt, **legitimo) as tls:
                resposta = pede(tls, "inexistente")
                confere("comando desconhecido", resposta.get("ok") is False,
                        resposta.get("erro", ""))

                resposta = pede(tls, "exec", {"cmd": "id"})
                confere("comando de execucao generica", resposta.get("ok") is False,
                        resposta.get("erro", ""))

                resposta = pede(tls, "resumo", {"dia": "../../../etc/passwd"})
                confere("dia com ../ no nome", resposta.get("ok") is False,
                        resposta.get("erro", ""))

                resposta = pergunta(tls, b"nao sou json\n")
                confere("JSON invalido", resposta.get("ok") is False,
                        resposta.get("erro", ""))

                resposta = pede(tls, "resumo", identificador="depois")
                confere("agente segue de pe depois dos erros",
                        resposta.get("ok") is True and resposta.get("id") == "depois")

                # 8. interfaces: leitura do sistema, sem argumento. Tem de
                # trazer pelo menos a loopback, que toda maquina tem.
                resposta = pede(tls, "interfaces")
                nomes = [i.get("nome") for i in (resposta.get("dados") or {}).get("interfaces", [])]
                confere("interfaces devolve a lista", resposta.get("ok") is True and "lo" in nomes,
                        ", ".join(nomes))
                resposta = pede(tls, "interfaces", {"nome": "eth0"})
                confere("interfaces recusa argumento", resposta.get("ok") is False,
                        resposta.get("erro", ""))

                # 9. rotas: mesma natureza. Regras de politica ha sempre
                # (main/default vem de fabrica), rotas so se houver rede.
                resposta = pede(tls, "rotas")
                regras = (resposta.get("dados") or {}).get("regras", [])
                confere("rotas devolve regras de politica",
                        resposta.get("ok") is True and len(regras) >= 1,
                        f"{len((resposta.get('dados') or {}).get('rotas', []))} rotas, {len(regras)} regras")

                # 10. vizinhos: a tabela ARP/NDP que o kernel ja tinha.
                # Pode vir VAZIA e estar certa -- maquina sem trafego na rede
                # local nao tem vizinho --, entao o que se prova e a forma e
                # que 'total' bate com o que veio. O par com argumento e o
                # mesmo do 'interfaces': leitura pura nao aceita "mostre-me
                # outra coisa".
                resposta = pede(tls, "vizinhos")
                forma = resposta.get("dados") or {}
                lista = forma.get("vizinhos")
                confere("vizinhos devolve a tabela",
                        resposta.get("ok") is True and isinstance(lista, list)
                        and forma.get("total") == len(lista)
                        and all({"ip", "mac", "interface", "estado"} <= set(v)
                                for v in lista),
                        f"{forma.get('total')} vizinho(s)")
                resposta = pede(tls, "vizinhos", {"interface": "eth0"})
                confere("vizinhos recusa argumento", resposta.get("ok") is False,
                        resposta.get("erro", ""))

                # 10b. conexoes: dois desfechos sao CERTOS, e o teste
                # aceita os dois. Em maquina que roteia, o mapa vem (pode
                # estar vazio: o amostrador acabou de subir). Em maquina sem
                # conntrack legivel -- que e o caso comum de quem roda este
                # teste --, a recusa explicando e o comportamento correto, e
                # nao uma falha.
                resposta = pede(tls, "conexoes")
                forma = resposta.get("dados") or {}
                confere("conexoes: mapa ou recusa explicando",
                        (resposta.get("ok") is True
                         and isinstance(forma.get("pares"), list)
                         and forma.get("intervalo"))
                        or (resposta.get("ok") is False
                            and "conexoes" in resposta.get("erro", "")),
                        f"{forma.get('total', resposta.get('erro', ''))}")
                resposta = pede(tls, "conexoes", {"origem": "10.0.0.1"})
                confere("conexoes recusa argumento", resposta.get("ok") is False,
                        resposta.get("erro", ""))

                # 11. trafego: o amostrador nasce com o agente; num teste
                # curto pode nao haver dois pontos ainda, mas a forma tem de
                # vir inteira.
                resposta = pede(tls, "trafego")
                forma = resposta.get("dados") or {}
                confere("trafego devolve a janela",
                        resposta.get("ok") is True and "interfaces" in forma
                        and forma.get("intervalo") and forma.get("janela"),
                        f"{len(forma.get('interfaces', {}))} interface(s) com pontos")

                # 12. papeis: o que se prova aqui e que o comando responde
                # uma LISTA, nao que ela venha vazia -- a maquina de teste
                # pode ter isc-dhcp-server da distribuicao, e o agente o
                # reporta de proposito (origem 'sistema').
                resposta = pede(tls, "papeis")
                papeis = (resposta.get("dados") or {}).get("papeis")
                confere("papeis responde a lista", resposta.get("ok") is True
                        and isinstance(papeis, list),
                        f"{len(papeis or [])} papel(is) aqui")

                # 13. leitura de papel ausente recusa com texto, nao explode.
                resposta = pede(tls, "wifi")
                confere("papel ausente recusa com explicacao",
                        resposta.get("ok") is False and "wifi" in resposta.get("erro", ""),
                        resposta.get("erro", ""))

                # 14 e 15: o comando de ACAO. Nao se pede acao de verdade
                # num teste -- o que se prova e que o conjunto e fechado
                # tambem aqui: papel de fora da tabela e acao inventada sao
                # recusados antes de qualquer coisa acontecer.
                resposta = pede(tls, "papel", {"papel": "lojmIt", "acao": "parar"})
                confere("acao em papel fora da tabela", resposta.get("ok") is False,
                        resposta.get("erro", ""))

                resposta = pede(tls, "papel", {"papel": "dns", "acao": "rm -rf /"})
                confere("acao inventada e recusada", resposta.get("ok") is False,
                        resposta.get("erro", ""))

            print("\nfalhas:", falhas)
            return 1 if falhas else 0
        finally:
            processo.terminate()
            try:
                processo.wait(timeout=5)
            except subprocess.TimeoutExpired:
                processo.kill()


if __name__ == "__main__":
    sys.exit(main())
