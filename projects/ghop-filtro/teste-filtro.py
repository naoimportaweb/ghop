#!/usr/bin/env python3
"""Prova o filtro de camada de aplicacao do GHop, caso a caso.

Sobe o ghop-filtro.py de verdade -- as mesmas funcoes que o servico chama --
sobre um diretorio temporario, com um destino de mentira do outro lado, e
bate nele com um ClientHello TLS DE VERDADE (gerado pelo modulo ssl, nao
montado a mao) e com pedidos HTTP:

   1. nome permitido, TLS       -> emenda: o destino recebe o ClientHello inteiro
   2. nome bloqueado, TLS       -> alerta TLS, e o destino NAO recebe nada
   3. nome bloqueado, HTTP      -> 403, e o destino NAO recebe nada
   4. nome permitido, HTTP      -> emenda, com o cabecalho intacto
   5. excecao acima do bloqueio -> a ORDEM decide (permitir vence)
   6. sufixo e por rotulo       -> 'exemplo.com' nao pega 'naoexemplo.com'
   7. sem nome legivel          -> passa, e e contada a parte
   8. politica 'bloquear'       -> ai o sem nome NAO passa
   9. bloqueio deixa rastro     -> quando, cliente, nome, porta e regra no log
  10. o que passou nao deixa    -> nem no log, nem na contagem por nome
  11. regras.json quebrado      -> segue com as regras que ja tinha
  12. destino e o proprio filtro-> recusa (seria laco)

O caso 10 e o que prova o desenho: um filtro que registrasse tambem o que
passou seria um registro nome a nome de tudo o que a LAN faz, que e o oposto
do 'so sumariza'. Os casos 2 e 3 provam que bloquear e bloquear -- o destino
nao chega a ser procurado.

O que este teste NAO cobre, porque exige root e netfilter: o
redirecionamento em si e o SO_ORIGINAL_DST. Aqui o destino original e
injetado; na maquina de verdade quem o informa e o kernel.

Uso:
  ./teste-filtro.py

Nao precisa de root, nao abre porta para fora (so 127.0.0.1) e nao fala com
maquina nenhuma. Roda a bateria inteira e sai 0 so com zero falhas.
"""

import importlib.util
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time

AQUI = os.path.dirname(os.path.abspath(__file__))


def carrega():
    """Importa o ghop-filtro.py apesar do hifen no nome."""
    caminho = os.path.join(AQUI, "ghop-filtro.py")
    spec = importlib.util.spec_from_file_location("ghop_filtro", caminho)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def cliente_hello(nome):
    """Um ClientHello TLS de verdade, pedindo aquele nome."""
    escuta = socket.socket()
    escuta.bind(("127.0.0.1", 0))
    escuta.listen(1)
    guardado = {}

    def pega():
        conexao, _ = escuta.accept()
        guardado["bytes"] = conexao.recv(16384)
        conexao.close()

    fio = threading.Thread(target=pega)
    fio.start()
    bruto = socket.create_connection(escuta.getsockname())
    try:
        ssl.create_default_context().wrap_socket(bruto, server_hostname=nome)
    except OSError:
        pass
    except ssl.SSLError:
        pass
    fio.join()
    escuta.close()
    return guardado.get("bytes", b"")


class Destino:
    """O 'la fora': guarda o que receber e devolve uma marca."""

    def __init__(self):
        self.escuta = socket.socket()
        self.escuta.bind(("127.0.0.1", 0))
        self.escuta.listen(4)
        self.recebido = b""
        self.conexoes = 0
        self.trava = threading.Lock()
        threading.Thread(target=self._laco, daemon=True).start()

    @property
    def endereco(self):
        return self.escuta.getsockname()

    def _laco(self):
        while True:
            try:
                conexao, _ = self.escuta.accept()
            except OSError:
                return
            with self.trava:
                self.conexoes += 1
            threading.Thread(target=self._atende, args=(conexao,), daemon=True).start()

    def _atende(self, conexao):
        conexao.settimeout(2)
        try:
            dados = conexao.recv(65536)
            with self.trava:
                self.recebido += dados
            conexao.sendall(b"DESTINO-OK")
        except OSError:
            pass
        finally:
            conexao.close()


def conversa(filtro, regras, contagem, destino, mandar, espera=1.5):
    """Roda um atendimento inteiro e devolve o que o cliente recebeu."""
    nosso, deles = socket.socketpair()
    fio = threading.Thread(
        target=filtro.atende, daemon=True,
        args=(deles, ("192.168.101.50", 40000), regras, contagem))
    fio.start()
    try:
        nosso.sendall(mandar)
    except (BrokenPipeError, OSError):
        # O filtro pode fechar ANTES de a gente terminar de mandar -- e o que
        # ele faz quando recusa de cara (caso 12). Cano quebrado aqui e
        # resultado, nao erro do teste.
        pass
    nosso.settimeout(espera)
    recebido = b""
    try:
        while True:
            pedaco = nosso.recv(65536)
            if not pedaco:
                break
            recebido += pedaco
            if b"DESTINO-OK" in recebido:
                break
    except (socket.timeout, TimeoutError, OSError):
        pass
    nosso.close()
    fio.join(timeout=3)
    return recebido


def main():
    filtro = carrega()
    temporario = tempfile.mkdtemp(prefix="ghop-filtro-teste-")
    arquivo_regras = os.path.join(temporario, "regras.json")
    filtro.ARQ_LOG = os.path.join(temporario, "bloqueados.log")
    filtro.ESPERA_NOME = 1.0

    destino = Destino()
    # O destino original e injetado: o kernel e quem o informa na maquina de
    # verdade, e para isso seria preciso root e uma regra de redirecionamento.
    # A PORTA e a de verdade do destino de mentira, nao 80 nem 443: quem
    # separa TLS de HTTP e o primeiro byte da conexao, e nao a porta -- se
    # este teste fixasse 443 aqui, estaria provando outra coisa.
    filtro.destino_original = lambda conexao: destino.endereco

    def escreve_regras(politica, regras):
        with open(arquivo_regras, "w", encoding="utf-8") as arquivo:
            json.dump({"politica": politica, "regras": regras}, arquivo)
        # mtime com granularidade de segundo em alguns sistemas: recarregar
        # sem mexer no tempo deixaria o objeto com as regras antigas.
        os.utime(arquivo_regras, (time.time() + 1, time.time() + 1))

    falhas = 0

    def confere(descricao, condicao, detalhe=""):
        nonlocal falhas
        if condicao:
            print(f"OK    {descricao}")
        else:
            falhas += 1
            print(f"FALHA {descricao}" + (f" -- {detalhe}" if detalhe else ""))

    escreve_regras("permitir", [
        {"tipo": "exato", "valor": "www.exemplo.com", "acao": "permitir"},
        {"tipo": "sufixo", "valor": "exemplo.com", "acao": "bloquear"},
    ])
    regras = filtro.Regras(arquivo_regras)
    contagem = filtro.Contagem(os.path.join(temporario, "estado.json"))

    # 1. nome permitido, TLS
    hello = cliente_hello("debian.org")
    antes = destino.conexoes
    recebido = conversa(filtro, regras, contagem, destino, hello)
    confere("1. nome permitido (TLS): a conexao e emendada ate o destino",
            b"DESTINO-OK" in recebido and destino.conexoes == antes + 1,
            f"recebido={recebido[:40]!r}")
    confere("1b. o destino recebe o ClientHello inteiro, sem faltar o que foi espiado",
            hello in destino.recebido, f"{len(destino.recebido)} bytes")

    # 2. nome bloqueado, TLS
    antes = destino.conexoes
    recebido = conversa(filtro, regras, contagem, destino,
                        cliente_hello("ads.exemplo.com"))
    confere("2. nome bloqueado (TLS): responde alerta de handshake",
            recebido == filtro.ALERTA_TLS, f"recebido={recebido!r}")
    confere("2b. bloqueado nao chega a procurar o destino",
            destino.conexoes == antes, f"conexoes={destino.conexoes}")

    # 3 e 4. HTTP -- mesma porta de sempre; o que muda e o que se manda.
    antes = destino.conexoes
    recebido = conversa(filtro, regras, contagem, destino,
                        b"GET / HTTP/1.1\r\nHost: ads.exemplo.com\r\n\r\n")
    confere("3. nome bloqueado (HTTP): responde 403",
            recebido.startswith(b"HTTP/1.1 403") and destino.conexoes == antes,
            f"recebido={recebido[:40]!r}")
    pedido = b"GET /pagina HTTP/1.1\r\nHost: debian.org\r\nX-Marca: 1\r\n\r\n"
    destino.recebido = b""
    recebido = conversa(filtro, regras, contagem, destino, pedido)
    confere("4. nome permitido (HTTP): emenda com o cabecalho intacto",
            b"DESTINO-OK" in recebido and pedido in destino.recebido,
            f"destino recebeu {destino.recebido[:60]!r}")

    # 5. a ordem decide
    antes = destino.conexoes
    recebido = conversa(filtro, regras, contagem, destino,
                        cliente_hello("www.exemplo.com"))
    confere("5. excecao ACIMA do bloqueio vence (a ordem e semantica)",
            b"DESTINO-OK" in recebido, f"recebido={recebido[:40]!r}")

    # 6. sufixo por rotulo
    recebido = conversa(filtro, regras, contagem, destino,
                        cliente_hello("naoexemplo.com"))
    confere("6. sufixo e por rotulo: 'exemplo.com' nao pega 'naoexemplo.com'",
            b"DESTINO-OK" in recebido, f"recebido={recebido[:40]!r}")

    # 7. sem nome legivel
    sem_nome_antes = contagem.sem_nome
    recebido = conversa(filtro, regras, contagem, destino, b"\x00\x01\x02\x03lixo")
    confere("7. sem nome legivel: passa (nao ha o que casar) e e contada a parte",
            b"DESTINO-OK" in recebido and contagem.sem_nome == sem_nome_antes + 1,
            f"sem_nome={contagem.sem_nome}")

    # 8. politica bloquear
    escreve_regras("bloquear", [{"tipo": "sufixo", "valor": "debian.org",
                                 "acao": "permitir"}])
    regras.recarrega()
    antes = destino.conexoes
    recebido = conversa(filtro, regras, contagem, destino, b"\x00\x01\x02\x03lixo")
    confere("8. politica 'bloquear': sem nome legivel NAO passa",
            recebido == filtro.ALERTA_TLS and destino.conexoes == antes,
            f"recebido={recebido!r}")
    recebido = conversa(filtro, regras, contagem, destino, cliente_hello("deb.debian.org"))
    confere("8b. politica 'bloquear': o que a regra permite continua saindo",
            b"DESTINO-OK" in recebido, f"recebido={recebido[:40]!r}")

    # 9. o bloqueio deixa rastro
    with open(filtro.ARQ_LOG, encoding="utf-8") as arquivo:
        linhas = [linha.rstrip("\n").split("\t") for linha in arquivo]
    confere("9. bloqueio deixa rastro (quando, cliente, nome, porta, regra)",
            linhas and all(len(linha) == 5 for linha in linhas)
            and any(linha[2] == "ads.exemplo.com" and linha[1] == "192.168.101.50"
                    for linha in linhas),
            f"{len(linhas)} linha(s): {linhas[:2]}")

    # 10. o que passou nao deixa rastro
    nomes_no_log = {linha[2] for linha in linhas}
    contagem.grava()
    with open(contagem.caminho, encoding="utf-8") as arquivo:
        estado = json.load(arquivo)
    confere("10. o que PASSOU nao aparece no registro de bloqueios",
            "debian.org" not in nomes_no_log and "naoexemplo.com" not in nomes_no_log,
            f"nomes no log: {sorted(nomes_no_log)}")
    confere("10b. o que PASSOU nao aparece na contagem por nome",
            "debian.org" not in estado["por_nome"]
            and estado["permitidas"] > 0,
            f"por_nome={estado['por_nome']}")

    # 11. arquivo quebrado
    quantas = len(regras.regras)
    with open(arquivo_regras, "w", encoding="utf-8") as arquivo:
        arquivo.write("{isto nao e json")
    os.utime(arquivo_regras, (time.time() + 2, time.time() + 2))
    regras.recarrega()
    confere("11. regras.json quebrado: segue com as regras que ja tinha",
            len(regras.regras) == quantas, f"{len(regras.regras)} regra(s)")

    # 12. laco
    filtro.destino_original = lambda conexao: ("127.0.0.1", filtro.PORTA)
    antes = destino.conexoes
    recebido = conversa(filtro, regras, contagem, destino, cliente_hello("debian.org"),
                        espera=0.5)
    confere("12. destino e o proprio filtro: recusa (seria laco)",
            recebido == b"" and destino.conexoes == antes, f"recebido={recebido!r}")

    print()
    print(f"{'TODOS OS CASOS PASSARAM' if not falhas else str(falhas) + ' FALHA(S)'}"
          f"  --  arquivos em {temporario}")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
