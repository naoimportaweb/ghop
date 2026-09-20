#!/usr/bin/env python3
"""Coletor de requisicoes do GHop (subprojeto REQUESTS).

Le a saida do tcpdump em tempo real e sumariza, em um banco SQLite por dia
(/var/ghop/tmp/REQUESTS_DD_MM_YYYY), o que esta sendo requisitado para fora:
o IP de destino e o dominio consultado.

Nao captura conteudo. De cada pacote sao lidos apenas:
  - o endereco e a porta de destino, em conexoes TCP novas (pacote SYN, que
    por definicao nao carrega dados), e SO quando o destino e publico: falar
    com a propria LAN nao e requisitar para fora;
  - o nome perguntado, em consultas DNS.
Nenhum payload e gravado, e o tcpdump roda sem as opcoes de despejo de dados
(-A, -X, -w).

As duas coisas sao lidas em interfaces DIFERENTES. O SYN e lido na WAN, na
saida: e la que se sabe o que de fato foi para a internet. A pergunta DNS e
lida na LAN, na ENTRADA, e o motivo e que na WAN ela nao existe inteira:
  - se o lojmIt tem resolvedor com cache, so a pergunta que nao estava em
    cache sobe pela WAN. Dominio ja resolvido nunca mais aparece la;
  - se o lojmIt cifra o DNS para cima (dnscrypt-proxy, DoH), na WAN sai
    so trafego cifrado na 443, e nenhum nome e legivel;
  - se um dia a saida for por VPN, a WAN fisica ve so o tunel.
Na LAN o cliente pergunta em claro, toda vez, antes de o lojmIt fazer
qualquer dessas coisas. Sem LAN_IF a pergunta DNS volta a ser lida na WAN,
que e o que ha.

O coletor sumariza: contadores por IP, por dominio e por cliente de DNS, sem
registro de evento individual. Ha UMA excecao, e ela e escopada: para os IPs que o operador
escolheu monitorar no inventario, grava-se evento a evento na tabela
'eventos' -- quando, origem, MAC de origem, destino, protocolo e porta.

Essa parte observa a interface da LAN, e nao a WAN, porque e o unico lugar
onde a origem ainda existe: depois do masquerade todos os clientes colapsam
num endereco so, e a informacao esta destruida, nao escondida.

Variaveis de ambiente:
  WAN_IF          interface de saida: conexoes TCP novas (padrao: enp1s0)
  LAN_IF          interface interna: perguntas DNS e IPs monitorados (sem padrao)
  GHOP_MONITORADOS   lista escrita pelo agente (padrao: /var/ghop/monitorados.json)
  GHOP_JANELA_EVENTO segundos antes de regravar o mesmo fluxo (padrao: 60)
  GHOP_DIR        diretorio dos bancos (padrao: /var/ghop/tmp)
  GHOP_LOTE       eventos acumulados antes de gravar (padrao: 200)
  GHOP_INTERVALO  segundos maximos antes de gravar (padrao: 5)

Uso:
  ghop-requests.py            captura de verdade, precisa de root
  ghop-requests.py --stdin    le linhas de tcpdump da entrada padrao (teste)
                              com LAN_IF definida, trata a entrada como se
                              viesse da LAN (exercita a contagem por cliente)
"""

import ipaddress
import json
import os
import queue
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime

WAN_IF = os.environ.get("WAN_IF", "enp1s0")
LAN_IF = os.environ.get("LAN_IF", "")
DIR_DADOS = os.environ.get("GHOP_DIR", "/var/ghop/tmp")
LIMITE_LOTE = int(os.environ.get("GHOP_LOTE", "200"))
INTERVALO = float(os.environ.get("GHOP_INTERVALO", "5"))

# Lista de IPs externos sob monitoracao, escrita pelo agente e lida aqui. Fica
# fora do banco do dia porque nao e dado coletado: e configuracao, e tem de
# sobreviver a virada de data.
ARQ_MONITORADOS = os.environ.get(
    "GHOP_MONITORADOS", "/var/ghop/monitorados.json")

# Captura so o inicio de cada conversa: SYN de TCP (conexao nova) e perguntas
# DNS. Registrar todo pacote encheria o disco sem acrescentar informacao.
#
# Sao dois filtros porque sao duas interfaces (ver o cabecalho): o SYN e
# lido na saida da WAN, a pergunta DNS na entrada da LAN. Sem LAN_IF os dois
# vao juntos para a WAN, e o coletor se comporta como antes.
FILTRO_SYN = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"
FILTRO_DNS = "udp dst port 53"

# Na LAN o pacote ainda carrega a origem verdadeira: o masquerade so acontece
# na saida pela WAN, e ali todos os clientes ja colapsaram num endereco so.
# Por isso a monitoracao de um IP externo observa a interface INTERNA -- e o
# unico lugar onde ainda existe a resposta para "qual maquina pediu isto".
# Aqui NAO se exige SYN, ao contrario da coleta da WAN, e a razao foi medida:
# quando se marca um IP para monitorar, a maquina em geral JA tem conexao
# aberta com ele. Exigindo inicio de conexao, um fluxo ativo de HTTPS nao
# gera evento nenhum -- a tela fica vazia enquanto o trafego corre, que e o
# pior jeito de falhar. Quem controla o volume e a janela abaixo.
#
# Pacote de volta nao vira evento: o destino dele e endereco privado, e
# endereco_publico() descarta. Sobra so o sentido que interessa, LAN -> fora.
FILTRO_MONITORADO = "tcp or udp"

# Uma conexao gera muitos pacotes: foram vistos 8 do mesmo fluxo dentro do
# mesmo milissegundo. Guardar todos encheria a tabela sem dizer nada de novo,
# entao o mesmo (origem, destino, protocolo, porta) so volta a ser gravado
# depois desta janela -- um fluxo continuo vira uma linha por minuto.
JANELA_REPETICAO = float(os.environ.get("GHOP_JANELA_EVENTO", "60"))

# Suficiente para cabecalhos e para a pergunta DNS, e nada alem disso.
SNAPLEN = "512"

CARIMBO = "datetime('now','localtime')"

ESQUEMA = """
PRAGMA journal_mode=WAL;

-- IPs de destino requisitados para fora, uma linha por endereco e porta.
CREATE TABLE IF NOT EXISTS ips (
    ip       TEXT    NOT NULL,
    porta    INTEGER NOT NULL,
    total    INTEGER NOT NULL DEFAULT 0,
    primeiro TEXT    NOT NULL,
    ultimo   TEXT    NOT NULL,
    PRIMARY KEY (ip, porta)
);

-- Dominios perguntados ao DNS, uma linha por nome.
CREATE TABLE IF NOT EXISTS dominios (
    dominio  TEXT    NOT NULL PRIMARY KEY,
    total    INTEGER NOT NULL DEFAULT 0,
    primeiro TEXT    NOT NULL,
    ultimo   TEXT    NOT NULL
);

-- Quem usa DNS nesta LAN, e para QUE SERVIDOR pergunta. Contador, nao
-- registro: nao ha aqui nenhuma ligacao entre cliente e nome consultado --
-- essa juncao e justamente a que a arquitetura recusa. O que se guarda e
-- "esta maquina fez N consultas a este servidor", que responde duas coisas
-- uteis: quem esta na rede, e quem esta ignorando o resolvedor do lojmIt
-- para falar com um DNS de fora.
CREATE TABLE IF NOT EXISTS clientes_dns (
    origem_ip  TEXT    NOT NULL,
    servidor   TEXT    NOT NULL,
    total      INTEGER NOT NULL,
    primeiro   TEXT    NOT NULL,
    ultimo     TEXT    NOT NULL,
    PRIMARY KEY (origem_ip, servidor)
);

-- Eventos dos IPs sob monitoracao. Aqui HA registro individual, ao contrario
-- do resto da coleta -- e a excecao e escopada: so existe para os enderecos
-- que o operador escolheu a dedo. A origem so sobrevive porque a captura e
-- feita na LAN, antes do masquerade.
CREATE TABLE IF NOT EXISTS eventos (
    quando     TEXT    NOT NULL,
    origem_ip  TEXT    NOT NULL,
    origem_mac TEXT    NOT NULL,
    destino_ip TEXT    NOT NULL,
    protocolo  TEXT    NOT NULL,
    porta      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS eventos_destino ON eventos (destino_ip, quando DESC);
CREATE INDEX IF NOT EXISTS ips_total      ON ips (total DESC);
CREATE INDEX IF NOT EXISTS dominios_total ON dominios (total DESC);
"""

SQL_IP = f"""
INSERT INTO ips (ip, porta, total, primeiro, ultimo)
VALUES (?, ?, 1, {CARIMBO}, {CARIMBO})
ON CONFLICT(ip, porta) DO UPDATE SET total = ips.total + 1, ultimo = {CARIMBO}
"""

SQL_DOMINIO = f"""
INSERT INTO dominios (dominio, total, primeiro, ultimo)
VALUES (?, 1, {CARIMBO}, {CARIMBO})
ON CONFLICT(dominio) DO UPDATE SET total = dominios.total + 1, ultimo = {CARIMBO}
"""

SQL_CLIENTE_DNS = f"""
INSERT INTO clientes_dns (origem_ip, servidor, total, primeiro, ultimo)
VALUES (?, ?, 1, {CARIMBO}, {CARIMBO})
ON CONFLICT(origem_ip, servidor) DO UPDATE SET
    total = clientes_dns.total + 1, ultimo = {CARIMBO}
"""

SQL_EVENTO = f"""
INSERT INTO eventos (quando, origem_ip, origem_mac, destino_ip, protocolo, porta)
VALUES ({CARIMBO}, ?, ?, ?, ?, ?)
"""

CARACTERES_DOMINIO = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")


def dominio_valido(nome):
    """Aceita so nomes plausiveis, para nada estranho chegar ao banco."""
    if not nome or len(nome) > 253 or "." not in nome:
        return False
    if not set(nome) <= CARACTERES_DOMINIO:
        return False
    # Consultas reversas dizem respeito a um IP que ja registramos como IP.
    return not (nome.endswith(".in-addr.arpa") or nome.endswith(".ip6.arpa"))


def endereco_publico(endereco):
    """So o que sai de verdade para a internet vale como IP requisitado.

    Destino em rede privada nao e "pedir para fora": e a maquina falando com
    a vizinhanca -- resolvedor, controlador de dominio, impressora, o proprio
    lojmIt. Isso nao entra no banco, nem para ser filtrado na leitura depois:
    o que nao e coletado nao precisa ser guardado nem explicado.

    is_global cobre de uma vez privado (RFC1918 e ULA), loopback,
    link-local, CGNAT, multicast e reservado, em IPv4 e IPv6 -- e ja valida
    o endereco de quebra.

    Nao vale para dominio: a consulta DNS vai para o resolvedor, que quase
    sempre e da LAN. Filtrar por destino ali mataria a coleta de nomes, que e
    justamente a parte que diz para onde a maquina queria ir.
    """
    try:
        return ipaddress.ip_address(endereco).is_global
    except ValueError:
        return False


def le_monitorados():
    """IPs sob monitoracao, escritos pelo agente. Lista vazia se nao houver.

    Falha de leitura nao derruba a coleta: sem lista, apenas nao ha captura
    na LAN, e o resumo da WAN continua funcionando.
    """
    try:
        with open(ARQ_MONITORADOS, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
    except (OSError, json.JSONDecodeError):
        return []
    ips = dados.get("ips")
    return [i for i in ips if isinstance(i, str)] if isinstance(ips, list) else []


def extrai_evento(linha):
    """Traduz uma linha de 'tcpdump -e' da LAN em um evento.

    Devolve (origem_ip, origem_mac, destino_ip, protocolo, porta) ou None.

    Formato esperado, com -e e -n:
      HH:MM:SS.ffffff aa:bb:.. > cc:dd:.., ethertype IPv4 (0x0800),
      length 60: 192.168.101.100.41924 > 34.149.66.165.443: Flags [S], ...

    Ancora em 'length' em vez de contar campos desde o inicio: o cabecalho
    ethernet varia (VLAN, por exemplo) e deslocaria tudo.
    """
    campos = linha.split()
    try:
        marca = campos.index("length")
    except ValueError:
        return None
    if len(campos) < marca + 5 or campos[marca + 3] != ">":
        return None

    origem_mac = campos[0 + 1] if len(campos) > 1 else ""
    origem = campos[marca + 2]
    destino = campos[marca + 4].rstrip(":")

    # O ultimo ponto separa a porta, no IPv4 e no IPv6 do tcpdump.
    endereco_origem, _, _ = origem.rpartition(".")
    endereco_destino, separador, porta = destino.rpartition(".")
    if not separador or not porta.isdigit():
        return None
    if not endereco_publico(endereco_destino):
        return None

    if "Flags" in linha:
        protocolo = "tcp"
    elif "UDP" in linha:
        protocolo = "udp"
    else:
        protocolo = "outro"
    return (endereco_origem, origem_mac, endereco_destino, protocolo, int(porta))


def extrai_cliente_dns(linha):
    """('cliente_dns', origem, servidor) de uma pergunta DNS vista na LAN.

    So faz sentido na captura da LAN: na WAN a origem ja foi mascarada e
    seria sempre o proprio lojmIt. O servidor e o DESTINO da pergunta --
    guardar isso e o que permite ver quem nao usa o resolvedor daqui.
    """
    campos = linha.split()
    for i, campo in enumerate(campos[:-1]):
        if campo == ">":
            origem = campos[i - 1] if i else ""
            destino = campos[i + 1].rstrip(":")
            break
    else:
        return None
    origem_ip, _, _ = origem.rpartition(".")
    servidor, separador, porta = destino.rpartition(".")
    if not origem_ip or not separador or porta != "53":
        return None
    return ("cliente_dns", origem_ip, servidor)


def extrai(linha):
    """Traduz uma linha do tcpdump em ('dominio', nome) ou ('ip', end, porta).

    Devolve None para qualquer linha que nao seja reconhecida com seguranca.
    """
    campos = linha.split()

    # Pergunta DNS: "... 43690+ A? exemplo.com.br. (32)"
    for i, campo in enumerate(campos[:-1]):
        if campo.endswith("?"):
            nome = campos[i + 1].rstrip(".,").lower()
            return ("dominio", nome) if dominio_valido(nome) else None

    # Conexao TCP nova: "... 192.168.100.92.51234 > 142.250.79.14.443: Flags [S]"
    for i, campo in enumerate(campos[:-1]):
        if campo == ">":
            destino = campos[i + 1].rstrip(":")
            break
    else:
        return None

    # O ultimo ponto separa a porta, tanto em IPv4 quanto em IPv6.
    endereco, separador, porta = destino.rpartition(".")
    if not separador or not porta.isdigit() or not endereco_publico(endereco):
        return None
    return ("ip", endereco, int(porta))


class Banco:
    """Mantem aberto o banco do dia corrente, trocando quando a data vira."""

    def __init__(self, diretorio):
        self.diretorio = diretorio
        self.caminho = None
        self.conexao = None

    def _caminho_de_hoje(self):
        return os.path.join(
            self.diretorio, "REQUESTS_" + datetime.now().strftime("%d_%m_%Y")
        )

    def _atual(self):
        caminho = self._caminho_de_hoje()
        if caminho != self.caminho:
            if self.conexao is not None:
                self.conexao.close()
            os.makedirs(self.diretorio, exist_ok=True)
            self.conexao = sqlite3.connect(caminho)
            self.conexao.executescript(ESQUEMA)
            self.caminho = caminho
        return self.conexao

    def grava(self, eventos):
        ips = [(e[1], e[2]) for e in eventos if e[0] == "ip"]
        dominios = [(e[1],) for e in eventos if e[0] == "dominio"]
        monitorados = [e[1:] for e in eventos if e[0] == "evento"]
        clientes = [e[1:] for e in eventos if e[0] == "cliente_dns"]
        try:
            conexao = self._atual()
            if ips:
                conexao.executemany(SQL_IP, ips)
            if dominios:
                conexao.executemany(SQL_DOMINIO, dominios)
            if monitorados:
                conexao.executemany(SQL_EVENTO, monitorados)
            if clientes:
                conexao.executemany(SQL_CLIENTE_DNS, clientes)
            conexao.commit()
        except sqlite3.Error as erro:
            # Perder um lote nao justifica derrubar a coleta.
            print(f"ghop-requests: falha ao gravar em {self.caminho}: {erro}",
                  file=sys.stderr, flush=True)

    def fecha(self):
        if self.conexao is not None:
            self.conexao.close()
            self.conexao = None


def abre_tcpdump(interface, direcao, filtro):
    """Uma captura sumarizada: so cabecalho, so um sentido, so o filtro."""
    comando = [
        "tcpdump",
        "-l",  # saida linha a linha, para nao atrasar a coleta
        "-n",  # nao resolve nomes: evita o proprio coletor gerar DNS
        "-i", interface,
        "-s", SNAPLEN,
        "-Q", direcao,
        filtro,
    ]
    return subprocess.Popen(
        comando,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )


def abre_capturas():
    """As capturas sumarizadas, por nome. -> {nome: Popen}

    'wan' e o que sai desta maquina para a internet. 'dns' e a pergunta que
    CHEGA da LAN: -Q in, porque a resposta que o lojmIt devolve tambem passa
    por ali e nao e pergunta. Sem LAN_IF nao ha 'dns': a WAN leva os dois
    filtros e o coletor fica como era.
    """
    if not LAN_IF:
        return {"wan": abre_tcpdump(WAN_IF, "out", f"({FILTRO_SYN}) or ({FILTRO_DNS})")}
    return {
        "wan": abre_tcpdump(WAN_IF, "out", FILTRO_SYN),
        "dns": abre_tcpdump(LAN_IF, "in", FILTRO_DNS),
    }


def abre_tcpdump_lan(ips):
    """Captura na LAN so o que fala com os IPs monitorados.

    O filtro nomeia os enderecos um a um em vez de pegar tudo e descartar no
    Python: pacote que nao interessa nem chega a acordar o processo, e numa
    LAN movimentada essa diferenca e o que separa observar de atrapalhar.
    """
    if not ips or not LAN_IF:
        return None
    alvos = " or ".join(f"host {ip}" for ip in ips)
    comando = [
        "tcpdump",
        "-l",  # saida linha a linha
        "-n",  # nao resolve nomes
        "-e",  # cabecalho ethernet: e dele que sai o MAC da maquina de origem
        "-i", LAN_IF,
        "-s", SNAPLEN,
        f"({alvos}) and ({FILTRO_MONITORADO})",
    ]
    return subprocess.Popen(comando, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True, bufsize=1)


def alimenta(fluxo, fila, origem="wan"):
    """Le o fluxo em uma thread para o laco principal poder gravar por tempo."""
    for linha in fluxo:
        fila.put((origem, linha))
    fila.put((origem, None))  # fim da entrada


def main():
    apenas_stdin = "--stdin" in sys.argv

    # As capturas sumarizadas. Todas alimentam a mesma fila e passam pelo
    # mesmo extrai(): a linha do tcpdump e igual, so muda a interface.
    capturas = {}
    if apenas_stdin:
        # Com LAN_IF definida, o teste entra pelo caminho da LAN: e o unico
        # em que a origem da pergunta existe, e portanto o unico que exercita
        # a contagem por cliente. Sem ela, entra como WAN, que e o caminho
        # de quem nao tem interface interna.
        fluxos = {"dns" if LAN_IF else "wan": sys.stdin}
    else:
        capturas = abre_capturas()
        fluxos = {nome: p.stdout for nome, p in capturas.items()}

    banco = Banco(DIR_DADOS)
    fila = queue.Queue()
    for nome, fluxo in fluxos.items():
        threading.Thread(target=alimenta, args=(fluxo, fila, nome), daemon=True).start()

    encerrando = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: encerrando.set())
    signal.signal(signal.SIGINT, lambda *_: encerrando.set())

    # Captura da LAN: existe so enquanto houver IP monitorado, e e refeita
    # quando a lista muda. Nao ha reinicio de servico no meio: o agente grava
    # o arquivo, e o coletor percebe pelo mtime.
    processo_lan = None
    monitorados = []
    assinatura_lista = None
    ultima_verificacao = 0.0
    # (origem, destino, protocolo, porta) -> instante da ultima gravacao.
    vistos = {}

    def religa_lan():
        nonlocal processo_lan, monitorados
        if processo_lan is not None:
            processo_lan.terminate()
            processo_lan = None
        monitorados = le_monitorados()
        if not monitorados:
            return
        processo_lan = abre_tcpdump_lan(monitorados)
        if processo_lan is not None:
            threading.Thread(target=alimenta,
                             args=(processo_lan.stdout, fila, "lan"),
                             daemon=True).start()
            print(f"ghop-requests: monitorando {len(monitorados)} IP(s) em {LAN_IF}",
                  file=sys.stderr, flush=True)

    lote = []
    ultima_gravacao = time.monotonic()
    fim_da_entrada = False
    captura_caida = None

    while not encerrando.is_set() and not fim_da_entrada:
        agora = time.monotonic()
        if agora - ultima_verificacao >= INTERVALO:
            ultima_verificacao = agora
            try:
                marca = os.stat(ARQ_MONITORADOS).st_mtime
            except OSError:
                marca = None
            if marca != assinatura_lista:
                assinatura_lista = marca
                religa_lan()

        try:
            origem, linha = fila.get(timeout=INTERVALO)
            if linha is None:
                # Uma captura sumarizada que acaba encerra tudo, para o
                # systemd reiniciar inteiro: sem ela o resumo fica pela
                # metade e ninguem percebe. A da LAN monitorada e diferente:
                # vai e volta conforme a lista muda, e isso e normal.
                if origem in fluxos:
                    fim_da_entrada = True
                    captura_caida = origem
            elif origem in fluxos:
                evento = extrai(linha)
                if evento is not None:
                    lote.append(evento)
                    # A mesma linha rende duas contagens quando e pergunta
                    # DNS vista na LAN: o nome pedido e quem pediu.
                    if origem == "dns" and evento[0] == "dominio":
                        cliente = extrai_cliente_dns(linha)
                        if cliente is not None:
                            lote.append(cliente)
            else:
                achado = extrai_evento(linha)
                if achado is not None:
                    origem_ip, origem_mac, destino_ip, protocolo, porta = achado
                    chave = (origem_ip, destino_ip, protocolo, porta)
                    quando = time.monotonic()
                    if quando - vistos.get(chave, -JANELA_REPETICAO) >= JANELA_REPETICAO:
                        vistos[chave] = quando
                        lote.append(("evento", origem_ip, origem_mac,
                                     destino_ip, protocolo, porta))
        except queue.Empty:
            pass

        vencido = time.monotonic() - ultima_gravacao >= INTERVALO
        if lote and (len(lote) >= LIMITE_LOTE or vencido or fim_da_entrada):
            banco.grava(lote)
            lote.clear()
            ultima_gravacao = time.monotonic()
            # A memoria anti-repeticao nao pode crescer para sempre: o que ja
            # saiu da janela nao serve mais para nada.
            corte = time.monotonic() - JANELA_REPETICAO
            vistos = {k: v for k, v in vistos.items() if v >= corte}

    if lote:
        banco.grava(lote)
    banco.fecha()

    if processo_lan is not None:
        processo_lan.terminate()
    for processo in capturas.values():
        processo.terminate()
    if capturas and not encerrando.is_set():
        # O tcpdump caiu sozinho: sai com erro para o systemd reiniciar.
        interface = LAN_IF if captura_caida == "dns" else WAN_IF
        print(f"ghop-requests: tcpdump encerrou em {interface}",
              file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
