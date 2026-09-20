#!/usr/bin/env python3
"""Filtro de camada de aplicacao do GHop (subprojeto FILTRO).

Decide se uma conexao da LAN pode sair, pelo NOME que ela pede -- o SNI do
ClientHello no TLS, o cabecalho Host no HTTP em claro. E o papel opcional
'filtro': o lojmIt funciona igual sem ele.

Por que existe, se ja ha o ghop-dns: o resolvedor so alcanca quem pergunta a
ele. Cliente da LAN que use DoH, DNS proprio, ou que ja tenha o IP em cache
sai sem passar pelo resolvedor -- e as listas de negacao nao valem nada para
ele. O nome pedido, esse, aparece na PROPRIA conexao, e e o ultimo lugar em
que ainda da para decidir sem inventar.

NAO DESCRIPTOGRAFA NADA. O SNI e o unico campo que o TLS manda em claro,
antes de qualquer chave ser combinada; o filtro le esses bytes, decide, e
dai em diante so emenda os dois lados sem olhar mais nada. Nao ha certificado
do GHop no cliente, nao ha MITM, e nao existe caminho por onde conteudo
cifrado passe a ser legivel. Quem quiser isso tera de escrever outro
programa -- este foi feito para nao conseguir.

O que fica registrado e SO o que foi bloqueado (quando, cliente, nome,
porta, regra), porque negar e acao e acao tem de deixar rastro. O que passou
nao e contado nome a nome: o coletor ja responde "quem falou com quem", e um
segundo registro nome a nome na mesma maquina seria o oposto do "so
sumariza".

Regras vem do painel, pelo agente, em regras.json -- este programa nao
decide o que bloquear, so aplica. Sem arquivo de regras nenhum, tudo passa.

Falha FECHADA: se o servico cair, a regra de redirecionamento continua no
firewall e as portas 80 e 443 da LAN param. E deliberado -- filtro que falha
aberto e filtro em que nao se pode confiar --, e o jeito de abrir e uma
ordem so: 'filtro.sh desligar' (ou o botao Parar no painel), que tira o
redirecionamento junto.

Variaveis de ambiente:
  GHOP_FILTRO_DIR        onde estao as regras (padrao: /etc/ghop/filtro)
  GHOP_FILTRO_PORTA      porta local do filtro (padrao: 7010)
  GHOP_FILTRO_ESTADO     contadores para o agente ler (padrao: /var/ghop/filtro.json)
  GHOP_FILTRO_LOG        registro dos bloqueios (padrao: /var/log/ghop/filtro-bloqueados.log)
  GHOP_FILTRO_ESPERA     segundos para o nome chegar (padrao: 4)
  GHOP_FILTRO_INTERVALO  segundos entre gravacoes do estado (padrao: 5)

Uso:
  ghop-filtro.py               atende de verdade, precisa de root
  ghop-filtro.py --testar NOME diz o que aconteceria com esse nome e sai
                               (le as regras, nao abre porta, nao precisa
                               de root -- e como se confere uma regra nova
                               sem esperar alguem tropecar nela)
"""

import errno
import json
import os
import selectors
import signal
import socket
import struct
import sys
import threading
import time

DIR_FILTRO = os.environ.get("GHOP_FILTRO_DIR", "/etc/ghop/filtro")
ARQ_REGRAS = os.path.join(DIR_FILTRO, "regras.json")
PORTA = int(os.environ.get("GHOP_FILTRO_PORTA", "7010"))
ARQ_ESTADO = os.environ.get("GHOP_FILTRO_ESTADO", "/var/ghop/filtro.json")
ARQ_LOG = os.environ.get("GHOP_FILTRO_LOG", "/var/log/ghop/filtro-bloqueados.log")
ESPERA_NOME = float(os.environ.get("GHOP_FILTRO_ESPERA", "4"))
INTERVALO_ESTADO = float(os.environ.get("GHOP_FILTRO_INTERVALO", "5"))

# O ClientHello cabe folgado nisto, e o cabecalho HTTP tambem. O limite
# existe para um cliente nao segurar memoria mandando bytes devagar para
# sempre: passou daqui sem nome legivel, trata-se como sem nome.
LIMITE_ESPIADA = 16 * 1024
PEDACO = 64 * 1024

# SO_ORIGINAL_DST: o kernel guarda o destino que o cliente PEDIU antes de o
# redirecionamento reescrever o pacote. Sem isto o filtro saberia o nome mas
# nao para onde entregar. O numero e do Linux (netfilter), nao esta no modulo
# socket, e nao muda ha vinte anos.
SO_ORIGINAL_DST = 80

# Alerta TLS 'handshake_failure' em claro, no nivel de registro: e valido
# antes de qualquer cifra e faz o navegador dizer "falha de handshake" em vez
# de "conexao encerrada do nada". Mesma ideia do REFUSED do resolvedor -- o
# cliente sabe na hora que foi recusado, em vez de ficar tentando.
ALERTA_TLS = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])

RESPOSTA_HTTP = (
    b"HTTP/1.1 403 Forbidden\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Connection: close\r\n"
    b"Content-Length: 68\r\n"
    b"\r\n"
    b"Bloqueado pelo filtro de camada de aplicacao desta rede (GHop).\r\n"
)

TIPOS_REGRA = ("sufixo", "exato", "prefixo", "contem")
ACOES_REGRA = ("bloquear", "permitir")
POLITICAS = ("permitir", "bloquear")


def agora():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def aviso(*texto):
    """Vai para o journal do servico. Nunca imprime nome que passou."""
    print(*texto, file=sys.stderr, flush=True)


# ------------------------------------------------------------------ regras

class Regras:
    """As regras em vigor, relidas quando o arquivo muda.

    Quem escreve regras.json e o AGENTE, com campos que ele mesmo validou --
    este programa nunca ve texto vindo do painel. Reler pelo mtime evita
    reiniciar o servico (e derrubar as conexoes de todo mundo) a cada regra
    nova que o operador acrescenta.
    """

    def __init__(self, caminho=ARQ_REGRAS):
        self.caminho = caminho
        self.politica = "permitir"
        self.regras = []
        self.carregado = 0.0
        self.trava = threading.Lock()
        self.recarrega()

    def recarrega(self):
        try:
            mtime = os.stat(self.caminho).st_mtime
        except OSError:
            # Sem arquivo de regras nao ha o que aplicar: tudo passa. E o
            # estado do papel recem-instalado, e e melhor do que bloquear
            # tudo por nao ter sido configurado ainda.
            with self.trava:
                if self.regras or self.carregado:
                    aviso("filtro: sem", self.caminho, "-- tudo passa")
                self.politica, self.regras, self.carregado = "permitir", [], 0.0
            return
        if mtime == self.carregado:
            return
        try:
            with open(self.caminho, encoding="utf-8") as arquivo:
                dado = json.load(arquivo)
        except (OSError, ValueError) as falha:
            # Arquivo pela metade (o agente esta gravando agora) ou quebrado:
            # segue com o que ja estava em memoria. Trocar por "tudo passa"
            # a cada erro de leitura seria abrir a rede por um soluco de I/O.
            aviso("filtro: nao consegui ler", self.caminho, f"({falha});"
                  " sigo com as regras que ja tinha")
            return
        politica = dado.get("politica")
        if politica not in POLITICAS:
            politica = "permitir"
        limpas = []
        for regra in dado.get("regras") or []:
            if not isinstance(regra, dict):
                continue
            tipo = regra.get("tipo")
            valor = (regra.get("valor") or "").strip().lower().rstrip(".")
            acao = regra.get("acao")
            if tipo in TIPOS_REGRA and acao in ACOES_REGRA and valor:
                limpas.append((tipo, valor, acao, regra.get("nota") or ""))
        with self.trava:
            self.politica, self.regras, self.carregado = politica, limpas, mtime
        aviso(f"filtro: {len(limpas)} regra(s), politica '{politica}'")

    def decide(self, nome):
        """(acao, descricao_da_regra) para um nome ja normalizado.

        Primeira regra que casa decide -- inclusive quando a acao e
        'permitir', que e como se abre excecao dentro de um bloqueio largo
        ('sufixo exemplo.com bloquear' com 'exato www.exemplo.com permitir'
        antes dela). Ordem e do painel; aqui nao se reordena nada.
        """
        with self.trava:
            politica, regras = self.politica, list(self.regras)
        if nome:
            for tipo, valor, acao, _nota in regras:
                if casa(nome, tipo, valor):
                    return acao, f"{tipo} {valor}"
        elif politica == "bloquear":
            # Politica de lista branca com conexao sem nome: nao da para
            # provar que esta na lista, entao nao passa.
            return "bloquear", "sem nome (politica bloquear)"
        else:
            # Sem nome e politica 'permitir': passa e e CONTADA a parte. E o
            # buraco conhecido deste papel -- quem nao manda SNI (IP direto,
            # ECH quando chegar, protocolo que nao seja TLS nem HTTP) nao e
            # filtrado por nome, porque nao ha nome. Esta na conta para o
            # operador ver o tamanho do buraco, nao escondido.
            return "permitir", "sem nome"
        return ("permitir" if politica == "permitir" else "bloquear"), f"politica {politica}"


def casa(nome, tipo, valor):
    if tipo == "exato":
        return nome == valor
    if tipo == "sufixo":
        # Sufixo e por ROTULO: 'exemplo.com' pega www.exemplo.com, e nao
        # pega naoexemplo.com. Casamento por texto puro bloquearia dominio
        # de outro dono pela coincidencia do fim do nome.
        return nome == valor or nome.endswith("." + valor)
    if tipo == "prefixo":
        return nome.startswith(valor)
    if tipo == "contem":
        return valor in nome
    return False


def normaliza(nome):
    """Nome de host como as regras o esperam, ou '' se nao servir."""
    if not nome:
        return ""
    nome = nome.strip().lower().rstrip(".")
    if nome.startswith("[") or ":" in nome:      # IPv6 literal
        return ""
    if len(nome) > 253 or "/" in nome or " " in nome:
        return ""
    return nome


# ------------------------------------------------------- leitura do nome

def nome_do_tls(dados):
    """SNI de um ClientHello, '' se nao houver, None se faltam bytes.

    So percorre os campos de tamanho fixo ate a extensao 0 (server_name).
    Nao guarda, nao registra e nao devolve mais nada do handshake.
    """
    if len(dados) < 5:
        return None
    if dados[0] != 0x16:                      # nao e handshake TLS
        return ""
    tamanho = struct.unpack("!H", dados[3:5])[0]
    if len(dados) < 5 + tamanho:
        return None
    corpo = dados[5:5 + tamanho]
    try:
        if not corpo or corpo[0] != 0x01:     # nao e ClientHello
            return ""
        p = 4                                 # tipo (1) + tamanho (3)
        p += 2 + 32                           # versao + random
        p += 1 + corpo[p]                     # session_id
        p += 2 + struct.unpack("!H", corpo[p:p + 2])[0]   # cipher_suites
        p += 1 + corpo[p]                     # compression_methods
        if p + 2 > len(corpo):
            return ""                         # ClientHello sem extensoes
        fim = p + 2 + struct.unpack("!H", corpo[p:p + 2])[0]
        p += 2
        while p + 4 <= min(fim, len(corpo)):
            tipo, tamanho_ext = struct.unpack("!HH", corpo[p:p + 4])
            p += 4
            if tipo == 0x0000:
                # server_name: lista(2) + tipo(1) + tamanho(2) + nome
                ext = corpo[p:p + tamanho_ext]
                if len(ext) >= 5 and ext[2] == 0x00:
                    tamanho_nome = struct.unpack("!H", ext[3:5])[0]
                    # ascii porque o SNI ja vai em A-label (xn--...): nome
                    # internacionalizado chega convertido pelo proprio
                    # cliente, e byte fora do ASCII ali e lixo, nao acento.
                    return ext[5:5 + tamanho_nome].decode("ascii", "ignore")
                return ""
            p += tamanho_ext
    except (IndexError, struct.error):
        return ""
    return ""


def nome_do_http(dados):
    """Host de um pedido HTTP, '' se nao houver, None se faltam bytes."""
    fim = dados.find(b"\r\n\r\n")
    if fim < 0:
        if len(dados) > 8192:
            return ""
        if dados and not (b"A" <= dados[:1].upper() <= b"Z"):
            return ""                         # nem parece HTTP: nao espere
        return None
    for linha in dados[:fim].split(b"\r\n")[1:]:
        chave, _, valor = linha.partition(b":")
        if chave.strip().lower() == b"host":
            hospedeiro = valor.strip().decode("ascii", "ignore")
            # Host pode trazer :porta; o nome e o que interessa.
            if hospedeiro.count(":") == 1:
                hospedeiro = hospedeiro.split(":", 1)[0]
            return hospedeiro
    return ""


def espia_nome(conexao):
    """Le o comeco da conexao ate achar o nome.

    Devolve (nome, bytes_lidos, protocolo), protocolo em 'tls', 'http' ou ''.

    Quem escolhe o analisador e o PRIMEIRO BYTE, nao a porta: 0x16 e o inicio
    de um handshake TLS e nao e caractere de metodo HTTP, entao os dois casos
    se separam sem ambiguidade. Pela porta seria mais curto e erraria em tudo
    o que nao esta onde se espera -- HTTPS numa porta alta, HTTP numa 443
    aberta por engano --, e e justamente esse trafego que interessa olhar.

    Os bytes lidos voltam junto porque fazem parte da conexao do cliente: se
    ela for permitida, tem de chegar ao destino exatamente como veio, sem
    faltar o pedaco que espiamos.
    """
    dados = b""
    limite = time.monotonic() + ESPERA_NOME
    while True:
        sobra = limite - time.monotonic()
        if sobra <= 0 or len(dados) >= LIMITE_ESPIADA:
            return "", dados, ""
        conexao.settimeout(sobra)
        try:
            pedaco = conexao.recv(PEDACO)
        except (socket.timeout, TimeoutError, OSError):
            return "", dados, ""
        if not pedaco:
            return "", dados, ""
        dados += pedaco
        protocolo = "tls" if dados[:1] == b"\x16" else "http"
        nome = nome_do_tls(dados) if protocolo == "tls" else nome_do_http(dados)
        if nome is not None:
            return normaliza(nome), dados, (protocolo if nome else "")


# ----------------------------------------------------------------- estado

class Contagem:
    """O que o agente le. Numeros, e nomes SO do que foi bloqueado."""

    def __init__(self, caminho=ARQ_ESTADO):
        self.caminho = caminho
        self.desde = agora()
        self.trava = threading.Lock()
        self.conexoes = 0
        self.permitidas = 0
        self.bloqueadas = 0
        self.sem_nome = 0
        self.por_nome = {}
        self.por_regra = {}
        self.sujo = True

    def conta(self, nome, acao, regra):
        with self.trava:
            self.conexoes += 1
            if acao == "bloquear":
                self.bloqueadas += 1
                if nome:
                    self.por_nome[nome] = self.por_nome.get(nome, 0) + 1
                self.por_regra[regra] = self.por_regra.get(regra, 0) + 1
            else:
                self.permitidas += 1
                if not nome:
                    self.sem_nome += 1
            self.sujo = True

    def grava(self):
        with self.trava:
            if not self.sujo:
                return
            # So os 200 mais bloqueados: a tela mostra o que se repete, e um
            # arquivo de estado nao e lugar de historico.
            maiores = sorted(self.por_nome.items(), key=lambda par: -par[1])[:200]
            dado = {
                "desde": self.desde,
                "atualizado": agora(),
                "conexoes": self.conexoes,
                "permitidas": self.permitidas,
                "bloqueadas": self.bloqueadas,
                "sem_nome": self.sem_nome,
                "por_nome": dict(maiores),
                "por_regra": dict(self.por_regra),
            }
            self.sujo = False
        temporario = self.caminho + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.caminho), exist_ok=True)
            with open(temporario, "w", encoding="utf-8") as arquivo:
                json.dump(dado, arquivo)
            # Troca atomica: o agente le este arquivo a qualquer momento e
            # nao pode pegar JSON pela metade.
            os.replace(temporario, self.caminho)
        except OSError as falha:
            aviso("filtro: nao consegui gravar", self.caminho, f"({falha})")


def registra_bloqueio(cliente, nome, porta, regra):
    """Uma linha por bloqueio. So bloqueio -- o que passou nao entra aqui."""
    linha = "\t".join([agora(), cliente, nome or "-", str(porta), regra])
    try:
        os.makedirs(os.path.dirname(ARQ_LOG), exist_ok=True)
        with open(ARQ_LOG, "a", encoding="utf-8") as arquivo:
            arquivo.write(linha + "\n")
    except OSError as falha:
        aviso("filtro: nao consegui registrar bloqueio", f"({falha})")


# ------------------------------------------------------------- atendimento

def destino_original(conexao):
    """Para onde o cliente queria ir, antes do redirecionamento."""
    bruto = conexao.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    porta, endereco = struct.unpack("!2xH4s8x", bruto)
    return socket.inet_ntoa(endereco), porta


def emenda(um, outro):
    """Passa bytes de um lado para o outro ate alguem fechar.

    Daqui para a frente o filtro nao olha mais nada: ja decidiu. E por isso
    que ele nao consegue ver conteudo nem querendo -- o unico codigo que
    interpreta bytes e o que leu o nome, e ele ja saiu de cena.
    """
    seletor = selectors.DefaultSelector()
    for lado in (um, outro):
        lado.setblocking(False)
        seletor.register(lado, selectors.EVENT_READ)
    par = {um: outro, outro: um}
    try:
        while True:
            prontos = seletor.select(timeout=300)
            if not prontos:
                return                        # ninguem falou em 5 min
            for chave, _evento in prontos:
                origem = chave.fileobj
                try:
                    pedaco = origem.recv(PEDACO)
                except OSError as falha:
                    if falha.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                    return
                if not pedaco:
                    return
                try:
                    par[origem].sendall(pedaco)
                except OSError:
                    return
    finally:
        seletor.close()


def atende(cliente, endereco, regras, contagem):
    origem = endereco[0]
    try:
        alvo_ip, alvo_porta = destino_original(cliente)
    except OSError as falha:
        aviso("filtro: sem destino original para", origem, f"({falha})")
        cliente.close()
        return
    # Conexao que ja chega apontando para o proprio filtro seria laco. Nao
    # acontece com o fragmento de firewall que este papel escreve (o
    # redirecionamento so pega o que ENTRA pela LAN, e trafego nascido aqui
    # nao passa por prerouting), mas um ruleset editado a mao faria.
    if alvo_porta == PORTA:
        cliente.close()
        return

    nome, inicio, protocolo = espia_nome(cliente)
    acao, regra = regras.decide(nome)
    contagem.conta(nome, acao, regra)

    if acao == "bloquear":
        registra_bloqueio(origem, nome, alvo_porta, regra)
        try:
            # A recusa vai na lingua que o cliente estava falando: 403 para
            # quem falava HTTP, alerta de handshake para quem falava TLS.
            # Quem nao falava nenhum dos dois so ve a conexao fechar -- nao
            # ha o que dizer que ele entenda, e inventar bytes ali seria
            # responder num protocolo que nao conhecemos.
            cliente.sendall(RESPOSTA_HTTP if protocolo == "http" else ALERTA_TLS)
        except OSError:
            pass
        cliente.close()
        return

    try:
        cliente.settimeout(None)
        saida = socket.create_connection((alvo_ip, alvo_porta), timeout=10)
    except OSError:
        # Destino fora do ar: o cliente ve a conexao cair, que e o que veria
        # sem o filtro no caminho.
        cliente.close()
        return
    try:
        if inicio:
            saida.sendall(inicio)
        emenda(cliente, saida)
    except OSError:
        pass
    finally:
        for lado in (cliente, saida):
            try:
                lado.close()
            except OSError:
                pass


def servidor(regras, contagem):
    escuta = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    escuta.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    escuta.bind(("0.0.0.0", PORTA))
    escuta.listen(128)
    aviso(f"filtro: escutando na {PORTA}")
    while True:
        try:
            cliente, endereco = escuta.accept()
        except OSError as falha:
            if falha.errno == errno.EINTR:
                continue
            raise
        threading.Thread(target=atende, daemon=True,
                         args=(cliente, endereco, regras, contagem)).start()


def relogio(regras, contagem):
    """Recarrega as regras e grava o estado, sem atrapalhar quem esta passando."""
    while True:
        time.sleep(INTERVALO_ESTADO)
        regras.recarrega()
        contagem.grava()


def main():
    argumentos = sys.argv[1:]
    if argumentos and argumentos[0] == "--testar":
        if len(argumentos) != 2:
            print("Uso: ghop-filtro.py --testar <nome>", file=sys.stderr)
            return 2
        regras = Regras()
        nome = normaliza(argumentos[1])
        if not nome:
            print(f"'{argumentos[1]}' nao e um nome de host que este filtro leia.")
            return 1
        acao, regra = regras.decide(nome)
        print(f"{nome}  ->  {acao}  (por: {regra})")
        return 0
    if argumentos:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    regras = Regras()
    contagem = Contagem()
    contagem.grava()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    threading.Thread(target=relogio, daemon=True, args=(regras, contagem)).start()
    try:
        servidor(regras, contagem)
    except KeyboardInterrupt:
        pass
    finally:
        contagem.grava()
    return 0


if __name__ == "__main__":
    sys.exit(main())
