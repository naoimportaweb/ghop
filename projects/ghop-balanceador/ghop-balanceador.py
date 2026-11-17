#!/usr/bin/env python3
"""Escolha de saida do GHop: lista por placa e, no que sobrar, balanceamento.

Uma maquina de borda com mais de uma saida tem de decidir, para cada conexao
que a LAN abre para fora, por qual placa ela sai. Este papel decide em DOIS
ESTAGIOS, nesta ordem:

    ENVIO PARA IP FORA -> lista da placa A -> lista da placa B -> ... ->
                          balanceamento de carga

A primeira lista que casa decide, como no ghop-filtro -- e pelo mesmo motivo:
a ordem e semantica, e e assim que se prende um destino a uma placa sem ter de
descrever todo o resto. O que nao esta em lista nenhuma cai no balanceamento.

Sao dois algoritmos de balanceamento, e a escolha e do operador:

  rodizio    (padrao) proxima conexao vai para a proxima placa, respeitando o
             PESO de cada uma. Distribui melhor, e o peso e o que acomoda
             placas de velocidades diferentes -- uma USB 2.0 nao segura o que
             uma gigabit de barramento segura.
  afinidade  a placa sai do hash do IP de ORIGEM: o mesmo cliente da LAN
             sempre pela mesma placa. Distribui pior (cliente pesado nao se
             divide), mas o IP publico de um cliente nao muda enquanto a placa
             estiver de pe -- o que importa para sessao e para portal que
             prende login a endereco.

Em cima disso, duas coisas que nao sao opcao e sim condicao de funcionar:

A DECISAO E POR CONEXAO, NUNCA POR PACOTE. Balancear pacote a pacote faz o
mesmo fluxo sair por dois IPs de origem: o outro lado descarta, o TLS reseta,
e o sintoma e "a internet esta instavel" -- nao "o balanceador esta errado".
Por isso a marca escolhida e gravada na conexao (`ct mark`) e RESTAURADA antes
de qualquer decisao: fluxo em curso nunca e redecidido.

SO O QUE ENTRA PELA LAN E VAI PARA ENDERECO PUBLICO. Trafego nascido nesta
maquina nao passa por prerouting, entao a resposta do agente ao painel sai
pelo caminho normal e nao por placa sorteada -- se saisse, a resposta voltaria
por outra placa e o canal do painel morreria. Conexao de um cliente para
outro, ou para o proprio lojmIt, tambem fica de fora: rede interna nao e
"para fora". E a mesma regra do coletor e do filtro.

O que este programa NAO faz, e esta a vista de proposito:

  - **IPv6 nao e balanceado.** A decisao casa `nfproto ipv4` e devolve o resto
    ao caminho normal. Marcar pacote v6 para uma tabela de rota v4 nao e
    cobertura parcial, e defeito -- melhor nao tocar.
  - **Nao escolhe por NOME.** Rota decide por IP; o nome pedido so existe na
    conexao, e quem o le e o ghop-filtro. Lista aqui e IP ou CIDR.
  - **Nao decide nada sozinho.** A lista e o peso vem do painel, como campos;
    a unica coisa que este programa resolve sem perguntar e tirar da rotacao
    placa que esta SEM CARRIER -- e isso nao e decisao de politica, e deixar
    de mandar trafego para um cabo desligado.

Placa caida sai da rotacao E PERDE A LISTA DELA: o que estava preso a ela cai
no balanceamento, em vez de ir para uma tabela de rota sem default. Degradar e
obrigatorio; o painel ve a placa fora e o operador decide o que fazer.

Uso:
  ghop-balanceador.py --mostrar          imprime o que seria aplicado, sem aplicar
  ghop-balanceador.py --aplicar          escreve o fragmento de nft e as rotas
  ghop-balanceador.py --remover         tira as rotas e o fragmento
  ghop-balanceador.py --estado          json para o agente ler
  ghop-balanceador.py --testar <ip>     por qual placa esse destino sairia, e por que

Variaveis: GHOP_BALANCEADOR_DIR (padrao /etc/ghop/balanceador), GHOP_NFT_DIR
(padrao /etc/ghop/nft.d).
"""

import fcntl
import json
import os
import re
import subprocess
import sys
import time

DIR_BALANCEADOR = os.environ.get("GHOP_BALANCEADOR_DIR", "/etc/ghop/balanceador")
DIR_NFT = os.environ.get("GHOP_NFT_DIR", "/etc/ghop/nft.d")

ARQ_PLACAS = os.path.join(DIR_BALANCEADOR, "placas")
ARQ_REGRAS = os.path.join(DIR_BALANCEADOR, "regras.json")
ARQ_LAN = os.path.join(DIR_BALANCEADOR, "interface")
ARQ_NFT = os.path.join(DIR_NFT, "balanceador.sh")

TABELA = "ghop_balanceador"

# As tabelas de rota e as prioridades de regra sao DERIVADAS da ordem das
# placas, nao configuraveis: numero de tabela e detalhe de implementacao, e
# deixar o operador escolher so cria conflito com o que ja existe na maquina.
TABELA_BASE = 100
PRIORIDADE_BASE = 100

# A marca e desta casa. Nada mais no GHop usa `meta mark`/`ct mark` hoje; se
# um dia usar, a divisao tem de ser combinada aqui, porque a marca e um
# numero so por pacote.
MARCA_BASE = 1

# Quando uma placa cai, ela sai NA HORA -- failover imediato, a que sobrou
# leva tudo. O que a quarentena controla e a VOLTA: ela so retorna a rotacao
# depois de X minutos de pe. Sem isso, uma placa instavel (a USB desta casa
# caiu sozinha com 'r8152 status -71' depois de 3 minutos de uso) entraria e
# sairia a cada ciclo da sonda, remexendo firewall e conntrack a cada vez --
# e o operador veria a rede "funcionando aos pedaços" sem entender por que.
# Estabilidade vale mais que aproveitar a placa trinta segundos antes.
QUARENTENA_PADRAO = 5          # minutos
QUARENTENA_MAXIMA = 24 * 60
ARQ_HISTORICO = "/var/ghop/balanceador-historico.json"
# O que foi aplicado da ultima vez. Com o temporizador rodando de minuto em
# minuto, reaplicar sempre seria reescrever o ruleset 1440 vezes por dia sem
# nada ter mudado -- e cada reescrita e uma janela, por menor que seja.
ARQ_APLICADO = "/var/ghop/balanceador-aplicado.json"
# Quem chama --aplicar: o udev (cabo entrando ou saindo), o temporizador da
# sonda, o comando 'rotear' do painel e o 'ligar' do instalador. Dois ao mesmo
# tempo se atropelam -- um remove as regras de politica enquanto o outro as
# acrescenta --, e o estado que sobra e meia configuracao: regra para uma placa
# so, com a outra marcada e sem para onde ir.
ARQ_TRAVA = "/var/ghop/balanceador.trava"

ALGORITMOS = ("rodizio", "afinidade")
ALGORITMO_PADRAO = "rodizio"

# Teto do mapa de slots do nftables. O peso e proporcao, nao vazao: 7 e 3
# distribuem igual a 70 e 30, e com teto baixo o mapa gerado cabe na tela de
# quem for conferir a regra a mao.
TOTAL_SLOTS = 64
PESO_PADRAO = 1
PESO_MAXIMO = 32

# Teto de regras de lista. O mesmo motivo do ghop-filtro: isto fica no
# CAMINHO do dado. Um set de nftables e indexado e aguenta muito mais, mas
# lista gigante aqui e sinal de que o assunto era outro -- rota estatica, ou
# o resolvedor.
LIMITE_REGRAS = 500

# Nome de placa: vira nome de set do nftables e chave no json do painel.
FORMATO_NOME = re.compile(r"^[a-z][a-z0-9_]{0,15}$")
# Nome de interface: vai para dentro de regra de nft e de linha de comando de
# `ip`, entao e conferido com rigor -- e ele NUNCA vem do painel, vem do
# arquivo de placas desta maquina.
FORMATO_IF = re.compile(r"^[A-Za-z0-9._-]{1,15}$")

# 'cidr' e 'exato' casam o DESTINO; 'origem' casa quem PEDIU. Origem existe
# para prender uma maquina a uma placa -- a estacao do operador na saida
# estavel, por exemplo -- e e o unico tipo que olha para dentro da LAN.
TIPOS = ("cidr", "exato", "origem")
TIPOS_DESTINO = ("cidr", "exato")

# A mesma lista do ghop-filtro, de proposito: "ir para fora" tem de querer
# dizer a mesma coisa nos dois papeis.
PRIVADOS = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16 }"


class ErroSaida(Exception):
    """Defeito de configuracao ou de regra. Quem tem tela decide como mostrar."""


# ------------------------------------------------------------------ leitura


def le_placas(texto):
    """As placas desta maquina, na ordem. Formato: nome=X if=Y gw=Z peso=N.

    Este arquivo e da MAQUINA, nao do painel: interface e gateway sao fato
    local, e nome de interface entra em regra de nft e em linha de comando do
    `ip`. O painel so conhece o NOME da placa -- e e por isso que ele pode
    escrever lista e peso sem nunca tocar em interface.
    """
    placas = []
    vistos = set()
    for numero, linha in enumerate(texto.splitlines(), start=1):
        linha = linha.strip()
        if not linha or linha.startswith("#"):
            continue
        campos = {}
        for pedaco in linha.split():
            if "=" not in pedaco:
                raise ErroSaida(f"linha {numero}: '{pedaco}' nao e chave=valor")
            chave, valor = pedaco.split("=", 1)
            campos[chave] = valor
        nome = campos.get("nome", "")
        interface = campos.get("if", "")
        gateway = campos.get("gw", "")
        if not FORMATO_NOME.match(nome):
            raise ErroSaida(f"linha {numero}: nome de placa invalido '{nome}'")
        if nome in vistos:
            raise ErroSaida(f"linha {numero}: placa '{nome}' aparece duas vezes")
        if not FORMATO_IF.match(interface):
            raise ErroSaida(f"linha {numero}: interface invalida '{interface}'")
        # 'auto' existe para a placa que ainda nao tem link: o gateway dela
        # nao se sabe antes de o cabo entrar, e inventar um numero seria pior
        # que nao ter -- rota default para gateway errado nao da erro, da
        # trafego que sai e nao volta. Com 'auto' o gateway e lido da rota da
        # propria interface na hora de aplicar, e sem rota a placa fica fora
        # da rotacao, como placa sem carrier.
        if gateway != "auto" and not _ip_valido(gateway):
            raise ErroSaida(f"linha {numero}: gateway invalido '{gateway}' "
                            "(use um IPv4 ou 'auto')")
        try:
            peso = int(campos.get("peso", PESO_PADRAO))
        except ValueError:
            raise ErroSaida(f"linha {numero}: peso nao e numero")
        if not 1 <= peso <= PESO_MAXIMO:
            raise ErroSaida(f"linha {numero}: peso fora de 1..{PESO_MAXIMO}")
        # A sonda e o que separa "placa de pe" de "placa que PASSA trafego".
        # 'nexthop' (padrao) pinga o gateway da propria placa: e o salto
        # seguinte, na rede local dela, entao nao e pedido para fora -- e
        # pega o caso comum, o roteador do provedor morto ou desplugado.
        # Um IPv4 explicito prova a internet de verdade, e e opt-in porque
        # ai a maquina passa a mandar pacote para fora por conta propria.
        # 'nao' desliga a sonda: a placa vale pelo link e pelo gateway, que
        # era o comportamento antes desta versao.
        sonda = campos.get("sonda", "nexthop")
        if sonda not in ("nexthop", "nao") and not _ip_valido(sonda):
            raise ErroSaida(f"linha {numero}: sonda invalida '{sonda}' "
                            "(use 'nexthop', 'nao' ou um IPv4)")
        try:
            quarentena = int(campos.get("quarentena", QUARENTENA_PADRAO))
        except ValueError:
            raise ErroSaida(f"linha {numero}: quarentena nao e numero")
        if not 0 <= quarentena <= QUARENTENA_MAXIMA:
            raise ErroSaida(f"linha {numero}: quarentena fora de 0..{QUARENTENA_MAXIMA} minutos")
        vistos.add(nome)
        placas.append({
            "sonda": sonda,
            "quarentena": quarentena,
            "nome": nome,
            "interface": interface,
            "gateway": gateway,
            "peso": peso,
            "marca": MARCA_BASE + len(placas),
            "tabela": TABELA_BASE + len(placas) + 1,
            "prioridade": PRIORIDADE_BASE + len(placas),
        })
    if not placas:
        raise ErroSaida(f"{ARQ_PLACAS} nao lista nenhuma placa")
    return placas


def le_regras(texto, placas):
    """As regras do painel, validadas. Linha ruim e CONTADA e descartada.

    Nunca levanta por causa de CONTEUDO: arquivo quebrado vira "nenhuma
    regra", que e o caso de papel recem-instalado -- tudo pelo balanceamento.
    Explodir aqui deixaria a maquina sem escolher saida nenhuma por causa de
    uma virgula.
    """
    conhecidas = {placa["nome"] for placa in placas}
    algoritmo = ALGORITMO_PADRAO
    regras = []
    descartadas = 0
    pesos = {}
    try:
        dados = json.loads(texto)
        if not isinstance(dados, dict):
            raise ValueError("raiz nao e objeto")
    except (ValueError, TypeError):
        return {"algoritmo": algoritmo, "regras": [], "descartadas": 0,
                "pesos": {}, "quebrado": True}

    pedido = dados.get("algoritmo")
    if pedido in ALGORITMOS:
        algoritmo = pedido
    elif pedido is not None:
        descartadas += 1

    for item in dados.get("placas") or []:
        if not isinstance(item, dict):
            descartadas += 1
            continue
        nome = item.get("nome")
        if nome not in conhecidas:
            # Placa que o painel conhece e esta maquina nao: pode ser cadastro
            # velho, pode ser placa que saiu. Nao e erro -- e descarte.
            descartadas += 1
            continue
        try:
            peso = int(item.get("peso", PESO_PADRAO))
        except (ValueError, TypeError):
            descartadas += 1
            continue
        if 1 <= peso <= PESO_MAXIMO:
            pesos[nome] = peso
        else:
            descartadas += 1

    for item in dados.get("regras") or []:
        if len(regras) >= LIMITE_REGRAS:
            descartadas += 1
            continue
        if not isinstance(item, dict):
            descartadas += 1
            continue
        placa = item.get("placa")
        tipo = item.get("tipo", "cidr")
        valor = item.get("valor")
        if placa not in conhecidas or tipo not in TIPOS:
            descartadas += 1
            continue
        normalizado = _normaliza_destino(tipo, valor)
        if not normalizado:
            descartadas += 1
            continue
        regras.append({"placa": placa, "tipo": tipo, "valor": normalizado,
                       "nota": str(item.get("nota", ""))[:200]})

    return {"algoritmo": algoritmo, "regras": regras,
            "descartadas": descartadas, "pesos": pesos, "quebrado": False}


def _ip_valido(texto):
    """IPv4 em quatro octetos. Sem ipaddress de proposito: aceitar '10' como
    10.0.0.0, que a biblioteca faz, transformaria erro de digitacao em regra
    larga."""
    if not isinstance(texto, str):
        return False
    partes = texto.split(".")
    if len(partes) != 4:
        return False
    for parte in partes:
        if not parte.isdigit() or not 0 <= int(parte) <= 255:
            return False
        if len(parte) > 1 and parte[0] == "0":
            return False
    return True


def _normaliza_destino(tipo, valor):
    """'198.51.100.0/24' ou '198.51.100.7'. None se nao for isso.

    'origem' aceita os dois formatos: prender uma maquina so (/32 implicito)
    ou um pedaco da LAN.
    """
    if not isinstance(valor, str):
        return None
    valor = valor.strip()
    if tipo == "exato":
        return valor if _ip_valido(valor) else None
    if tipo == "origem":
        if _ip_valido(valor):
            return valor
        # cai no tratamento de CIDR logo abaixo
    if "/" not in valor:
        return None
    endereco, _, prefixo = valor.partition("/")
    if not _ip_valido(endereco) or not prefixo.isdigit():
        return None
    if not 0 <= int(prefixo) <= 32:
        return None
    return f"{endereco}/{int(prefixo)}"


# ------------------------------------------------------------------- carrier


def tem_carrier(interface, raiz="/sys/class/net"):
    """A placa esta com link? Placa USB cai e volta -- cabo, porta, driver.

    Ausente e tratado como caido: interface que nao existe mais (a USB que
    alguem tirou) nao pode continuar na rotacao.
    """
    try:
        with open(os.path.join(raiz, interface, "carrier"), encoding="ascii") as arquivo:
            return arquivo.read().strip() == "1"
    except OSError:
        return False


def gateway_de(interface):
    """O gateway da rota default DESTA interface, ou '' se nao houver.

    E o que resolve 'gw=auto': numa placa que pega endereco por DHCP o
    gateway so existe depois de o cabo entrar. Le a tabela principal, nunca as
    deste papel -- as nossas tem exatamente o default que estamos tentando
    descobrir, e perguntar a elas seria circular.
    """
    try:
        resultado = subprocess.run(
            ["ip", "-4", "route", "show", "default", "dev", interface],
            capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return ""
    for linha in resultado.stdout.splitlines():
        campos = linha.split()
        if "via" in campos:
            candidato = campos[campos.index("via") + 1]
            if _ip_valido(candidato):
                return candidato
    return ""


def resolve_gateways(placas, consulta=gateway_de):
    """Troca 'auto' pelo gateway real. Quem continuar sem gateway fica sem."""
    for placa in placas:
        if placa["gateway"] == "auto":
            placa["gateway"] = consulta(placa["interface"])
            placa["automatico"] = True
    return placas


def sonda_responde(placa, executa=None):
    """A placa esta PASSANDO trafego? Nao basta estar de pe.

    Uma placa com link e gateway pode nao levar a lugar nenhum -- roteador do
    provedor caido, link contratado fora do ar, cabo no switch errado. Sem
    esta conferencia, o balanceador manda a fatia dela para um buraco negro e
    o sintoma, para quem usa, e "a internet funciona pela metade": parte das
    conexoes abre, parte morre calada. Nada mais dificil de diagnosticar.

    O alvo sai do proprio arquivo de placas. Com 'nexthop' (padrao) e o
    gateway dela -- um salto, na rede local dela, sem pacote para fora.
    """
    alvo = placa.get("sonda", "nexthop")
    if alvo == "nao":
        return True
    if alvo == "nexthop":
        alvo = placa.get("gateway") or ""
    if not alvo:
        return False
    comando = ["ping", "-c", "1", "-W", "2", "-n", "-q",
               "-I", placa["interface"], alvo]
    if executa is not None:
        return executa(comando)
    try:
        return subprocess.run(comando, capture_output=True,
                              timeout=6).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def le_historico(caminho=None):
    """Quando cada placa caiu pela ultima vez. Arquivo ausente ou ruim: vazio."""
    try:
        with open(caminho or ARQ_HISTORICO, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
        return {nome: float(quando) for nome, quando in dados.items()
                if isinstance(nome, str)}
    except (OSError, ValueError, AttributeError):
        return {}


def grava_historico(historico, caminho=None):
    alvo = caminho or ARQ_HISTORICO
    try:
        os.makedirs(os.path.dirname(alvo), exist_ok=True)
        temporario = alvo + ".novo"
        with open(temporario, "w", encoding="utf-8") as arquivo:
            json.dump(historico, arquivo, indent=2)
            arquivo.write("\n")
        os.replace(temporario, alvo)
    except OSError:
        pass   # historico e conveniencia; perde-lo nao pode derrubar a rede


def placas_ativas(placas, carrier=tem_carrier, sonda=sonda_responde,
                  historico=None, agora=None):
    """As placas que podem receber trafego agora.

    Tres condicoes, e as tres sao sobre poder rotear, nao sobre politica:
    link de pe, gateway conhecido e a sonda respondendo. Placa com carrier e
    sem gateway nao e saida -- marcar conexao para a tabela dela seria mandar
    o pacote para uma rota default que nao existe. E placa com gateway que
    nao responde tambem nao e: a fatia dela viraria buraco negro.

    Quando SOBRA UMA, o gerador nao sorteia: vai tudo nela. E o failover que
    se espera -- se uma placa cai, a que esta de pe leva tudo. Quando nao
    sobra nenhuma, o fragmento sai vazio e a maquina volta ao caminho normal,
    que e melhor que marcar para tabela sem rota.
    """
    historico = {} if historico is None else historico
    agora = time.time() if agora is None else agora
    vivas = []
    for placa in placas:
        nome = placa["nome"]
        if not carrier(placa["interface"]):
            falha = "sem link"
        elif not placa["gateway"]:
            falha = "sem gateway"
        elif not sonda(placa):
            falha = "sonda sem resposta"
        else:
            falha = ""

        if falha:
            # Cai AGORA, e o relogio da quarentena (re)comeca. A outra placa
            # assume na mesma aplicacao -- failover nao espera nada.
            historico[nome] = agora
            placa["motivo_fora"] = falha
            placa["volta_em"] = placa["quarentena"] * 60
            continue

        caiu_em = historico.get(nome)
        if caiu_em is not None:
            falta = placa["quarentena"] * 60 - (agora - caiu_em)
            if falta > 0:
                placa["motivo_fora"] = "em quarentena"
                placa["volta_em"] = int(falta)
                continue
            historico.pop(nome, None)
        placa["motivo_fora"] = ""
        placa["volta_em"] = 0
        vivas.append(placa)
    return vivas


# ------------------------------------------------------------------ decisao
#
# O mapa de slots e o balanceamento inteiro: o nftables sorteia (ou conta) um
# numero e o mapa diz qual marca aquele numero vale. Peso vira QUANTIDADE DE
# SLOTS, que e o unico jeito de pesar sem o kernel precisar saber de peso.


def mapa_slots(placas):
    """Slot -> marca, com cada placa ocupando slots na proporcao do peso.

    O total e o menor possivel que ainda respeite a proporcao: pesos 7 e 3
    dao 10 slots, nao 64. Mapa curto e mapa que da para conferir a mao.
    """
    if not placas:
        return []
    total = sum(placa["peso"] for placa in placas)
    if total > TOTAL_SLOTS:
        # Proporcao mantida, resolucao reduzida: cada placa fica com a fatia
        # arredondada do teto, e quem arredondaria para zero fica com 1 --
        # peso baixo quer dizer "pouco", nunca "nada".
        slots = []
        for placa in placas:
            quantos = max(1, round(placa["peso"] * TOTAL_SLOTS / total))
            slots.extend([placa["marca"]] * quantos)
        return slots[:TOTAL_SLOTS]
    slots = []
    for placa in placas:
        slots.extend([placa["marca"]] * placa["peso"])
    return slots


def decide(destino, placas, regras, origem=None, slots_de=None):
    """Por qual placa um destino sairia, e por que. So para --testar.

    O kernel e que decide de verdade; isto reproduz a MESMA ordem para o
    operador poder conferir uma regra sem esperar alguem tropecar nela. O que
    cai no balanceamento nao tem resposta unica -- depende do contador do
    nftables --, e por isso a resposta diz "balanceamento" e lista as placas.
    """
    if not _ip_valido(destino):
        raise ErroSaida(f"'{destino}' nao e um IPv4")
    if _privado(destino):
        return {"placa": None, "motivo": "interno",
                "explicacao": "destino em rede privada: nao e saida para fora"}
    for numero, regra in enumerate(regras, start=1):
        alvo = origem if regra["tipo"] == "origem" else destino
        if alvo and _casa(regra, alvo):
            viva = any(placa["nome"] == regra["placa"] for placa in placas)
            if viva:
                return {"placa": regra["placa"], "motivo": "lista",
                        "regra": numero,
                        "explicacao": f"regra {numero}: {regra['valor']} "
                                      f"-> placa {regra['placa']}"}
            return {"placa": None, "motivo": "lista_caida", "regra": numero,
                    "explicacao": f"regra {numero} manda na placa "
                                  f"'{regra['placa']}', que esta fora; "
                                  f"cai no balanceamento"}
    nomes = [placa["nome"] for placa in placas]
    return {"placa": None, "motivo": "balanceamento", "placas": nomes,
            "explicacao": "nenhuma lista casa: balanceamento entre " +
                          (", ".join(nomes) if nomes else "nenhuma placa ativa")}


def _privado(destino):
    octetos = [int(parte) for parte in destino.split(".")]
    if octetos[0] in (10, 127):
        return True
    if octetos[0] == 192 and octetos[1] == 168:
        return True
    if octetos[0] == 172 and 16 <= octetos[1] <= 31:
        return True
    if octetos[0] == 169 and octetos[1] == 254:
        return True
    return False


def _casa(regra, destino):
    # 'origem' aceita os dois formatos (uma maquina ou um pedaco da LAN),
    # entao quem decide a comparacao e a FORMA do valor, nao so o tipo.
    valor = regra["valor"]
    if regra["tipo"] == "exato" or "/" not in valor:
        return valor == destino
    endereco, _, prefixo = valor.partition("/")
    bits = int(prefixo)
    if bits == 0:
        return True
    mascara = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return (_numero(destino) & mascara) == (_numero(endereco) & mascara)


def _numero(endereco):
    a, b, c, d = (int(parte) for parte in endereco.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


# ------------------------------------------------------------------ geracao


def agrupa(regras, ativas):
    """Regras consecutivas da mesma placa e do mesmo campo, em ORDEM.

    Agrupar so o que e CONSECUTIVO e o que preserva o significado: a primeira
    regra que casa decide, e juntar regras salteadas da mesma placa mudaria
    quem casa primeiro. Regra de placa que esta fora da rotacao e pulada --
    o trafego dela cai no balanceamento, que e a degradacao escolhida.
    """
    grupos = []
    for regra in regras:
        if regra["placa"] not in ativas:
            continue
        campo = "origem" if regra["tipo"] == "origem" else "destino"
        if (grupos and grupos[-1]["placa"] == regra["placa"]
                and grupos[-1]["tipo"] == campo):
            grupos[-1]["valores"].append(regra["valor"])
        else:
            grupos.append({"placa": regra["placa"], "tipo": campo,
                           "valores": [regra["valor"]]})
    return grupos


def monta_nft(lan, placas, configuracao, principal=None):
    """O fragmento de nft, como texto. Funcao PURA: nada de efeito aqui.

    Vai para /etc/ghop/nft.d/balanceador.sh, aplicado pelo papel nftables DEPOIS
    das regras base -- que e o que permite acrescentar saida sem reescrever o
    ruleset e sem que a reinstalacao do firewall apague isto.
    """
    if not FORMATO_IF.match(lan):
        raise ErroSaida(f"interface de LAN invalida '{lan}'")
    algoritmo = configuracao["algoritmo"]
    regras = configuracao["regras"]
    slots = mapa_slots(placas)

    linhas = [
        "#!/bin/bash",
        "# Gerado por projects/ghop-balanceador/ghop-balanceador.py do GHop.",
        "# Alteracoes manuais serao sobrescritas: mexa na regra, nao aqui.",
        "#",
        "# A ordem e semantica: a marca gravada na conexao e restaurada ANTES",
        "# de qualquer decisao, e dai em diante a primeira lista que casa",
        "# decide. O que sobra cai no balanceamento.",
        "",
    ]
    if not placas:
        linhas += [
            "# Nenhuma placa ativa: nao se escreve regra nenhuma, e a maquina",
            "# volta a sair pelo caminho normal. Marcar para uma tabela de rota",
            "# sem default seria trocar saida ruim por saida nenhuma.",
            "exit 0",
            "",
        ]
        return "\n".join(linhas)

    linhas.append(f"nft add table inet {TABELA}")
    # Um set por GRUPO de regras consecutivas da mesma placa e do mesmo tipo,
    # e nao um set por placa. A diferenca e semantica, nao arrumacao: com um
    # set por placa, quem decide e a ordem das PLACAS, e a tela -- que responde
    # pela ordem das REGRAS -- passaria a mentir na primeira vez que o
    # operador puser uma excecao de uma placa acima de uma faixa de outra.
    # Painel e kernel discordando em silencio e o pior defeito possivel aqui.
    grupos = agrupa(regras, ativas={placa["nome"] for placa in placas})
    for indice, grupo in enumerate(grupos, start=1):
        nome = f"g{indice}_{grupo['placa']}"
        linhas.append(f"nft add set inet {TABELA} {nome} "
                      "'{ type ipv4_addr; flags interval; }'")
        for inicio in range(0, len(grupo["valores"]), 50):
            lote = ", ".join(grupo["valores"][inicio:inicio + 50])
            linhas.append(f"nft add element inet {TABELA} {nome} '{{ {lote} }}'")

    linhas += [
        "",
        f"nft add chain inet {TABELA} prerouting "
        "'{ type filter hook prerouting priority -150; }'",
        f"nft add rule inet {TABELA} prerouting counter",
        "",
        "# IPv6 sai pelo caminho normal: marcar pacote v6 para tabela de rota",
        "# v4 nao e cobertura parcial, e defeito.",
        f"nft add rule inet {TABELA} prerouting meta nfproto != ipv4 counter return",
        "",
        "# So o que ENTRA pela LAN. Esta regra vem ANTES da restauracao da",
        "# marca, e a ordem aqui nao e estilo: e o que faz a RESPOSTA chegar.",
        "#",
        "# A resposta de uma conexao balanceada entra pela placa de saida, nao",
        "# pela LAN. Se ela passasse pela restauracao, ganharia a marca da",
        "# conexao (ct mark vale nos DOIS sentidos) e seria roteada pela tabela",
        "# daquela placa -- que so tem rota default. O pacote, cujo destino e um",
        "# cliente da LAN, voltaria para o uplink em vez de ser entregue, e o",
        "# cliente ficaria sem resposta. Marcando so o que entra pela LAN, a",
        "# resposta sai sem marca, cai na tabela principal e e entregue na LAN.",
        f"nft add rule inet {TABELA} prerouting iifname != {lan} counter return",
        "",
        "# Fluxo em curso NUNCA e redecidido: a marca da conexao volta e a",
        "# travessia termina aqui. Sem isto, o mesmo fluxo sairia por duas",
        "# placas, com dois IPs de origem, e o outro lado descartaria.",
        f"nft add rule inet {TABELA} prerouting ct mark != 0x0 "
        "meta mark set ct mark counter return",
        "",
        "# O que nasce nesta maquina nao passa por prerouting -- a resposta do",
        "# agente ao painel sai pelo caminho normal, nao por placa sorteada.",
        f"nft add rule inet {TABELA} prerouting ip daddr {PRIVADOS} counter return",
        f"nft add rule inet {TABELA} prerouting ct state != new counter return",
        "",
        "# Estagio 1: lista por placa, a primeira que casa decide.",
    ]
    marcas = {placa["nome"]: placa["marca"] for placa in placas}
    for indice, grupo in enumerate(grupos, start=1):
        # 'origem' casa quem PEDIU; os outros dois casam para ONDE vai.
        campo = "ip saddr" if grupo["tipo"] == "origem" else "ip daddr"
        linhas.append(
            f"nft add rule inet {TABELA} prerouting "
            f"{campo} @g{indice}_{grupo['placa']} "
            f"meta mark set {hex(marcas[grupo['placa']])} counter")
    if not grupos:
        linhas.append("# (nenhuma lista escrita ainda: tudo vai ao balanceamento)")

    linhas += ["", f"# Estagio 2: balanceamento ({algoritmo})."]
    if len(placas) == 1:
        unica = placas[0]
        linhas.append(
            "# Uma placa ativa so: nao se sorteia entre uma. Vai tudo nela.")
        linhas.append(
            f"nft add rule inet {TABELA} prerouting meta mark 0x0 "
            f"meta mark set {hex(unica['marca'])} counter")
    else:
        mapa = ", ".join(f"{posicao} : {hex(marca)}"
                         for posicao, marca in enumerate(slots))
        if algoritmo == "afinidade":
            sorteio = f"jhash ip saddr mod {len(slots)}"
            linhas.append(
                "# Hash do IP de ORIGEM: o mesmo cliente sempre pela mesma")
            linhas.append("# placa, enquanto ela estiver de pe.")
        else:
            sorteio = f"numgen inc mod {len(slots)}"
            linhas.append(
                "# Contador que gira: a proxima conexao vai para a proxima")
            linhas.append("# placa. O peso de cada uma e o numero de slots dela.")
        linhas.append(
            f"nft add rule inet {TABELA} prerouting meta mark 0x0 "
            f"meta mark set {sorteio} map '{{ {mapa} }}' counter")

    linhas += [
        "",
        "# Grava a escolha na conexao, para a regra de restauracao la em cima",
        "# encontra-la nos pacotes seguintes.",
        f"nft add rule inet {TABELA} prerouting meta mark != 0x0 "
        "ct state new ct mark set meta mark counter",
        "",
        "# Masquerade por placa. A regra base do papel nftables ja mascara a",
        "# WAN principal; cada placa a mais precisa da sua, senao o pacote",
        "# sai com endereco da LAN e nao volta.",
    ]
    for placa in placas:
        if principal and placa["interface"] == principal:
            linhas.append(f"# {placa['interface']}: ja mascarada pela regra base")
            continue
        linhas.append(f"nft add rule inet nat postrouting oif {placa['interface']} "
                      "counter masquerade")
    linhas.append("")
    linhas.append("exit 0")
    linhas.append("")
    return "\n".join(linhas)


def monta_rotas(placas):
    """As chamadas de `ip` que poem cada placa na tabela dela.

    Lista de listas de argumentos, nunca string de shell: nada aqui vai para
    um shell, e os valores ja passaram por FORMATO_IF e por _ip_valido.
    """
    comandos = []
    for placa in placas:
        comandos.append(["ip", "route", "replace", "default",
                         "via", placa["gateway"], "dev", placa["interface"],
                         "table", str(placa["tabela"])])
        comandos.append(["ip", "rule", "add", "fwmark", hex(placa["marca"]),
                         "lookup", str(placa["tabela"]),
                         "priority", str(placa["prioridade"])])
    return comandos


def monta_remocao(placas):
    """Desfaz o que monta_rotas fez. Repetido e inofensivo."""
    comandos = []
    for placa in placas:
        comandos.append(["ip", "rule", "del", "fwmark", hex(placa["marca"]),
                         "lookup", str(placa["tabela"]),
                         "priority", str(placa["prioridade"])])
        comandos.append(["ip", "route", "flush", "table", str(placa["tabela"])])
    return comandos


# -------------------------------------------------------------------- casca


def _carrega():
    """placas, configuracao, lan -- do disco. Levanta ErroSaida se faltar."""
    try:
        with open(ARQ_PLACAS, encoding="utf-8") as arquivo:
            placas = le_placas(arquivo.read())
    except OSError as erro:
        raise ErroSaida(f"nao consegui ler {ARQ_PLACAS}: {erro}")
    try:
        with open(ARQ_LAN, encoding="utf-8") as arquivo:
            lan = arquivo.read().strip()
    except OSError as erro:
        raise ErroSaida(f"nao consegui ler {ARQ_LAN}: {erro}")
    texto = ""
    try:
        with open(ARQ_REGRAS, encoding="utf-8") as arquivo:
            texto = arquivo.read()
    except OSError:
        # Papel recem-instalado nao tem regra: tudo pelo balanceamento.
        texto = ""
    return placas, le_regras(texto, placas), lan


def assinatura(lan, ativas, configuracao):
    """O que define o que esta no kernel. Igual = nao ha o que reaplicar."""
    return json.dumps({
        "lan": lan,
        "ativas": [(placa["nome"], placa["interface"], placa["gateway"],
                    placa["peso"]) for placa in ativas],
        "algoritmo": configuracao["algoritmo"],
        "regras": configuracao["regras"],
    }, sort_keys=True)


def trava():
    """Segura a aplicacao para que so uma aconteca por vez. None se nao der."""
    try:
        os.makedirs(os.path.dirname(ARQ_TRAVA), exist_ok=True)
        arquivo = open(ARQ_TRAVA, "w")
        fcntl.flock(arquivo, fcntl.LOCK_EX)
        return arquivo
    except OSError:
        return None


def estado_no_kernel(ativas):
    """O kernel esta MESMO como a assinatura diz? Confiar so na assinatura
    deixa a deriva permanente: ela registra o que se MANDOU aplicar, nao o
    que esta valendo. Uma regra de politica que sumiu (aplicacao atropelada,
    alguem mexendo a mao) nunca mais seria recolocada."""
    try:
        regras = subprocess.run(["ip", "rule", "show"], capture_output=True,
                                text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    for placa in ativas:
        if f"fwmark {hex(placa['marca'])}" not in regras:
            return False
        try:
            rota = subprocess.run(["ip", "route", "show", "table",
                                   str(placa["tabela"])], capture_output=True,
                                  text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return False
        if "default" not in rota:
            return False
    return True


def _habilitado():
    """O papel esta ligado? 'ligar' habilita a unidade, 'desligar' a desabilita."""
    try:
        resultado = subprocess.run(
            ["systemctl", "is-enabled", "ghop-balanceador.service"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return True   # sem systemd a decisao nao e nossa: aplica
    return resultado.stdout.strip() == "enabled"


def _executa(comandos, tolerar=False):
    for comando in comandos:
        resultado = subprocess.run(comando, capture_output=True, text=True)
        if resultado.returncode != 0 and not tolerar:
            raise ErroSaida(f"'{' '.join(comando)}' falhou: "
                            f"{resultado.stderr.strip()}")


def _rodar():
    argumentos = sys.argv[1:]
    if not argumentos:
        print(__doc__.strip())
        return 0
    acao = argumentos[0]
    placas, configuracao, lan = _carrega()
    resolve_gateways(placas)
    historico = le_historico()
    ativas = placas_ativas(placas, historico=historico)
    # Gravado SEMPRE, inclusive em --estado e --mostrar: o relogio da
    # quarentena nao pode depender de qual comando foi chamado.
    grava_historico(historico)
    principal = os.environ.get("GHOP_BALANCEADOR_PRINCIPAL") or None

    # O peso que vale e o do painel, quando ele mandou um; o do arquivo de
    # placas e o padrao de quem instalou a maquina.
    for placa in placas:
        placa["peso"] = configuracao["pesos"].get(placa["nome"], placa["peso"])

    if acao == "--mostrar":
        print(monta_nft(lan, ativas, configuracao, principal))
        for comando in monta_rotas(ativas):
            print(" ".join(comando))
        return 0

    if acao == "--aplicar":
        _trava = trava()
        # O udev chama isto a cada evento de rede. Se o operador DESLIGOU o
        # papel, reaplicar seria desfazer a decisao dele pelas costas -- foi o
        # que aconteceu quando a prova de rede derrubou o balanceador e o
        # proprio veth da prova, ao sumir, o trouxe de volta.
        if not _habilitado():
            print("ghop-balanceador: papel desligado; nada a aplicar")
            return 0
        atual = assinatura(lan, ativas, configuracao)
        anterior = ""
        try:
            with open(ARQ_APLICADO, encoding="utf-8") as arquivo:
                anterior = arquivo.read()
        except OSError:
            pass
        forcar = "--forcar" in argumentos
        if (atual == anterior and os.path.exists(ARQ_NFT) and not forcar
                and estado_no_kernel(ativas)):
            # O temporizador roda de minuto em minuto. Reescrever o ruleset
            # sem nada ter mudado seria 1440 janelas por dia a troco de nada.
            print("ghop-balanceador: sem mudanca; nada a reaplicar")
            return 0
        os.makedirs(DIR_NFT, exist_ok=True)
        with open(ARQ_NFT, "w", encoding="utf-8") as arquivo:
            arquivo.write(monta_nft(lan, ativas, configuracao, principal))
        os.chmod(ARQ_NFT, 0o755)
        # As rotas das placas caidas saem antes, para nao sobrar regra
        # apontando para tabela sem default.
        _executa(monta_remocao(placas), tolerar=True)
        _executa(monta_rotas(ativas))
        # O fragmento acabou de ser reescrito, e quem o aplica e o papel
        # nftables -- dono unico do ruleset. Sem este pedido, um evento de
        # udev (cabo entrando, por exemplo) atualizaria as ROTAS e deixaria a
        # MARCACAO velha no kernel: rota nova para marca que ninguem poe.
        # --no-block porque isto roda DENTRO do ExecStart de uma unidade que
        # declara After=ghop-nftables: esperar o job do outro lado seria
        # esperar por quem espera por nos.
        _executa([["systemctl", "--no-block", "restart",
                   "ghop-nftables.service"]], tolerar=True)
        try:
            os.makedirs(os.path.dirname(ARQ_APLICADO), exist_ok=True)
            with open(ARQ_APLICADO, "w", encoding="utf-8") as arquivo:
                arquivo.write(atual)
        except OSError:
            pass
        fora = [f"{placa['nome']} ({placa.get('motivo_fora')})"
                for placa in placas if placa not in ativas]
        print(f"ghop-balanceador: {len(ativas)} placa(s) ativa(s) de {len(placas)}; "
              f"{len(configuracao['regras'])} regra(s) de lista; "
              f"algoritmo {configuracao['algoritmo']}"
              + (f"; fora: {', '.join(fora)}" if fora else ""))
        return 0

    if acao == "--remover":
        _executa(monta_remocao(placas), tolerar=True)
        try:
            os.remove(ARQ_NFT)
        except OSError:
            pass
        print("ghop-balanceador: rotas e fragmento removidos")
        return 0

    if acao == "--estado":
        print(json.dumps({
            "algoritmo": configuracao["algoritmo"],
            "lan": lan,
            "regras": configuracao["regras"],
            "descartadas": configuracao["descartadas"],
            "regras_quebradas": configuracao["quebrado"],
            # 'slots' so quer dizer algo contra o total, e 'sorteio' diz se ha
            # sorteio: com uma placa ativa nao ha -- vai tudo nela. Numero
            # certo com rotulo errado e pior que numero nenhum.
            "sorteio": len(ativas) > 1,
            "slots_total": len(mapa_slots(ativas)),
            "placas": [{
                "nome": placa["nome"],
                "interface": placa["interface"],
                "gateway": placa["gateway"] or None,
                "gateway_automatico": placa.get("automatico", False),
                "sonda": placa.get("sonda", "nexthop"),
                "quarentena": placa.get("quarentena", QUARENTENA_PADRAO),
                "motivo_fora": placa.get("motivo_fora", ""),
                "volta_em": placa.get("volta_em", 0),
                "peso": placa["peso"],
                "ativa": placa in ativas,
                "slots": mapa_slots(ativas).count(placa["marca"]),
            } for placa in placas],
        }, ensure_ascii=False, indent=2))
        return 0

    if acao == "--testar":
        if len(argumentos) < 2:
            print("Uso: ghop-balanceador.py --testar <ip-destino> [--de <ip-origem>]",
                  file=sys.stderr)
            return 2
        # Sem a origem, regra de 'origem' nunca casaria -- e a resposta diria
        # "balanceamento" para um destino que na verdade esta preso a uma
        # placa. Resposta certa com pergunta incompleta e pior que erro.
        origem = None
        if "--de" in argumentos:
            posicao = argumentos.index("--de")
            if posicao + 1 < len(argumentos):
                origem = argumentos[posicao + 1]
        resposta = decide(argumentos[1], ativas, configuracao["regras"],
                          origem=origem)
        print(resposta["explicacao"])
        return 0

    print(f"Erro: acao desconhecida '{acao}'.", file=sys.stderr)
    print("Uso: --mostrar | --aplicar | --remover | --estado | --testar <ip>",
          file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(_rodar())
    except ErroSaida as erro:
        print(f"Erro: {erro}", file=sys.stderr)
        sys.exit(1)
