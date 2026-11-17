#!/usr/bin/env python3
"""Agente do GHop: escuta comandos do painel sobre mTLS e responde.

O agente e burro de proposito. Ele executa um conjunto FECHADO de comandos,
enumerados em COMANDOS, e nada fora dele: nao ha comando generico de execucao,
nao ha eval, nao ha shell. No dia em que houver, o GHop deixa de ser
observador e vira backdoor com TLS.

Sete comandos MUDAM a maquina: 'monitorar', que grava a lista de IPs a
observar de perto; 'papel', que instala, inicia, para ou desinstala um papel
do GHop -- e so os que estao em GERENCIAVEIS, rodando o script que a tabela
diz; 'firewall', que cria e apaga tabela, cadeia e regra no nftables a
partir de CAMPOS (nunca texto de regra); 'lista', que mexe nas listas do
resolvedor (cria com texto colado, acrescenta ou tira uma regra, liga,
desliga, apaga); 'filtrar', que recebe as regras do filtro de nome inteiras,
estado e nao delta; 'rotear', que recebe as listas e os pesos do balanceador de
saida, tambem estado inteiro; e 'limpar', o unico que APAGA dado ja coletado -- uma
especie e um dia por vez, sem tocar em 'eventos'. Os demais leem:

  resumo      contadores que o ghop-requests juntou
  eventos     registro individual dos IPs sob monitoracao
  interfaces  interfaces de rede como estao agora
  rotas       tabela de rotas e regras de politica
  vizinhos    quem esta ao alcance de camada 2 (tabela ARP/NDP), sem varrer
  conexoes    mapa de quem falou com quem, acumulado da tabela do kernel
  trafego     bytes por segundo por interface nos ultimos minutos
  sistema     a maquina em si: processador, memoria, disco, versoes
  listas      as listas do resolvedor e, se pedido, as regras de uma delas
  papeis      quais PAPEIS DO GHOP estao instalados nesta maquina
  dhcp        concessoes do servidor DHCP, se o papel existir aqui
  dns         estado do resolvedor e o que ele negou, idem
  wifi        radio, rede e quem esta associado, idem
  nftables    o firewall em vigor, com os contadores de cada regra
  filtro      as regras do filtro de nome e o que elas negaram, idem
  balanceador placas de saida, pesos, algoritmo e as listas em vigor, idem
  acao        como esta a ultima acao pedida por 'papel'

As leituras de papel (dhcp, dns, wifi, nftables, filtro) so respondem onde
aquele papel esta instalado: o painel pergunta 'papeis' primeiro e so entao
oferece a tela de cada um.

Nenhum comando de escrita DECIDE coisa alguma. 'monitorar' recebe a lista
pronta e grava; 'papel' recebe qual papel e qual das quatro acoes, e roda o
script que a tabela GERENCIAVEIS diz. Quem escolhe e sempre o painel.

A classificacao -- o que e suspeito, o que e esperado -- NAO acontece aqui:
as listas branca e negra vivem no painel, e e la que o historico inteiro e
reclassificado quando uma regra muda. O agente entrega numero cru.

O registro individual de 'eventos' e a excecao deliberada a regra de que o
coletor so sumariza, e e ESCOPADA: existe apenas para os IPs que o operador
escolheu a dedo no inventario. Todo o resto da coleta segue sendo contador.

Identidade
  Os dois lados se provam. O agente so aceita cliente cujo certificado tenha
  sido emitido pela CA do GHop E cujo CN comece com 'ghop-painel-'. Um
  certificado de agente, mesmo emitido pela mesma CA, nao passa como cliente:
  o extendedKeyUsage separa serverAuth de clientAuth.

Protocolo
  Uma mensagem JSON por linha, UTF-8, nos dois sentidos.

    pedido    {"id": "...", "comando": "resumo", "argumentos": {...}}
    resposta  {"id": "...", "ok": true,  "dados": {...}}
              {"id": "...", "ok": false, "erro": "..."}

  Cada mensagem e autocontida: traz o proprio id e tudo de que precisa, sem
  depender do que veio antes. Hoje quem conecta e o painel, porque comando
  sincrono e melhor de usar. Mas a direcao e revogavel -- atravessar NAT
  aninhado exige encaminhar porta em cada nivel, e sair sempre e permitido
  enquanto entrar nunca e. Quando a direcao inverter, troca-se o transporte
  sem reescrever isto.

Variaveis de ambiente
  GHOP_PORTA   porta de escuta (padrao: 7000, dentro da faixa 7000-7100)
  GHOP_ESCUTA  endereco de escuta (padrao: 0.0.0.0; o nftables e que limita)
  GHOP_CERT    certificado do agente (padrao: /etc/ghop/certs/agente.crt)
  GHOP_CHAVE   chave do agente      (padrao: /etc/ghop/certs/agente.key)
  GHOP_CA      certificado da CA    (padrao: /etc/ghop/certs/ca.crt)
  GHOP_DIR     bancos do coletor    (padrao: /var/ghop/tmp)
  GHOP_MONITORADOS  lista de IPs observados (padrao: /var/ghop/monitorados.json)
"""

import collections
import ipaddress
import json
import os
import re
import subprocess
import signal
import socket
import sqlite3
import ssl
import sys
import threading
import time
import urllib.parse
from datetime import datetime, timedelta

PORTA = int(os.environ.get("GHOP_PORTA", "7000"))
ESCUTA = os.environ.get("GHOP_ESCUTA", "0.0.0.0")
ARQ_CERT = os.environ.get("GHOP_CERT", "/etc/ghop/certs/agente.crt")
ARQ_CHAVE = os.environ.get("GHOP_CHAVE", "/etc/ghop/certs/agente.key")
ARQ_CA = os.environ.get("GHOP_CA", "/etc/ghop/certs/ca.crt")
DIR_DADOS = os.environ.get("GHOP_DIR", "/var/ghop/tmp")
# Lista dos IPs sob monitoracao. Escrita aqui, lida pelo coletor. Fora do
# banco do dia porque e configuracao, nao dado coletado -- tem de sobreviver
# a virada de data.
ARQ_MONITORADOS = os.environ.get("GHOP_MONITORADOS", "/var/ghop/monitorados.json")

PREFIXO_PAINEL = "ghop-painel-"

# O nome do banco vira caminho em disco. So o formato exato do coletor passa:
# sem isso, um 'dia' com ../ leria arquivo fora de GHOP_DIR.
FORMATO_DIA = re.compile(r"^\d{2}_\d{2}_\d{4}$")

# Tetos. Uma linha de pedido nao tem motivo para ser grande, e um resumo
# gigante viraria memoria de graca para quem pedir.
LIMITE_LINHA = 64 * 1024
LIMITE_RESUMO = 1000
PADRAO_RESUMO = 100
# Teto da janela do resumo, em minutos: um dia. Alem disso nao ha o que
# responder -- o banco e por dia, e pedir 'as ultimas 30 horas' leria so o
# que couber no arquivo de hoje e mentiria sobre o resto.
JANELA_RESUMO = 24 * 60

# Teto de IPs monitorados. Cada um vira um termo no filtro do tcpdump, e
# filtro grande demais custa CPU em cada pacote da LAN.
LIMITE_MONITORADOS = 200

# Conexao parada nao ocupa o agente para sempre.
TEMPO_LIMITE = 30


def registra(*mensagem):
    """Log para o journal. Nunca imprime conteudo de dado coletado."""
    print("ghop-agente:", *mensagem, file=sys.stderr, flush=True)


class Recusado(Exception):
    """Pedido malformado ou fora do combinado. Vira resposta de erro."""


def nome_comum(certificado):
    for campo in (certificado or {}).get("subject", ()):
        for chave, valor in campo:
            if chave == "commonName":
                return valor
    return None


def abre_banco(dia):
    """Abre o banco do dia SO PARA LEITURA.

    O agente le o que o coletor escreve. Abrir em modo ro garante que um erro
    aqui nao corrompa a coleta -- sao dois processos no mesmo arquivo.
    """
    caminho = os.path.join(DIR_DADOS, "REQUESTS_" + dia)
    if not os.path.exists(caminho):
        raise Recusado(f"nao ha banco para o dia {dia}")
    uri = "file:" + urllib.parse.quote(caminho) + "?mode=ro"
    try:
        return sqlite3.connect(uri, uri=True, timeout=5)
    except sqlite3.Error as erro:
        raise Recusado(f"nao consegui abrir o banco de {dia}: {erro}")


def abre_banco_escrita(dia):
    """Abre o banco do dia PARA ESCREVER. So o 'limpar' usa isto.

    O irmao 'abre_banco' abre em modo ro e e o certo para todo o resto: sao
    dois processos no mesmo arquivo, e leitura que nao pode escrever nunca
    corrompe a coleta. Aqui a escrita e o proposito, entao a garantia vem de
    outro lugar -- o comando apaga tabela inteira, por dia, e nao aceita
    nome de tabela vindo do pedido.

    O coletor incrementa no proprio banco (ON CONFLICT ... total + 1), nao a
    partir de um total guardado em memoria: depois de apagar, o proximo
    contato recomeca em 1, sem total fantasma reaparecendo.
    """
    caminho = os.path.join(DIR_DADOS, "REQUESTS_" + dia)
    if not os.path.exists(caminho):
        raise Recusado(f"nao ha banco para o dia {dia}")
    try:
        return sqlite3.connect(caminho, timeout=10)
    except sqlite3.Error as erro:
        raise Recusado(f"nao consegui abrir o banco de {dia}: {erro}")


# As tabelas que 'limpar' pode esvaziar, e o nome que o painel usa. Tabela
# NUNCA vem do pedido: o valor recebido e chave deste dicionario, e o SQL sai
# daqui. 'eventos' fica de fora de proposito -- e o registro evento a evento
# dos IPs que o operador mandou monitorar, outra decisao e outra tela.
# 'clientes_dns' tambem: alimenta a aba Clientes do DNS, nao a analise de
# saida.
TABELAS_LIMPAVEIS = {"dominios": "dominios", "ips": "ips"}


def comando_limpar(argumentos):
    """Esvazia os contadores de dominios OU de IPs de um dia. ESCREVE.

    O unico comando que APAGA dado coletado, e por isso o mais estreito de
    todos: uma especie por vez, um dia por vez, tabela escolhida de uma
    tabela fixa aqui dentro. Nao apaga 'eventos' nem 'clientes_dns'.

    Nao ha desfazer. Quem confirma e o operador, na tela; aqui so se registra
    quanto sumiu, para o log dizer o que a tela mandou fazer.
    """
    especie = argumentos.get("especie")
    dia = argumentos.get("dia") or datetime.now().strftime("%d_%m_%Y")
    if sobra := set(argumentos) - {"especie", "dia"}:
        raise Recusado(f"argumento desconhecido: {sorted(sobra)}")
    if especie not in TABELAS_LIMPAVEIS:
        raise Recusado(
            f"especie {especie!r} nao pode ser limpa. "
            f"Ha: {', '.join(sorted(TABELAS_LIMPAVEIS))}")
    if not isinstance(dia, str) or not FORMATO_DIA.match(dia):
        raise Recusado("dia deve estar no formato DD_MM_YYYY")

    tabela = TABELAS_LIMPAVEIS[especie]
    conexao = abre_banco_escrita(dia)
    try:
        antes = conexao.execute(f"SELECT COUNT(*) FROM {tabela}").fetchone()[0]
        conexao.execute(f"DELETE FROM {tabela}")
        conexao.commit()
    except sqlite3.Error as erro:
        raise Recusado(f"falha ao limpar {especie} de {dia}: {erro}")
    finally:
        conexao.close()

    registra(f"limpar {especie} do dia {dia}: {antes} linha(s) apagada(s)")
    return {"dia": dia, "especie": especie, "apagadas": antes}


def comando_resumo(argumentos):
    """Contadores por IP e por dominio do dia pedido. Numero cru, sem juizo.

    Com 'minutos', responde so as linhas cujo ULTIMO contato caiu na janela
    -- "quem apareceu nos ultimos N minutos". Nao e "quanto falou em N
    minutos": as tabelas 'ips' e 'dominios' sao contadores ACUMULADOS por
    chave, sem evento a evento, entao o 'total' continua sendo o do dia.
    Contagem por janela exigiria o que so a tabela 'eventos' guarda, e essa
    existe apenas para os IPs que o operador mandou monitorar.

    O corte e feito AQUI, antes do LIMIT, e nao no painel de proposito: a
    ordem e por total decrescente, entao filtrar depois do limite esconderia
    justamente o host que apareceu agora e falou pouco -- que e o que se
    procura numa janela de dez minutos.
    """
    dia = argumentos.get("dia") or datetime.now().strftime("%d_%m_%Y")
    if not isinstance(dia, str) or not FORMATO_DIA.match(dia):
        raise Recusado("dia deve estar no formato DD_MM_YYYY")

    limite = argumentos.get("limite", PADRAO_RESUMO)
    if not isinstance(limite, int) or isinstance(limite, bool):
        raise Recusado("limite deve ser inteiro")
    if not 1 <= limite <= LIMITE_RESUMO:
        raise Recusado(f"limite deve estar entre 1 e {LIMITE_RESUMO}")

    minutos = argumentos.get("minutos")
    desde = None
    if minutos is not None:
        if not isinstance(minutos, int) or isinstance(minutos, bool):
            raise Recusado("minutos deve ser inteiro")
        if not 1 <= minutos <= JANELA_RESUMO:
            raise Recusado(f"minutos deve estar entre 1 e {JANELA_RESUMO}")
        desde = (datetime.now() - timedelta(minutes=minutos)
                 ).strftime("%Y-%m-%d %H:%M:%S")

    # O filtro entra como parametro, nunca interpolado: 'desde' nasce aqui
    # de um inteiro ja validado, mas a regra da casa e a linha do pedido
    # nunca encostar no SQL.
    onde = " WHERE ultimo >= ?" if desde else ""
    faixa = (desde,) if desde else ()

    conexao = abre_banco(dia)
    try:
        ips = conexao.execute(
            "SELECT ip, porta, total, primeiro, ultimo FROM ips" + onde +
            " ORDER BY total DESC, ip LIMIT ?", faixa + (limite,)
        ).fetchall()
        dominios = conexao.execute(
            "SELECT dominio, total, primeiro, ultimo FROM dominios" + onde +
            " ORDER BY total DESC, dominio LIMIT ?", faixa + (limite,)
        ).fetchall()
    except sqlite3.Error as erro:
        raise Recusado(f"falha ao ler o banco de {dia}: {erro}")
    finally:
        conexao.close()

    return {
        "dia": dia,
        "limite": limite,
        # Ecoados para o painel saber que a janela FOI aplicada. Agente
        # antigo ignora 'minutos' e devolve o dia inteiro; sem este eco o
        # painel rotularia de "ultimos 10 min" uma tela do dia todo.
        "minutos": minutos,
        "desde": desde,
        "ips": [
            {"ip": i, "porta": p, "total": t, "primeiro": pr, "ultimo": u}
            for i, p, t, pr, u in ips
        ],
        "dominios": [
            {"dominio": d, "total": t, "primeiro": pr, "ultimo": u}
            for d, t, pr, u in dominios
        ],
    }


def comando_monitorar(argumentos):
    """Define a lista de IPs externos que o coletor deve observar de perto.

    PRIMEIRO COMANDO QUE ESCREVE. Ate aqui o agente so lia. Mesmo assim ele
    continua burro: recebe a lista pronta e a grava, nao decide o que
    monitorar nem consulta nada a respeito. Quem escolhe e o painel, dentro
    do inventario.

    O que ele pode causar de pior e o coletor observar IP demais -- custa
    disco, nao seguranca. Nao abre porta, nao roda programa, nao toca em
    firewall. Por isso cabe no conjunto fechado sem transformar o GHop em
    outra coisa.

    Substitui a lista inteira em vez de acrescentar: sincronizar estado e
    idempotente, e um painel que perdeu uma mensagem nao deixa IP orfao
    sendo observado para sempre.
    """
    ips = argumentos.get("ips")
    if not isinstance(ips, list):
        raise Recusado("ips deve ser uma lista")
    if len(ips) > LIMITE_MONITORADOS:
        raise Recusado(f"no maximo {LIMITE_MONITORADOS} IPs monitorados")

    aceitos = []
    for bruto in ips:
        if not isinstance(bruto, str):
            raise Recusado("cada ip deve ser texto")
        try:
            endereco = ipaddress.ip_address(bruto.strip())
        except ValueError:
            raise Recusado(f"IP invalido: {bruto!r}")
        # Monitorar endereco privado nao faz sentido aqui: o coletor observa
        # quem da LAN fala com um destino de FORA. E deixar passar convidaria
        # a apontar a captura para a propria rede interna inteira.
        if not endereco.is_global:
            raise Recusado(f"{endereco} nao e endereco publico")
        texto = str(endereco)
        if texto not in aceitos:
            aceitos.append(texto)

    try:
        os.makedirs(os.path.dirname(ARQ_MONITORADOS), exist_ok=True)
        temporario = ARQ_MONITORADOS + ".novo"
        with open(temporario, "w", encoding="utf-8") as arquivo:
            json.dump({"ips": aceitos}, arquivo, indent=2)
            arquivo.write("\n")
        os.replace(temporario, ARQ_MONITORADOS)
    except OSError as erro:
        raise Recusado(f"nao consegui gravar a lista: {erro}")

    registra(f"monitorados: {len(aceitos)} IP(s)")
    return {"ips": aceitos, "total": len(aceitos)}


def comando_eventos(argumentos):
    """Eventos gravados para os IPs monitorados: quem falou com quem, quando.

    Diferente de 'resumo', que so conta. Aqui ha registro individual, e isso
    e deliberado e ESCOPADO: so existe para os IPs que o operador escolheu a
    dedo. O resto da coleta continua sendo so contador.
    """
    dia = argumentos.get("dia") or datetime.now().strftime("%d_%m_%Y")
    if not isinstance(dia, str) or not FORMATO_DIA.match(dia):
        raise Recusado("dia deve estar no formato DD_MM_YYYY")

    limite = argumentos.get("limite", PADRAO_RESUMO)
    if not isinstance(limite, int) or isinstance(limite, bool):
        raise Recusado("limite deve ser inteiro")
    if not 1 <= limite <= LIMITE_RESUMO:
        raise Recusado(f"limite deve estar entre 1 e {LIMITE_RESUMO}")

    ip = argumentos.get("ip")
    if ip is not None and not isinstance(ip, str):
        raise Recusado("ip deve ser texto")

    conexao = abre_banco(dia)
    try:
        if ip:
            linhas = conexao.execute(
                "SELECT quando, origem_ip, origem_mac, destino_ip, protocolo,"
                " porta FROM eventos WHERE destino_ip = ?"
                " ORDER BY quando DESC LIMIT ?", (ip, limite)).fetchall()
        else:
            linhas = conexao.execute(
                "SELECT quando, origem_ip, origem_mac, destino_ip, protocolo,"
                " porta FROM eventos ORDER BY quando DESC LIMIT ?",
                (limite,)).fetchall()
    except sqlite3.Error as erro:
        # Tabela pode nao existir se nada foi monitorado neste dia.
        raise Recusado(f"nao ha eventos para {dia}: {erro}")
    finally:
        conexao.close()

    return {
        "dia": dia,
        "ip": ip,
        "limite": limite,
        "eventos": [
            {"quando": q, "origem_ip": oi, "origem_mac": om,
             "destino_ip": di, "protocolo": p, "porta": po}
            for q, oi, om, di, p, po in linhas
        ],
    }


IW = "/usr/sbin/iw"


def _executa_leitura(comando, tempo=10):
    """Roda um programa do sistema SO PARA LER, com argumentos fixos.

    Nao e um comando generico: a lista de argumentos e escrita aqui, no
    codigo, e nada do painel entra nela. E o mesmo espirito do conjunto
    fechado -- o painel pede 'interfaces', nunca 'rode isto'.
    """
    try:
        return subprocess.run(comando, capture_output=True, text=True,
                              timeout=tempo, check=True).stdout
    except (OSError, subprocess.SubprocessError) as erro:
        raise Recusado(f"nao consegui ler {comando[0]}: {erro}")


def _sem_fio(nome):
    """O que o iw diz de uma interface sem fio, se o iw existir. Pode ser {}."""
    if not os.path.exists(IW):
        return {}
    dados = {}
    try:
        for linha in _executa_leitura([IW, "dev", nome, "info"]).splitlines():
            campos = linha.split()
            if len(campos) >= 2 and campos[0] in ("type", "ssid"):
                dados[campos[0]] = " ".join(campos[1:])
            elif len(campos) >= 2 and campos[0] == "channel":
                dados["canal"] = campos[1]
        if dados.get("type") == "AP":
            saida = _executa_leitura([IW, "dev", nome, "station", "dump"])
            dados["clientes"] = sum(1 for l in saida.splitlines() if l.startswith("Station"))
    except Recusado:
        pass
    return dados


def comando_interfaces(argumentos):
    """As interfaces de rede desta maquina, como estao agora. Leitura pura.

    Le o que o 'ip' e o /sys ja mostram a qualquer usuario da maquina: nome,
    tipo, estado, MAC, enderecos, bridge, contadores. Nao ha argumento: nao
    ha o que escolher, e argumento aqui seria porta para 'mostre-me outra
    coisa'. O painel e quem junta isso com o que os outros nos dizem.
    """
    if argumentos:
        raise Recusado("interfaces nao aceita argumentos")

    try:
        bruto = json.loads(_executa_leitura(["ip", "-j", "-s", "addr", "show"]))
    except ValueError as erro:
        raise Recusado(f"resposta do ip ilegivel: {erro}")

    interfaces = []
    for item in bruto:
        nome = item.get("ifname")
        if not nome:
            continue
        sistema = os.path.join("/sys/class/net", nome)
        if item.get("link_type") == "loopback":
            tipo = "loopback"
        elif os.path.isdir(os.path.join(sistema, "bridge")):
            tipo = "bridge"
        elif os.path.isdir(os.path.join(sistema, "wireless")):
            tipo = "sem fio"
        elif item.get("link_type") == "none":
            tipo = "tunel"
        else:
            tipo = "ethernet"

        enderecos = []
        for endereco in item.get("addr_info", []):
            # IPv6 de enlace (fe80::) nao diz nada sobre a rede; fica de fora.
            if endereco.get("family") == "inet6" and endereco.get("scope") != "global":
                continue
            enderecos.append(f"{endereco.get('local')}/{endereco.get('prefixlen')}")

        membros = []
        if tipo == "bridge":
            try:
                membros = sorted(os.listdir(os.path.join(sistema, "brif")))
            except OSError:
                pass

        estatisticas = item.get("stats64") or {}
        registro = {
            "nome": nome,
            "tipo": tipo,
            "estado": (item.get("operstate") or "").lower(),
            "mac": item.get("address", ""),
            "mtu": item.get("mtu"),
            "enderecos": enderecos,
            "bridge": item.get("master", ""),
            "membros": membros,
            "rx_bytes": (estatisticas.get("rx") or {}).get("bytes"),
            "tx_bytes": (estatisticas.get("tx") or {}).get("bytes"),
        }
        if tipo == "sem fio":
            registro["sem_fio"] = _sem_fio(nome)
        interfaces.append(registro)

    rota = {}
    try:
        padrao = json.loads(_executa_leitura(["ip", "-j", "route", "show", "default"]))
        if padrao:
            rota = {"via": padrao[0].get("gateway", ""), "por": padrao[0].get("dev", "")}
    except (Recusado, ValueError):
        pass

    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "interfaces": interfaces,
        "rota_padrao": rota,
    }


def comando_rotas(argumentos):
    """A tabela de rotas e as regras de politica desta maquina, agora.

    Todas as tabelas menos a 'local', que so repete os enderecos das
    interfaces. As regras ('ip rule') entram porque e nelas que um dia vai
    aparecer o split por VPN -- e ai a tabela 'main' sozinha mentiria.
    Leitura pura, sem argumento, argumentos fixos no codigo.
    """
    if argumentos:
        raise Recusado("rotas nao aceita argumentos")

    try:
        bruto = json.loads(_executa_leitura(["ip", "-j", "route", "show", "table", "all"]))
        regras_brutas = json.loads(_executa_leitura(["ip", "-j", "rule", "show"]))
    except ValueError as erro:
        raise Recusado(f"resposta do ip ilegivel: {erro}")

    rotas = []
    for item in bruto:
        tabela = item.get("table", "main")
        if tabela == "local":
            continue
        rotas.append({
            "destino": item.get("dst", ""),
            "via": item.get("gateway", ""),
            "por": item.get("dev", ""),
            "origem": item.get("prefsrc", ""),
            "protocolo": item.get("protocol", ""),
            "escopo": item.get("scope", ""),
            "metrica": item.get("metric"),
            "tabela": tabela,
            "tipo": item.get("type", "unicast"),
        })

    regras = []
    for item in regras_brutas:
        regras.append({
            "prioridade": item.get("priority"),
            "de": item.get("src", "all"),
            "para": item.get("dst", ""),
            "marca": item.get("fwmark", ""),
            "entrada": item.get("iif", ""),
            "tabela": str(item.get("table", "")),
        })

    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "rotas": rotas,
        "regras": regras,
    }


# A tabela de vizinhos e truncada como as concessoes do DHCP: uma LAN grande
# (ou um /16 mal desenhado) enche isto de entradas FAILED, e a linha do
# protocolo tem limite. 'total' continua dizendo quantos havia.
LIMITE_VIZINHOS = 500


def comando_vizinhos(argumentos):
    """Quem esta ao alcance de camada 2 desta maquina, agora.

    E a tabela ARP/NDP que o kernel ja mantem para conseguir falar com a
    rede local: NAO ha varredura, nao ha um pacote a mais na rede, so a
    leitura do que o trafego que ja existia preencheu. Por isso o alcance e
    exatamente a vizinhanca -- a LAN e o roteador de cima --, e nunca a
    internet: quem esta atras de um salto nao tem entrada aqui.

    Existe porque as outras respostas a "quem esta nesta rede" tem buraco, e
    o buraco e sempre o mesmo lugar: 'dhcp' so ve quem pediu endereco ao
    isc-dhcp-server e 'wifi' so quem esta associado ao radio. Maquina de
    endereco fixo, aparelho de outra LAN em bridge, ou rede cujo DHCP nao e
    nosso -- que e o caso normal de uma maquina que se observa sem ter
    instalado -- so aparecem aqui. Cruzar as tres e tarefa do painel, e e la
    que a diferenca entre elas vira informacao ("tem concessao e nao fala",
    "fala e nunca pediu endereco").

    Estado FAILED e INCOMPLETE ficam de proposito: sao o rastro de um IP que
    alguem daqui procurou e que nao respondeu -- some da rede, nao da
    tabela. Quem desenha decide se mostra.

    O MAC vai inteiro. Ele nao e segredo (viaja em claro em cada quadro da
    LAN, e 'dhcp' e 'wifi' ja o devolvem), e e a unica chave que faz o mesmo
    aparelho ser UM so nas tres fontes -- IP nao serve, porque muda e porque
    o mesmo IP privado existe em varios lugares com NAT aninhado.

    Leitura pura, sem argumento, argumentos fixos no codigo.
    """
    if argumentos:
        raise Recusado("vizinhos nao aceita argumentos")

    # Sem -4 nem -6: o 'ip' devolve as duas familias de uma vez, e IPv6 de
    # enlace e justamente onde aparece aparelho que nunca pediu IPv4.
    try:
        bruto = json.loads(_executa_leitura(["ip", "-j", "neigh", "show"]))
    except ValueError as erro:
        raise Recusado(f"resposta do ip ilegivel: {erro}")

    ordenados = []
    for item in bruto:
        endereco = item.get("dst")
        if not endereco:
            continue
        try:
            ordem = ipaddress.ip_address(endereco)
        except ValueError:
            continue
        ordenados.append(((item.get("dev", ""), ordem.version, ordem), {
            "ip": endereco,
            # Minusculo sempre: o 'ip' e o dhcpd.leases escrevem em caixas
            # diferentes, e o painel cruza por igualdade de string.
            "mac": (item.get("lladdr") or "").lower(),
            "interface": item.get("dev", ""),
            "estado": " ".join(e.lower() for e in item.get("state", [])),
            "familia": "inet6" if ordem.version == 6 else "inet",
            # So NDP marca roteador; em IPv4 quem faz esse papel aparece na
            # rota padrao, que o comando 'interfaces' ja devolve.
            "roteador": bool(item.get("router")),
        }))

    ordenados.sort(key=lambda par: par[0])
    vizinhos = [registro for _, registro in ordenados]
    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(vizinhos),
        "vizinhos": vizinhos[:LIMITE_VIZINHOS],
    }


DIR_GHOP_NFTABLES = "/etc/ghop/nftables"

# --------------------------------------------------------------- trafego
#
# Os contadores de bytes de uma interface sao cumulativos: sozinhos nao dizem
# nada sobre "agora". Para o painel desenhar os ultimos minutos, alguem tem
# de ter amostrado antes de a tela abrir -- e esse alguem e o agente, que ja
# esta de pe. So em MEMORIA: nada vai a disco, e o que se guarda e um numero
# por interface a cada poucos segundos. E o mais sumarizado que um dado de
# rede consegue ser.
INTERVALO_AMOSTRA = 5      # segundos entre leituras
JANELA_TRAFEGO = 600       # quanto se guarda: 10 minutos

# deque de (instante, {interface: (rx_bytes, tx_bytes)}); o maxlen descarta o
# que passou da janela sem precisar de limpeza.
_amostras = collections.deque(maxlen=JANELA_TRAFEGO // INTERVALO_AMOSTRA + 1)
_amostras_tranca = threading.Lock()

# E para a maquina em si: (instante, (jiffies por cpu, memoria)). Mesma
# razao de sempre -- uso de processador so existe como DIFERENCA entre duas
# leituras, e alguem tem de ter lido antes de a tela abrir.
_amostras_sistema = collections.deque(
    maxlen=JANELA_TRAFEGO // INTERVALO_AMOSTRA + 1)

# A mesma ideia para as cadeias do firewall: (instante, {cadeia: pacotes}).
# O contador vem da regra de contagem no topo de cada cadeia, que o
# ghop-nftables escreve justamente para isto.
_amostras_cadeias = collections.deque(
    maxlen=JANELA_TRAFEGO // INTERVALO_AMOSTRA + 1)


# --------------------------------------------------------- mapa de conexoes
#
# A tabela de conexoes do kernel e o que a maquina JA precisa manter para
# mascarar: fazer NAT e manter estado, entao ler /proc/net/nf_conntrack nao
# custa um pacote nem uma captura. E a fonte mais completa de "quem esta na
# rede": nenhum aparelho que queira internet escapa dela, tenha endereco fixo,
# DNS proprio ou nada nosso.
#
# Mas ela e VIVA: entrada expira (UDP em ~30 s), e uma leitura sozinha mostra
# so o instante. Por isso o agente le de tempos em tempos e vai ACUMULANDO os
# pares vistos -- e o mapa que o painel recebe, nao o retrato.
#
# O que isto guarda que o resto do GHop nao guardava: o endereco de ORIGEM na
# LAN, par a par. Continua sendo contagem (nunca conteudo), continua SO EM
# MEMORIA e morre com o servico -- mas e uma extensao deliberada do "o coletor
# so sumariza por destino", e esta anotada como tal no arquitetura.md.
PASSOS_CONEXOES = 3        # a cada 3 ciclos do amostrador: 15 s
LIMITE_MAPA = 5000         # pares guardados; o mais velho sai primeiro
LIMITE_CONEXOES = 1000     # pares por resposta

ARQ_CONNTRACK = "/proc/net/nf_conntrack"
PROTOCOLOS_CT = ("tcp", "udp", "icmp", "icmpv6", "sctp", "dccp")

# chave (origem, destino, porta, protocolo) -> [primeiro, ultimo, amostras]
_mapa = {}
_mapa_tranca = threading.Lock()
_mapa_desde = None
_mapa_vivas = 0


def _le_conexoes():
    """Os pares (origem, destino, porta, protocolo) na tabela agora.

    Le a direcao ORIGINAL de cada entrada -- o primeiro src=/dst= da linha --,
    que e a de antes do masquerade: ali a origem ainda e o cliente da LAN. A
    tupla de resposta diz o contrario e nao serve para saber quem falou.
    """
    try:
        with open(ARQ_CONNTRACK, encoding="utf-8", errors="replace") as arquivo:
            linhas = arquivo.readlines()
    except OSError:
        # Sem conntrack (modulo fora, ou maquina que nao roteia) nao e erro:
        # e uma maquina onde este comando nao tem o que dizer.
        return None

    pares = set()
    for linha in linhas:
        campos = linha.split()
        protocolo = next((c for c in campos[:4] if c in PROTOCOLOS_CT), "")
        origem = destino = porta = ""
        for campo in campos:
            if campo.startswith("src=") and not origem:
                origem = campo[4:]
            elif campo.startswith("dst=") and not destino:
                destino = campo[4:]
            elif campo.startswith("dport=") and not porta:
                porta = campo[6:]
        if origem and destino:
            pares.add((origem, destino, porta, protocolo))
    return pares


def amostra_conexoes():
    """Junta o que a tabela mostra agora ao mapa acumulado."""
    global _mapa_desde, _mapa_vivas
    pares = _le_conexoes()
    if pares is None:
        return
    agora = time.time()
    with _mapa_tranca:
        if _mapa_desde is None:
            _mapa_desde = agora
        _mapa_vivas = len(pares)
        for chave in pares:
            registro = _mapa.get(chave)
            if registro is None:
                _mapa[chave] = [agora, agora, 1]
            else:
                registro[1] = agora
                registro[2] += 1
        # Teto: sai quem foi visto ha mais tempo. Mapa que cresce sem limite
        # em maquina que roteia muito vira consumo de memoria no agente.
        if len(_mapa) > LIMITE_MAPA:
            sobra = len(_mapa) - LIMITE_MAPA
            for chave in sorted(_mapa, key=lambda c: _mapa[c][1])[:sobra]:
                del _mapa[chave]


def comando_conexoes(argumentos):
    """O mapa de quem falou com quem, acumulado desde que o agente subiu.

    Nao e "as conexoes agora": e o que foi visto ao longo das amostras. O
    campo 'amostras' de cada par diz em quantas leituras ele apareceu --
    NAO quantas conexoes houve, que e coisa que amostragem nao sabe. Rotulo
    honesto importa mais aqui do que numero grande.

    'vivas' e o tamanho da tabela na ultima leitura, e 'intervalo' diz de
    quanto em quanto tempo se le: fluxo curto que nasce e morre entre duas
    amostras nao aparece, e quem desenha precisa poder dizer isso.

    Leitura pura, sem argumento.
    """
    if argumentos:
        raise Recusado("conexoes nao aceita argumentos")

    with _mapa_tranca:
        if _mapa_desde is None:
            raise Recusado(
                "esta maquina nao tem tabela de conexoes legivel "
                f"({ARQ_CONNTRACK}); ela nao roteia, ou o conntrack nao esta carregado")
        itens = [{"origem": o, "destino": d, "porta": p, "protocolo": r,
                  "primeiro": datetime.fromtimestamp(reg[0]).strftime("%Y-%m-%d %H:%M:%S"),
                  "ultimo": datetime.fromtimestamp(reg[1]).strftime("%Y-%m-%d %H:%M:%S"),
                  "amostras": reg[2]}
                 for (o, d, p, r), reg in _mapa.items()]
        desde, vivas = _mapa_desde, _mapa_vivas

    itens.sort(key=lambda i: (i["ultimo"], i["amostras"]), reverse=True)
    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "desde": datetime.fromtimestamp(desde).strftime("%Y-%m-%d %H:%M:%S"),
        "intervalo": INTERVALO_AMOSTRA * PASSOS_CONEXOES,
        "vivas": vivas,
        "total": len(itens),
        "pares": itens[:LIMITE_CONEXOES],
    }


def _le_contadores():
    """{interface: (rx_bytes, tx_bytes)} direto do /sys, sem processo externo."""
    contadores = {}
    try:
        nomes = os.listdir("/sys/class/net")
    except OSError:
        return contadores
    for nome in nomes:
        if nome == "lo":
            continue
        base = os.path.join("/sys/class/net", nome, "statistics")
        try:
            with open(os.path.join(base, "rx_bytes")) as rx, \
                    open(os.path.join(base, "tx_bytes")) as tx:
                contadores[nome] = (int(rx.read()), int(tx.read()))
        except (OSError, ValueError):
            continue
    return contadores


def _contadores_cadeias():
    """{'tabela/cadeia': pacotes} da regra de contagem no topo de cada uma.

    A regra de contagem e reconhecida por nao ter veredito nem condicao: a
    unica cuja expressao e so um 'counter'. Cadeia sem essa regra fica de
    fora, em vez de aparecer com numero que nao quer dizer nada.
    """
    contadores = {}
    if not os.path.isdir(DIR_GHOP_NFTABLES):
        return contadores
    try:
        bruto = json.loads(subprocess.run(
            ["nft", "-j", "list", "ruleset"], capture_output=True, text=True,
            timeout=10, check=True).stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        return contadores
    for item in bruto.get("nftables", []):
        regra = item.get("rule")
        if not regra:
            continue
        expressoes = regra.get("expr", [])
        if len(expressoes) != 1 or "counter" not in expressoes[0]:
            continue
        chave = f"{regra.get('table')}/{regra.get('chain')}"
        contadores.setdefault(chave, expressoes[0]["counter"].get("packets", 0))
    return contadores


def _le_processadores():
    """{'cpu0': (ocupado, total)} do /proc/stat, em jiffies acumulados."""
    processadores = {}
    try:
        with open("/proc/stat", encoding="utf-8") as arquivo:
            for linha in arquivo:
                if not linha.startswith("cpu"):
                    break
                campos = linha.split()
                nome = campos[0]
                if nome == "cpu":
                    nome = "total"
                numeros = [int(c) for c in campos[1:11]]
                total = sum(numeros)
                # Ocioso e espera de disco nao sao trabalho: tirar os dois e
                # o que faz o numero bater com o que 'top' mostra.
                ocioso = numeros[3] + numeros[4]
                processadores[nome] = (total - ocioso, total)
    except (OSError, ValueError, IndexError):
        pass
    return processadores


def _le_memoria():
    """(ram_total, ram_usada, swap_total, swap_usada) em bytes."""
    campos = {}
    try:
        with open("/proc/meminfo", encoding="utf-8") as arquivo:
            for linha in arquivo:
                chave, _, resto = linha.partition(":")
                campos[chave] = int(resto.split()[0]) * 1024
    except (OSError, ValueError, IndexError):
        return (0, 0, 0, 0)
    ram_total = campos.get("MemTotal", 0)
    # MemAvailable, e nao MemFree: o que o kernel usa de cache nao esta
    # "ocupado" no sentido que interessa a quem olha a tela.
    ram_usada = ram_total - campos.get("MemAvailable", campos.get("MemFree", 0))
    swap_total = campos.get("SwapTotal", 0)
    swap_usada = swap_total - campos.get("SwapFree", 0)
    return (ram_total, ram_usada, swap_total, swap_usada)


def amostra_trafego(encerrando):
    """Laco do amostrador. Roda numa thread daemon desde que o agente sobe."""
    passo = 0
    while not encerrando.is_set():
        instante = time.time()
        contadores = _le_contadores()
        cadeias = _contadores_cadeias()
        processadores = _le_processadores()
        memoria = _le_memoria()
        with _amostras_tranca:
            _amostras.append((instante, contadores))
            if cadeias:
                _amostras_cadeias.append((instante, cadeias))
            _amostras_sistema.append((instante, processadores, memoria))
        # A tabela de conexoes e mais cara de ler e muda mais devagar que um
        # contador de bytes: nao precisa do mesmo passo.
        if passo % PASSOS_CONEXOES == 0:
            amostra_conexoes()
        passo += 1
        encerrando.wait(INTERVALO_AMOSTRA)


def _serie_cadeias():
    """Pacotes por segundo por cadeia, na janela amostrada."""
    with _amostras_tranca:
        amostras = list(_amostras_cadeias)
    series = {}
    for (t0, c0), (t1, c1) in zip(amostras, amostras[1:]):
        duracao = t1 - t0
        if duracao <= 0:
            continue
        for nome, valor in c1.items():
            if nome not in c0:
                continue
            taxa = max(0, valor - c0[nome]) / duracao
            series.setdefault(nome, []).append([round(t1, 1), round(taxa, 2)])
    return series


def comando_trafego(argumentos):
    """Bytes por segundo, por interface, nos ultimos minutos. Leitura pura.

    Devolve pontos (instante, rx_bps, tx_bps) calculados entre amostras
    consecutivas. Contador que anda para tras (interface recriada) vira
    zero em vez de numero negativo. Sem argumento: a janela e a que o
    agente guarda, e nao ha o que escolher.
    """
    if argumentos:
        raise Recusado("trafego nao aceita argumentos")

    with _amostras_tranca:
        amostras = list(_amostras)

    series = {}
    for (t0, c0), (t1, c1) in zip(amostras, amostras[1:]):
        duracao = t1 - t0
        if duracao <= 0:
            continue
        for nome, (rx1, tx1) in c1.items():
            if nome not in c0:
                continue
            rx0, tx0 = c0[nome]
            rx = max(0, rx1 - rx0) / duracao
            tx = max(0, tx1 - tx0) / duracao
            series.setdefault(nome, []).append([round(t1, 1), round(rx), round(tx)])

    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "agora": round(time.time(), 1),
        "intervalo": INTERVALO_AMOSTRA,
        "janela": JANELA_TRAFEGO,
        "interfaces": series,
    }


# ----------------------------------------------------- papeis desta maquina
#
# O agente diz quais PAPEIS DO GHOP existem aqui -- nao quais servicos a
# maquina tem. A diferenca importa: papel e coisa nossa, com marca propria
# em /etc/ghop e unidade conhecida, e cada um tem seu comando de leitura. Sair
# farejando software de terceiros seria adivinhacao, e daria ao painel uma
# lista que ele nao sabe ler.
#
# 'basta_a_unidade' e a excecao, e ela e escopada por um motivo so: o painel
# JA SABE ler aquele servico mesmo quando nao fomos nos que o instalamos. O
# 'dhcp' le /var/lib/dhcp/dhcpd.leases e /etc/dhcp/dhcpd.conf, que sao do
# isc-dhcp-server e nao do GHop -- entao reconhece-lo pela unidade nao e
# adivinhacao, e uma leitura que funciona igual. Numa maquina observada, que
# e o caso de uso do projeto, o DHCP quase nunca foi instalado por nos.
#
# Quem entra por aqui vem marcado com origem='sistema' (contra origem='ghop'),
# e a origem NAO e enfeite de tela: 'desinstalar' se recusa a mexer no que
# nao instalamos (ver comando_papel).
PAPEIS = {
    # O lojmIt nao tem mais servico proprio: o firewall virou o papel
    # nftables e o que sobrou aqui e o encaminhamento de pacotes, que e um
    # sysctl. A marca e o arquivo que o instalador escreve.
    "lojmIt": {"rotulo": "lojmIt", "unidade": "",
                "marca": "/etc/sysctl.d/99-forward.conf", "comando": ""},
    "coletor": {"rotulo": "Coletor", "unidade": "ghop-requests.service",
                "marca": "/usr/local/sbin/ghop-requests.py", "comando": "resumo"},
    "dns": {"rotulo": "DNS", "unidade": "dnscrypt-proxy.service",
            "marca": "/etc/ghop/dns", "comando": "dns"},
    "wifi": {"rotulo": "Wi-Fi", "unidade": "hostapd.service",
             "marca": "/etc/ghop/wifi", "comando": "wifi"},
    "dhcp": {"rotulo": "DHCP", "unidade": "isc-dhcp-server.service",
             "marca": "/etc/ghop/dhcp", "comando": "dhcp",
             "basta_a_unidade": True},
    "nftables": {"rotulo": "Roteamento", "unidade": "ghop-nftables.service",
                 "marca": "/etc/ghop/nftables", "comando": "nftables"},
    "filtro": {"rotulo": "Filtro", "unidade": "ghop-filtro.service",
               "marca": "/etc/ghop/filtro", "comando": "filtro"},
    "balanceador": {"rotulo": "Balanceador",
                    "unidade": "ghop-balanceador.service",
                    "marca": "/etc/ghop/balanceador", "comando": "balanceador"},
}


def _estado_unidade(unidade):
    """(ativo, habilitado) de um servico. Ausente vira ('', '').

    Quem precisa saber se a unidade EXISTE usa _unidade_existe: aqui ('', '')
    e ambiguo de proposito (nao existe, esta mascarada, ou o systemctl nao
    respondeu), e tratar essa ambiguidade como "nao existe" ja deu erro.
    """
    return _consulta_unidade(unidade)[:2]


def _unidade_existe(unidade):
    """A unidade esta carregada no systemd? (pacote instalado, mesmo parada.)

    Sai do LoadState, nao de o ActiveState vir preenchido: unidade mascarada
    responde ('inactive', 'masked') e systemctl que falha responde vazio.
    Confundir "nao consegui perguntar" com "nao existe" faz servico sumir da
    tela sem que ninguem saiba que sumiu.
    """
    return _consulta_unidade(unidade)[2]


def _consulta_unidade(unidade):
    """(ativo, habilitado, existe) de um servico. Um systemctl show so."""
    if not unidade:
        return "", "", False
    try:
        saida = _executa_leitura(
            ["systemctl", "show", unidade, "-p", "ActiveState",
             "-p", "UnitFileState", "-p", "LoadState"])
    except Recusado:
        return "", "", False
    campos = dict(
        linha.split("=", 1) for linha in saida.splitlines() if "=" in linha)
    carregada = campos.get("LoadState") not in ("not-found", None, "")
    if not carregada:
        return "", "", False
    # Mascarada e "instalada, mas impedida de subir". Nao entra como servico
    # que se possa ligar: 'papeis' a trataria como um DHCP em pe.
    if campos.get("UnitFileState") == "masked" or campos.get("LoadState") == "masked":
        return campos.get("ActiveState", ""), "masked", False
    return campos.get("ActiveState", ""), campos.get("UnitFileState", ""), True


def comando_papeis(argumentos):
    """Quais papeis do GHop estao instalados aqui, e como estao. Leitura pura."""
    if argumentos:
        raise Recusado("papeis nao aceita argumentos")

    encontrados = []
    for chave, definicao in PAPEIS.items():
        nosso = os.path.exists(definicao["marca"])
        # A marca e de graca (um stat); o systemctl e um processo. So vale
        # perguntar ao systemd quando a marca nao decidiu E este papel pode
        # entrar sem marca -- senao seriam cinco spawns por chamada, e
        # 'papeis' e pedido a cada abertura de no e depois de cada acao.
        if not nosso and not definicao.get("basta_a_unidade"):
            continue
        ativo, habilitado, existe = _consulta_unidade(definicao["unidade"])
        if not nosso and not existe:
            continue
        encontrados.append({
            "chave": chave,
            "rotulo": definicao["rotulo"],
            "unidade": definicao["unidade"],
            "ativo": ativo,
            "habilitado": habilitado,
            "comando": definicao["comando"],
            "origem": "ghop" if nosso else "sistema",
        })
    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "papeis": sorted(encontrados, key=lambda p: p["rotulo"]),
    }


# ------------------------------------------------------------ papel: dhcp

ARQ_LEASES = "/var/lib/dhcp/dhcpd.leases"
ARQ_DHCPD_CONF = "/etc/dhcp/dhcpd.conf"
LIMITE_CONCESSOES = 500


def _exige_papel(chave):
    """Recusa a leitura de um papel que nao existe nesta maquina.

    Mesmo criterio de 'papeis': marca nossa, ou -- so onde 'basta_a_unidade'
    permite -- a unidade carregada. Sem isto a leitura devolveria sucesso
    vazio, e vazio mente: o painel nao distingue "nao ha DHCP aqui" de "ha um
    DHCP que ainda nao concedeu nada".
    """
    definicao = PAPEIS[chave]
    if os.path.exists(definicao["marca"]):
        return
    if definicao.get("basta_a_unidade") and _unidade_existe(definicao["unidade"]):
        return
    raise Recusado(
        f"{chave} nao existe nesta maquina (sem {definicao['marca']} nem "
        f"{definicao['unidade'] or 'unidade'})")


def comando_dhcp(argumentos):
    """Concessoes do DHCP e o que ele entrega. Leitura pura, sem argumento.

    O arquivo de concessoes e acrescido, nunca reescrito: o mesmo IP aparece
    varias vezes e vale o ULTIMO bloco. Por isso se guarda por endereco em
    vez de acumular numa lista.
    """
    if argumentos:
        raise Recusado("dhcp nao aceita argumentos")
    _exige_papel("dhcp")

    concessoes = {}
    try:
        with open(ARQ_LEASES, encoding="utf-8", errors="replace") as arquivo:
            atual = None
            for linha in arquivo:
                linha = linha.strip().rstrip(";")
                if linha.startswith("lease ") and linha.endswith("{"):
                    atual = {"ip": linha.split()[1], "estado": "", "mac": "",
                             "nome": "", "inicio": "", "fim": ""}
                elif atual is None:
                    continue
                elif linha == "}":
                    concessoes[atual["ip"]] = atual
                    atual = None
                elif linha.startswith("binding state "):
                    atual["estado"] = linha[len("binding state "):]
                elif linha.startswith("hardware ethernet "):
                    atual["mac"] = linha[len("hardware ethernet "):]
                elif linha.startswith("client-hostname "):
                    atual["nome"] = linha[len("client-hostname "):].strip('"')
                elif linha.startswith("starts "):
                    atual["inicio"] = " ".join(linha.split()[2:])
                elif linha.startswith("ends "):
                    atual["fim"] = " ".join(linha.split()[2:])
    except FileNotFoundError:
        # Aqui ja se sabe que HA um DHCP nesta maquina (_exige_papel passou):
        # sem arquivo de concessao ele so nao atendeu ninguem ainda, e isso e
        # uma tabela vazia, nao um erro. O caso "nao ha DHCP" foi recusado
        # la em cima, com essas palavras.
        pass
    except OSError as erro:
        raise Recusado(f"nao consegui ler {ARQ_LEASES}: {erro}")

    # Ativas primeiro, e dentro delas a mais recente no topo. 'fim' vem como
    # 'YYYY/MM/DD HH:MM:SS', entao ordem de texto e ordem de tempo -- e o
    # decrescente importa porque a lista e truncada em LIMITE_CONCESSOES:
    # crescente cortava justamente quem acabou de entrar na rede, que e o
    # aparelho por causa do qual se abre esta tela.
    lista = sorted(concessoes.values(),
                   key=lambda c: (c["estado"] == "active", c["fim"]), reverse=True)

    configuracao = {}
    try:
        with open(ARQ_DHCPD_CONF, encoding="utf-8", errors="replace") as arquivo:
            for linha in arquivo:
                limpa = linha.strip().rstrip(";")
                for chave, prefixo in (("faixa", "range "),
                                       ("roteador", "option routers "),
                                       ("resolvedor", "option domain-name-servers "),
                                       ("concessao", "default-lease-time "),
                                       ("concessao_maxima", "max-lease-time ")):
                    if limpa.startswith(prefixo):
                        configuracao[chave] = limpa[len(prefixo):]
    except OSError:
        pass

    ativas = sum(1 for c in lista if c["estado"] == "active")
    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "configuracao": configuracao,
        "ativas": ativas,
        "total": len(lista),
        "concessoes": lista[:LIMITE_CONCESSOES],
    }


# ------------------------------------------------------------- papel: dns

DIR_GHOP_DNS = "/etc/ghop/dns"
ARQ_BLOQUEADOS = "/var/log/dnscrypt-proxy/bloqueados.log"
ARQ_TOML_DNS = "/etc/dnscrypt-proxy/dnscrypt-proxy.toml"
ARQ_FONTES_DNS = "/var/cache/dnscrypt-proxy/public-resolvers.md"
LIMITE_BLOQUEIOS = 500
# Quanto do log se le para somar. O arquivo cresce sem parar; ler tudo em
# maquina fraca custaria caro, e o que se perde e a contagem de meses atras.
LIMITE_LINHAS_LOG = 100000


def _conta_regras(caminho):
    try:
        with open(caminho, encoding="utf-8", errors="replace") as arquivo:
            return sum(1 for linha in arquivo
                       if linha.strip() and not linha.lstrip().startswith("#"))
    except OSError:
        return 0


def comando_dns(argumentos):
    """Estado do resolvedor da LAN e o que ele andou negando.

    O registro de bloqueio traz cliente e nome, evento a evento -- e a
    excecao que o proprio desenho do ghop-dns assume: negar e ACAO, e acao
    tem de deixar rastro de quem tentou e o que. O resto das consultas nao e
    registrado em lugar nenhum.
    """
    if argumentos:
        raise Recusado("dns nao aceita argumentos")
    if not os.path.isdir(DIR_GHOP_DNS):
        raise Recusado("o papel dns nao esta instalado nesta maquina")

    ativo, habilitado = _estado_unidade("dnscrypt-proxy.service")

    escuta = []
    try:
        for linha in _executa_leitura(["ss", "-H", "-lnu", "sport = :53"]).splitlines():
            campos = linha.split()
            # O 'ss' omite a coluna do protocolo quando so um foi pedido, e
            # contar campos a partir da esquerda pegava o endereco errado.
            # Da direita e estavel: ultimo e o par remoto, penultimo o local.
            if len(campos) >= 2 and campos[-2] not in escuta:
                escuta.append(campos[-2])
    except Recusado:
        pass

    # SUMARIZADO, e nao evento a evento: um nome negado que um aparelho
    # insiste em pedir gera dezenas de linhas iguais por minuto, e a tela
    # virava rolagem sem informacao. Agrupado por (regra, nome, cliente),
    # com o total e a ultima vez, a mesma tela responde o que interessa --
    # o que mais bate na porta, e quem esta batendo.
    #
    # O agrupamento e feito AQUI porque o total tem de sair do arquivo
    # inteiro: agrupar no painel so contaria as ultimas linhas enviadas.
    agrupados = {}
    try:
        with open(ARQ_BLOQUEADOS, encoding="utf-8", errors="replace") as arquivo:
            for linha in arquivo.readlines()[-LIMITE_LINHAS_LOG:]:
                campos = linha.rstrip("\n").split("\t")
                if len(campos) < 3:
                    continue
                quando = campos[0].strip("[]")
                chave = (campos[3] if len(campos) > 3 else "", campos[2], campos[1])
                registro = agrupados.get(chave)
                if registro is None:
                    agrupados[chave] = {
                        "regra": chave[0], "nome": chave[1], "cliente": chave[2],
                        "total": 1, "primeiro": quando, "ultimo": quando,
                    }
                else:
                    registro["total"] += 1
                    registro["ultimo"] = quando
    except OSError:
        pass
    bloqueios = sorted(agrupados.values(), key=lambda b: b["ultimo"],
                       reverse=True)[:LIMITE_BLOQUEIOS]

    # O lado de CIMA: para quem este resolvedor pergunta. Nao ha API no
    # dnscrypt-proxy para isto; o que ele conta, conta no diario ao subir.
    # Por isso se le o journal em vez de inventar um numero.
    acima = {}
    try:
        for linha in _executa_leitura(
                ["journalctl", "-u", "dnscrypt-proxy.service", "-n", "400",
                 "--no-pager", "-o", "cat"]).splitlines():
            if "lowest initial latency" in linha:
                _, _, resto = linha.partition("latency:")
                nome, _, latencia = resto.strip().partition("(rtt:")
                acima["servidor"] = nome.strip()
                acima["latencia"] = latencia.strip(" )ms")
            elif "live servers:" in linha:
                acima["servidores_vivos"] = linha.rsplit(":", 1)[1].strip()
    except Recusado:
        pass

    # E o que a configuracao EXIGE de quem esta acima. Vale mostrar junto:
    # o servidor escolhido so significa alguma coisa a luz do que se exigiu
    # dele -- sem log, sem filtro, cifrado por qual protocolo.
    configuracao = {}
    try:
        with open(ARQ_TOML_DNS, encoding="utf-8", errors="replace") as arquivo:
            for linha in arquivo:
                limpa = linha.strip()
                for chave in ("server_names", "dnscrypt_servers", "doh_servers",
                              "require_nolog", "require_nofilter", "require_dnssec",
                              "lb_strategy", "cache", "cache_size",
                              "blocked_query_response"):
                    if limpa.startswith(chave + " ") or limpa.startswith(chave + "="):
                        configuracao[chave] = limpa.split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass

    try:
        idade = os.path.getmtime(ARQ_FONTES_DNS)
        acima["fontes_de"] = datetime.fromtimestamp(idade).strftime("%Y-%m-%d %H:%M")
    except OSError:
        pass

    # Quem usa DNS nesta rede vem do COLETOR, nao do resolvedor: este nao
    # registra consulta, e o outro ve os pacotes na entrada da LAN. A juncao
    # das duas leituras e o que responde "quem esta ai" e, melhor ainda,
    # "quem esta ignorando o resolvedor daqui".
    clientes = []
    dia = datetime.now().strftime("%d_%m_%Y")
    try:
        conexao = abre_banco(dia)
    except Recusado:
        conexao = None
    if conexao is not None:
        try:
            clientes = [
                {"origem": o, "servidor": sv, "total": t, "primeiro": p, "ultimo": u}
                for o, sv, t, p, u in conexao.execute(
                    "SELECT origem_ip, servidor, total, primeiro, ultimo"
                    " FROM clientes_dns ORDER BY total DESC LIMIT 500")
            ]
        except sqlite3.Error:
            # Coletor antigo, sem a tabela: lista vazia diz a verdade -- nao
            # ha essa contagem aqui -- em vez de derrubar o comando inteiro.
            pass
        finally:
            conexao.close()

    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ativo": ativo,
        "habilitado": habilitado,
        "escuta": escuta,
        "clientes": clientes,
        "dia": dia,
        "negados": _conta_regras(os.path.join(DIR_GHOP_DNS, "negados.txt")),
        "permitidos": _conta_regras(os.path.join(DIR_GHOP_DNS, "permitidos.txt")),
        "bloqueios": list(reversed(bloqueios)),
        "acima": acima,
        "configuracao": configuracao,
    }


# O que se aceita como nome negado. E a sintaxe do proprio dnscrypt-proxy:
# nome, '=nome' para exato, e curingas. O que NAO passa e o que transformaria
# uma linha de lista em outra coisa: espaco, '#', barra, aspas, quebra de
# linha. A lista e um arquivo lido por outro programa -- deixar passar um '#'
# permitiria comentar a regra seguinte, e uma quebra de linha permitiria
# escrever duas regras onde o painel pediu uma.
FORMATO_NEGADO = re.compile(r"^=?[A-Za-z0-9_.*?\[\]\-]{1,253}$")

# ------------------------------------------------- listas do resolvedor
#
# O dnscrypt-proxy le UM arquivo por especie. Varias listas existem porque
# esses dois arquivos sao GERADOS: cada lista e um arquivo em negados.d/ ou
# permitidos.d/, e aqui se concatenam as ativas. Desligar uma lista nao
# apaga nada -- e o que permite experimentar uma lista grande e voltar
# atras sem perder as regras escritas a mao.
#
# O CONTEUDO CHEGA COLADO PELO OPERADOR, em pedacos. O agente nunca baixa
# lista nenhuma: pedido de saida partindo daqui faria da maquina observada
# um proxy da rede que ela observa, e o conjunto fechado existe para isso
# nao acontecer. Quem viu o arquivo e decidiu foi uma pessoa, no painel.
ESPECIES_LISTA = ("negados", "permitidos")
FORMATO_LISTA = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
LIMITE_TEXTO_LISTA = 8 * 1024 * 1024
LIMITE_REGRAS_TELA = 2000

# Recebimento em curso: (especie, lista) -> [pedacos]. Em memoria, porque
# uma transferencia interrompida nao deve deixar arquivo pela metade.
_recebendo = {}
_recebendo_tranca = threading.Lock()


def _arquivo_lista(especie, nome):
    return os.path.join(DIR_GHOP_DNS, especie + ".d", nome + ".txt")


def _le_indice_listas():
    try:
        with open(os.path.join(DIR_GHOP_DNS, "listas.json"), encoding="utf-8") as arquivo:
            indice = json.load(arquivo)
    except (OSError, ValueError):
        indice = {}
    for especie in ESPECIES_LISTA:
        indice.setdefault(especie, {})
    return indice


def _grava_indice_listas(indice):
    caminho = os.path.join(DIR_GHOP_DNS, "listas.json")
    temporario = caminho + ".novo"
    with open(temporario, "w", encoding="utf-8") as arquivo:
        json.dump(indice, arquivo, indent=2, ensure_ascii=False)
        arquivo.write("\n")
    os.chmod(temporario, 0o644)
    os.replace(temporario, caminho)


def _regras_de(caminho, limite=None):
    """[(regra, nota)] de um arquivo de lista. Comentario puro nao entra."""
    regras = []
    try:
        with open(caminho, encoding="utf-8", errors="replace") as arquivo:
            for linha in arquivo:
                limpa = linha.strip()
                if not limpa or limpa.startswith("#"):
                    continue
                regra, _, nota = limpa.partition("#")
                regras.append((regra.strip(), nota.strip()))
                if limite and len(regras) >= limite:
                    break
    except OSError:
        pass
    return regras


def _compila_listas(especie):
    """Junta as listas ativas no arquivo unico que o resolvedor le."""
    indice = _le_indice_listas()
    destino = os.path.join(DIR_GHOP_DNS, especie + ".txt")
    partes = ["# GERADO pelo ghop-agente a partir de " + especie + ".d/.",
              "# Nao edite: a proxima mudanca de lista sobrescreve.", ""]
    # 'propria' primeiro: e a lista escrita a mao, e quem le o arquivo
    # gerado deve encontra-la no topo.
    nomes = sorted(indice[especie], key=lambda n: (n != "propria", n))
    for nome in nomes:
        if not indice[especie].get(nome, {}).get("ativa", True):
            continue
        caminho = _arquivo_lista(especie, nome)
        if not os.path.exists(caminho):
            continue
        partes.append(f"# --- {nome} ---")
        try:
            with open(caminho, encoding="utf-8", errors="replace") as arquivo:
                partes.append(arquivo.read().rstrip("\n"))
        except OSError:
            continue
        partes.append("")
    temporario = destino + ".novo"
    with open(temporario, "w", encoding="utf-8") as arquivo:
        arquivo.write("\n".join(partes) + "\n")
    os.chmod(temporario, 0o644)
    os.replace(temporario, destino)


def _recarrega_resolvedor():
    try:
        _executa_leitura(["systemctl", "restart", "dnscrypt-proxy.service"], tempo=20)
    except Recusado as erro:
        raise Recusado(f"listas gravadas, mas o resolvedor nao recarregou: {erro}")


def _limpa_texto_lista(texto):
    """Texto colado -> (linhas aceitas, quantas foram recusadas).

    Aceita o formato 'hosts' (0.0.0.0 dominio), que e como metade das
    listas publicas vem, e comentario, que ajuda a lembrar de onde veio a
    regra. Linha que nao vira nome valido e CONTADA e descartada -- melhor
    dizer 'entraram 40 mil, sobraram 12' do que gravar lixo que o
    dnscrypt-proxy vai recusar em silencio no proximo boot.
    """
    aceitas, recusadas = [], 0
    for linha in texto.splitlines():
        limpa = linha.strip()
        if not limpa:
            continue
        if limpa.startswith("#"):
            aceitas.append(limpa)
            continue
        campos = limpa.split()
        if len(campos) >= 2 and campos[0] in ("0.0.0.0", "127.0.0.1", "::1", "::"):
            candidato = campos[1]          # formato 'hosts'
        elif len(campos) == 1:
            candidato = campos[0]
        elif campos[1].startswith("#"):
            candidato = campos[0]          # nome seguido de comentario
        else:
            # Linha com varias palavras que nao e nenhum dos formatos acima:
            # RECUSA, nao corta na primeira palavra. Cortar transformaria
            # uma linha estranha em um dominio plausivel, e uma lista de
            # cem mil linhas passaria a bloquear coisa que ninguem escreveu.
            recusadas += 1
            continue
        candidato = candidato.rstrip(".")
        if FORMATO_NEGADO.match(candidato):
            aceitas.append(candidato)
        else:
            recusadas += 1
    return aceitas, recusadas


def comando_listas(argumentos):
    """As listas do resolvedor e, se pedido, as regras de uma delas."""
    especie = argumentos.get("especie")
    lista = argumentos.get("lista")
    if sobra := set(argumentos) - {"especie", "lista"}:
        raise Recusado(f"argumento desconhecido: {sorted(sobra)}")
    if not os.path.isdir(DIR_GHOP_DNS):
        raise Recusado("o papel dns nao esta instalado nesta maquina")
    if especie is not None and especie not in ESPECIES_LISTA:
        raise Recusado(f"especie {especie!r} desconhecida")

    indice = _le_indice_listas()
    resposta = {"quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "listas": {}}
    for uma in ESPECIES_LISTA:
        entradas = []
        for nome in sorted(indice[uma], key=lambda n: (n != "propria", n)):
            dados = indice[uma][nome]
            caminho = _arquivo_lista(uma, nome)
            entradas.append({
                "nome": nome,
                "ativa": bool(dados.get("ativa", True)),
                "origem": dados.get("origem", ""),
                "em": dados.get("em", ""),
                "regras": len(_regras_de(caminho)),
                "existe": os.path.exists(caminho),
            })
        resposta["listas"][uma] = entradas

    # As regras so viajam quando alguem abre UMA lista: ha listas de
    # centenas de milhares de linhas, e manda-las a cada leitura de tela
    # seria entupir o canal para mostrar o que ninguem pediu.
    if especie and lista:
        if not FORMATO_LISTA.match(lista):
            raise Recusado("nome de lista invalido")
        regras = _regras_de(_arquivo_lista(especie, lista), LIMITE_REGRAS_TELA + 1)
        resposta["escolhida"] = {
            "especie": especie, "lista": lista,
            "regras": [{"regra": r, "nota": n} for r, n in regras[:LIMITE_REGRAS_TELA]],
            "cortada": len(regras) > LIMITE_REGRAS_TELA,
        }
    return resposta


def comando_lista(argumentos):
    """Cria, recebe, liga, desliga ou apaga uma lista do resolvedor. ESCREVE.

    O texto colado chega em pedacos ('iniciar', 'parte'..., 'concluir'),
    porque uma lista publica tem megabytes e o limite de linha do protocolo
    e de 64 kB -- e afrouxar esse limite para todo mundo por causa de um
    comando seria pagar caro pelo caminho errado.
    """
    acao = argumentos.get("acao")
    especie = argumentos.get("especie")
    nome = argumentos.get("lista")
    if sobra := set(argumentos) - {"acao", "especie", "lista", "texto", "nome"}:
        raise Recusado(f"argumento desconhecido: {sorted(sobra)}")
    if especie not in ESPECIES_LISTA:
        raise Recusado(f"especie {especie!r} desconhecida ({', '.join(ESPECIES_LISTA)})")
    if not isinstance(nome, str) or not FORMATO_LISTA.match(nome):
        raise Recusado("nome de lista: minusculas, digitos, hifen; ate 32")
    if not os.path.isdir(DIR_GHOP_DNS):
        raise Recusado("o papel dns nao esta instalado nesta maquina")
    chave = (especie, nome)

    if acao == "iniciar":
        with _recebendo_tranca:
            _recebendo[chave] = []
        return {"lista": nome, "recebendo": True}

    if acao == "parte":
        texto = argumentos.get("texto")
        if not isinstance(texto, str):
            raise Recusado("texto deve ser uma string")
        with _recebendo_tranca:
            if chave not in _recebendo:
                raise Recusado("nenhum envio em andamento para esta lista")
            _recebendo[chave].append(texto)
            tamanho = sum(len(p) for p in _recebendo[chave])
            if tamanho > LIMITE_TEXTO_LISTA:
                del _recebendo[chave]
                raise Recusado(
                    f"lista maior que {LIMITE_TEXTO_LISTA // (1024 * 1024)} MB")
        return {"lista": nome, "recebido": tamanho}

    if acao == "concluir":
        with _recebendo_tranca:
            pedacos = _recebendo.pop(chave, None)
        if pedacos is None:
            raise Recusado("nenhum envio em andamento para esta lista")
        aceitas, recusadas = _limpa_texto_lista("".join(pedacos))
        caminho = _arquivo_lista(especie, nome)
        try:
            os.makedirs(os.path.dirname(caminho), exist_ok=True)
            temporario = caminho + ".novo"
            with open(temporario, "w", encoding="utf-8") as arquivo:
                arquivo.write("\n".join(aceitas) + "\n")
            os.chmod(temporario, 0o644)
            os.replace(temporario, caminho)
        except OSError as erro:
            raise Recusado(f"nao consegui gravar a lista: {erro}")
        indice = _le_indice_listas()
        indice[especie][nome] = {
            "ativa": indice[especie].get(nome, {}).get("ativa", True),
            "origem": "colada no painel",
            "em": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }
        _grava_indice_listas(indice)
        _compila_listas(especie)
        _recarrega_resolvedor()
        registra(f"lista {especie}/{nome}: {len(aceitas)} linha(s), {recusadas} recusada(s)")
        return {"lista": nome, "aceitas": len(aceitas), "recusadas": recusadas}

    if acao in ("adicionar_regra", "remover_regra"):
        regra = (argumentos.get("nome") or "").strip()
        if not FORMATO_NEGADO.match(regra):
            raise Recusado(
                "regra invalida: letras, digitos, ponto, hifen e curinga; "
                "sem espaco, '#' ou barra")
        caminho = _arquivo_lista(especie, nome)
        if not os.path.exists(caminho):
            raise Recusado(f"nao ha lista {nome!r} em {especie}")
        try:
            with open(caminho, encoding="utf-8", errors="replace") as arquivo:
                linhas = arquivo.read().splitlines()
        except OSError as erro:
            raise Recusado(f"nao consegui ler a lista: {erro}")

        def so_a_regra(linha):
            return linha.split("#", 1)[0].strip()

        ja_esta = any(so_a_regra(l) == regra for l in linhas)
        if acao == "adicionar_regra":
            if ja_esta:
                raise Recusado(f"{regra} ja esta na lista {nome}")
            linhas.append(f"{regra}\t# painel, {datetime.now():%Y-%m-%d %H:%M}")
        else:
            if not ja_esta:
                raise Recusado(f"{regra} nao esta na lista {nome}")
            linhas = [l for l in linhas if so_a_regra(l) != regra]
        try:
            temporario = caminho + ".novo"
            with open(temporario, "w", encoding="utf-8") as arquivo:
                arquivo.write("\n".join(linhas) + "\n")
            os.chmod(temporario, 0o644)
            os.replace(temporario, caminho)
        except OSError as erro:
            raise Recusado(f"nao consegui gravar a lista: {erro}")
        _compila_listas(especie)
        _recarrega_resolvedor()
        registra(f"lista {especie}/{nome}: {acao} '{regra}'")
        return {"lista": nome, "acao": acao, "nome": regra,
                "regras": len(_regras_de(caminho))}

    if acao in ("ativar", "desativar", "remover"):
        indice = _le_indice_listas()
        if nome not in indice[especie]:
            raise Recusado(f"nao ha lista {nome!r} em {especie}")
        if acao == "remover":
            if nome == "propria":
                raise Recusado(
                    "a lista 'propria' nao se apaga: e a que se escreve a mao. "
                    "Desative-a, ou esvazie-a colando texto vazio.")
            del indice[especie][nome]
            try:
                os.remove(_arquivo_lista(especie, nome))
            except OSError:
                pass
        else:
            indice[especie][nome]["ativa"] = acao == "ativar"
        _grava_indice_listas(indice)
        _compila_listas(especie)
        _recarrega_resolvedor()
        registra(f"lista {especie}/{nome}: {acao}")
        return {"lista": nome, "acao": acao}

    raise Recusado(
        f"acao {acao!r} desconhecida (iniciar, parte, concluir, "
        "adicionar_regra, remover_regra, ativar, desativar, remover)")


# ------------------------------------------------------------ papel: wifi

ARQ_GHOP_WIFI = "/etc/ghop/wifi/interfaces"
ARQ_HOSTAPD = "/etc/hostapd/hostapd.conf"


def comando_wifi(argumentos):
    """Radio, rede e quem esta associado. Leitura pura, sem argumento.

    A senha do hostapd.conf NAO sai daqui: le-se so o que descreve a rede.
    Um comando que devolvesse a chave transformaria leitura em vazamento.
    """
    if argumentos:
        raise Recusado("wifi nao aceita argumentos")
    if not os.path.exists(ARQ_GHOP_WIFI):
        raise Recusado("o papel wifi nao esta instalado nesta maquina")

    estado = {}
    try:
        with open(ARQ_GHOP_WIFI, encoding="utf-8") as arquivo:
            for linha in arquivo:
                if "=" in linha:
                    chave, valor = linha.strip().split("=", 1)
                    estado[chave] = valor
    except OSError as erro:
        raise Recusado(f"nao consegui ler {ARQ_GHOP_WIFI}: {erro}")

    rede = {}
    try:
        with open(ARQ_HOSTAPD, encoding="utf-8", errors="replace") as arquivo:
            for linha in arquivo:
                limpa = linha.strip()
                for chave in ("ssid", "channel", "hw_mode", "country_code",
                              "wpa", "bridge", "interface"):
                    if limpa.startswith(chave + "="):
                        rede[chave] = limpa.split("=", 1)[1]
    except OSError:
        pass

    radio = estado.get("WIFI_IF", "")
    clientes = []
    if radio and os.path.exists(IW):
        try:
            atual = None
            for linha in _executa_leitura([IW, "dev", radio, "station", "dump"]).splitlines():
                if linha.startswith("Station "):
                    atual = {"mac": linha.split()[1], "sinal": "", "rx_bytes": 0,
                             "tx_bytes": 0, "conectado": "", "inativo": ""}
                    clientes.append(atual)
                elif atual is None or ":" not in linha:
                    continue
                else:
                    rotulo, valor = (p.strip() for p in linha.split(":", 1))
                    if rotulo == "signal":
                        atual["sinal"] = valor.split()[0]
                    elif rotulo == "rx bytes":
                        atual["rx_bytes"] = int(valor)
                    elif rotulo == "tx bytes":
                        atual["tx_bytes"] = int(valor)
                    elif rotulo == "connected time":
                        atual["conectado"] = valor
                    elif rotulo == "inactive time":
                        atual["inativo"] = valor
        except (Recusado, ValueError):
            pass

    ativo, habilitado = _estado_unidade("hostapd.service")
    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ativo": ativo,
        "habilitado": habilitado,
        "radio": radio,
        "ponte": estado.get("PONTE_IF", ""),
        "cabo": estado.get("CABO_IF", ""),
        "rede": rede,
        "clientes": clientes,
    }


# ---------------------------------------------------------- papel: filtro

DIR_GHOP_FILTRO = "/etc/ghop/filtro"
ARQ_REGRAS_FILTRO = os.path.join(DIR_GHOP_FILTRO, "regras.json")
ARQ_ESTADO_FILTRO = "/var/ghop/filtro.json"
ARQ_LOG_FILTRO = "/var/log/ghop/filtro-bloqueados.log"
# Cabem folgado nos 64 kB de uma linha do protocolo (~40 bytes por regra), e
# o filtro percorre a lista A CADA CONEXAO -- o teto e do caminho do dado,
# nao do painel. Lista publica de cem mil nomes e assunto do resolvedor, que
# tem indice proprio para isso; aqui sao as regras que o operador escreveu.
LIMITE_REGRAS_FILTRO = 500
LIMITE_BLOQUEIOS_FILTRO = 500
TIPOS_REGRA_FILTRO = ("sufixo", "exato", "prefixo", "contem")
ACOES_REGRA_FILTRO = ("bloquear", "permitir")
POLITICAS_FILTRO = ("permitir", "bloquear")
# Nome de host, e so isso: rotulos alfanumericos com hifen no meio. Estreita
# de proposito -- o valor vai para um arquivo que um servico no caminho do
# dado le e compara, e caractere estranho ali nao tem uso legitimo.
FORMATO_NOME_FILTRO = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


def comando_filtro(argumentos):
    """Estado do filtro de camada de aplicacao e o que ele andou bloqueando.

    Devolve as regras em vigor, os contadores que o proprio filtro grava e o
    registro dos bloqueios -- que existe pelo mesmo motivo do registro do
    resolvedor: negar e ACAO, e acao tem de deixar rastro de quem tentou e o
    que. O que PASSOU nao esta aqui e nao esta em lugar nenhum: o coletor ja
    responde quem falou com quem, e um segundo registro nome a nome na mesma
    maquina seria o oposto do 'so sumariza'.
    """
    if argumentos:
        raise Recusado("filtro nao aceita argumentos")
    if not os.path.isdir(DIR_GHOP_FILTRO):
        raise Recusado("o papel filtro nao esta instalado nesta maquina")

    ativo, habilitado = _estado_unidade("ghop-filtro.service")

    politica, regras = "permitir", []
    try:
        with open(ARQ_REGRAS_FILTRO, encoding="utf-8") as arquivo:
            dado = json.load(arquivo)
        politica = dado.get("politica") if dado.get("politica") in POLITICAS_FILTRO else "permitir"
        for regra in dado.get("regras") or []:
            if isinstance(regra, dict):
                regras.append({"tipo": regra.get("tipo", ""),
                               "valor": regra.get("valor", ""),
                               "acao": regra.get("acao", ""),
                               "nota": regra.get("nota", "")})
    except (OSError, ValueError):
        pass

    contadores = {}
    try:
        with open(ARQ_ESTADO_FILTRO, encoding="utf-8") as arquivo:
            contadores = json.load(arquivo)
    except (OSError, ValueError):
        pass

    # Agrupado por (regra, nome, cliente), como no dns: um aparelho que
    # insiste num nome negado gera dezenas de linhas iguais por minuto, e a
    # tela virava rolagem sem informacao. O total sai do arquivo inteiro,
    # por isso o agrupamento e aqui e nao no painel.
    agrupados = {}
    try:
        with open(ARQ_LOG_FILTRO, encoding="utf-8", errors="replace") as arquivo:
            for linha in arquivo.readlines()[-LIMITE_LINHAS_LOG:]:
                campos = linha.rstrip("\n").split("\t")
                if len(campos) < 5:
                    continue
                quando, cliente, nome, porta, regra = campos[:5]
                chave = (regra, nome, cliente, porta)
                registro = agrupados.get(chave)
                if registro is None:
                    agrupados[chave] = {
                        "regra": regra, "nome": nome, "cliente": cliente,
                        "porta": porta, "total": 1,
                        "primeiro": quando, "ultimo": quando,
                    }
                else:
                    registro["total"] += 1
                    registro["ultimo"] = quando
    except OSError:
        pass
    bloqueios = sorted(agrupados.values(), key=lambda b: b["ultimo"],
                       reverse=True)[:LIMITE_BLOQUEIOS_FILTRO]

    interface = ""
    try:
        with open(os.path.join(DIR_GHOP_FILTRO, "interface"), encoding="utf-8") as arquivo:
            interface = arquivo.read().strip()
    except OSError:
        pass

    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ativo": ativo,
        "habilitado": habilitado,
        "interface": interface,
        "politica": politica,
        "regras": regras,
        "contadores": contadores,
        "bloqueios": bloqueios,
        # O redirecionamento esta no firewall? Sem ele o servico pode estar
        # de pe sem ver trafego nenhum, e a tela mentiria dizendo "ativo".
        "redirecionando": os.path.isfile("/etc/ghop/nft.d/filtro.sh"),
    }


def comando_filtrar(argumentos):
    """Grava as regras do filtro. ESCREVE.

    Estado inteiro, nao delta -- molde do 'monitorar', e pelo mesmo motivo:
    sincronizar estado e idempotente, e painel que perdeu uma mensagem nao
    deixa regra orfa bloqueando para sempre. E o contrario do comando
    'lista' do resolvedor, onde a maquina tambem guarda listas que nao vieram
    do painel; aqui nao ha nenhuma outra fonte, entao mandar tudo e honesto.

    O painel manda CAMPOS, nunca texto de regra: tipo, valor, acao e nota,
    cada um conferido aqui contra uma lista fechada ou uma expressao
    estreita. O que sai daqui e DADO em JSON, lido por um programa que nao
    passa nada disso a shell nenhum.

    Nao reinicia o servico: o filtro reve o arquivo pelo mtime em segundos.
    Reiniciar derrubaria as conexoes de todo mundo a cada regra escrita.
    """
    politica = argumentos.get("politica", "permitir")
    regras = argumentos.get("regras")
    if sobra := set(argumentos) - {"politica", "regras"}:
        raise Recusado(f"argumento desconhecido: {sorted(sobra)}")
    if not os.path.isdir(DIR_GHOP_FILTRO):
        raise Recusado("o papel filtro nao esta instalado nesta maquina")
    if politica not in POLITICAS_FILTRO:
        raise Recusado(f"politica deve ser uma de {POLITICAS_FILTRO}")
    if not isinstance(regras, list):
        raise Recusado("regras deve ser uma lista")
    if len(regras) > LIMITE_REGRAS_FILTRO:
        raise Recusado(f"no maximo {LIMITE_REGRAS_FILTRO} regras")

    limpas = []
    for bruta in regras:
        if not isinstance(bruta, dict):
            raise Recusado("cada regra deve ser um objeto")
        if sobra := set(bruta) - {"tipo", "valor", "acao", "nota"}:
            raise Recusado(f"campo desconhecido em regra: {sorted(sobra)}")
        tipo, acao = bruta.get("tipo"), bruta.get("acao")
        valor, nota = bruta.get("valor"), bruta.get("nota") or ""
        if tipo not in TIPOS_REGRA_FILTRO:
            raise Recusado(f"tipo deve ser um de {TIPOS_REGRA_FILTRO}")
        if acao not in ACOES_REGRA_FILTRO:
            raise Recusado(f"acao deve ser uma de {ACOES_REGRA_FILTRO}")
        if not isinstance(valor, str) or not isinstance(nota, str):
            raise Recusado("valor e nota devem ser texto")
        valor = valor.strip().lower().rstrip(".")
        if not FORMATO_NOME_FILTRO.match(valor):
            raise Recusado(f"valor invalido: {valor!r} (nome de host, sem espaco nem barra)")
        if len(nota) > 200:
            raise Recusado("nota longa demais (200 caracteres)")
        limpas.append({"tipo": tipo, "valor": valor, "acao": acao, "nota": nota})

    dado = {
        "versao": 1,
        "politica": politica,
        "atualizado": time.strftime("%Y-%m-%d %H:%M:%S"),
        "regras": limpas,
    }
    try:
        temporario = ARQ_REGRAS_FILTRO + ".novo"
        with open(temporario, "w", encoding="utf-8") as arquivo:
            json.dump(dado, arquivo, indent=2, ensure_ascii=False)
            arquivo.write("\n")
        os.chmod(temporario, 0o644)
        # Troca atomica: o filtro le este arquivo a qualquer momento e nao
        # pode pegar JSON pela metade -- ele fica no caminho do trafego.
        os.replace(temporario, ARQ_REGRAS_FILTRO)
    except OSError as erro:
        raise Recusado(f"nao consegui gravar as regras: {erro}")

    bloqueiam = sum(1 for regra in limpas if regra["acao"] == "bloquear")
    registra(f"filtro: {len(limpas)} regra(s), {bloqueiam} de bloqueio, "
             f"politica {politica}")
    return {"total": len(limpas), "bloqueiam": bloqueiam, "politica": politica}


# -------------------------------------------------------- papel: nftables

LIMITE_RULESET = 256 * 1024


def comando_nftables(argumentos):
    """O firewall como esta AGORA, com os contadores de cada regra.

    Le o ruleset do kernel, nao o arquivo que o gerou: o que vale e o que
    esta em vigor. Os contadores dizem quais regras de fato pegam trafego --
    regra que nunca contou e regra que ninguem testou.
    """
    if argumentos:
        raise Recusado("nftables nao aceita argumentos")
    if not os.path.isdir(DIR_GHOP_NFTABLES):
        raise Recusado("o papel nftables nao esta instalado nesta maquina")

    try:
        bruto = json.loads(_executa_leitura(["nft", "-j", "list", "ruleset"]))
    except ValueError as erro:
        raise Recusado(f"resposta do nft ilegivel: {erro}")

    tabelas, cadeias, regras = [], [], []
    for item in bruto.get("nftables", []):
        if "table" in item:
            t = item["table"]
            tabelas.append({"familia": t.get("family", ""), "nome": t.get("name", "")})
        elif "chain" in item:
            c = item["chain"]
            cadeias.append({
                "familia": c.get("family", ""), "tabela": c.get("table", ""),
                "nome": c.get("name", ""), "gancho": c.get("hook", ""),
                "prioridade": c.get("prio"), "politica": c.get("policy", ""),
            })
        elif "rule" in item:
            r = item["rule"]
            # O nft nao devolve a regra em texto; monta-se um resumo legivel
            # a partir das expressoes, que e o que a tela precisa mostrar.
            pacotes = bytes_ = None
            veredito = ""
            for expressao in r.get("expr", []):
                if "counter" in expressao:
                    pacotes = expressao["counter"].get("packets")
                    bytes_ = expressao["counter"].get("bytes")
                # O veredito e o que a regra FAZ, separado do que ela casa.
                # A tela desenha por ele: aceitar e barrar tem de se
                # distinguir de longe, sem ler o texto da regra.
                for nome in ("accept", "drop", "reject", "masquerade",
                             "snat", "dnat", "jump", "goto", "return", "log"):
                    if nome in expressao:
                        veredito = nome
            regras.append({
                "familia": r.get("family", ""), "tabela": r.get("table", ""),
                "cadeia": r.get("chain", ""), "posicao": r.get("handle"),
                "texto": _texto_regra(r.get("expr", []))[:200],
                "veredito": veredito,
                "pacotes": pacotes, "bytes": bytes_,
            })

    estado = {}
    try:
        with open(os.path.join(DIR_GHOP_NFTABLES, "interfaces"), encoding="utf-8") as arquivo:
            for linha in arquivo:
                if "=" in linha:
                    chave, valor = linha.strip().split("=", 1)
                    estado[chave] = valor
    except OSError:
        pass

    try:
        with open("/proc/sys/net/ipv4/ip_forward", encoding="utf-8") as arquivo:
            encaminha = arquivo.read().strip() == "1"
    except OSError:
        encaminha = False

    ativo, habilitado = _estado_unidade("ghop-nftables.service")
    fragmentos = []
    try:
        fragmentos = sorted(f for f in os.listdir("/etc/ghop/nft.d") if f.endswith(".sh"))
    except OSError:
        pass

    # O ruleset como o nft o imprime. A tabela acima e resumo; isto e o
    # texto que se le quando o resumo nao explica -- ordem das regras,
    # sintaxe exata, o que veio de fragmento. Teto porque um ruleset grande
    # nao pode virar mensagem de megabytes no canal.
    try:
        texto = _executa_leitura(["nft", "list", "ruleset"])[:LIMITE_RULESET]
    except Recusado:
        texto = ""

    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ativo": ativo,
        "habilitado": habilitado,
        "wan": estado.get("WAN_IF", ""),
        "lan": estado.get("LAN_IF", ""),
        "encaminha": encaminha,
        "fragmentos": fragmentos,
        "tabelas": tabelas,
        "cadeias": cadeias,
        "regras": regras,
        "texto": texto,
        "agora": round(time.time(), 1),
        "intervalo": INTERVALO_AMOSTRA,
        "janela": JANELA_TRAFEGO,
        "series": _serie_cadeias(),
        "painel": _le_regras_painel(),
    }


def _lado(valor):
    """Um lado de uma comparacao do nft, escrito como o nft escreveria.

    O JSON do nft e uma arvore: {"payload": {"protocol": "tcp", "field":
    "dport"}} e o que se le como 'tcp dport'. Traduzir aqui em vez de na
    tela porque quem monta a frase precisa conhecer o formato, e a tela nao
    tem por que conhecer.
    """
    if isinstance(valor, dict):
        if "payload" in valor:
            p = valor["payload"]
            return f"{p.get('protocol', '')} {p.get('field', '')}".strip()
        if "meta" in valor:
            return str(valor["meta"].get("key", ""))
        if "ct" in valor:
            return f"ct {valor['ct'].get('key', '')}".strip()
        if "set" in valor:
            return "{" + ",".join(_lado(x) for x in valor["set"]) + "}"
        if "range" in valor:
            return "-".join(_lado(x) for x in valor["range"])
        if "prefix" in valor:
            return f"{_lado(valor['prefix'].get('addr'))}/{valor['prefix'].get('len')}"
        if "name" in valor:
            return str(valor["name"])
        return " ".join(f"{k} {_lado(v)}" for k, v in list(valor.items())[:2])
    if isinstance(valor, list):
        return ",".join(_lado(x) for x in valor[:6])
    return str(valor)


def _texto_regra(expressoes):
    """A regra em uma linha legivel: 'iifname br0 tcp dport 22 accept'."""
    partes = []
    for expressao in expressoes:
        if "counter" in expressao:
            continue
        if "match" in expressao:
            comparacao = expressao["match"]
            esquerda = _lado(comparacao.get("left"))
            direita = _lado(comparacao.get("right"))
            operador = comparacao.get("op", "==")
            partes.append(f"{esquerda} {direita}" if operador == "=="
                          else f"{esquerda} {operador} {direita}")
            continue
        for chave, valor in expressao.items():
            if valor in (None, {}, "", []):
                partes.append(chave)
            else:
                partes.append(f"{chave} {_lado(valor)}")
    return " ".join(p for p in partes if p)


# ------------------------------------------------------ a maquina em si

# Sistemas de arquivo que valem espaco em disco de verdade. O resto (proc,
# sysfs, tmpfs de runtime) so poluiria a tela com numero que nao e disco.
TIPOS_DISCO = {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs",
               "vfat", "exfat", "ntfs", "ntfs3", "jfs", "reiserfs"}


def comando_sistema(argumentos):
    """O basico da maquina, mais processador, memoria e disco. Leitura pura.

    Processador e memoria vem da janela que o agente amostra em memoria --
    uso e diferenca entre duas leituras, entao nao existe "agora" sem
    historico. Disco e leitura direta: muda devagar demais para valer serie.
    """
    if argumentos:
        raise Recusado("sistema nao aceita argumentos")

    basico = {}
    try:
        basico["maquina"] = os.uname().nodename
        basico["kernel"] = os.uname().release
        basico["arquitetura"] = os.uname().machine
    except OSError:
        pass
    try:
        with open("/etc/os-release", encoding="utf-8") as arquivo:
            for linha in arquivo:
                if linha.startswith("PRETTY_NAME="):
                    basico["sistema"] = linha.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    try:
        with open("/proc/uptime", encoding="utf-8") as arquivo:
            basico["ligada_ha"] = int(float(arquivo.read().split()[0]))
    except (OSError, ValueError, IndexError):
        pass
    try:
        basico["carga"] = [round(c, 2) for c in os.getloadavg()]
    except OSError:
        pass
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as arquivo:
            for linha in arquivo:
                if linha.startswith("model name"):
                    basico["processador"] = linha.split(":", 1)[1].strip()
                    break
    except OSError:
        pass
    basico["nucleos"] = os.cpu_count()

    with _amostras_tranca:
        amostras = list(_amostras_sistema)

    nomes, serie_cpu = [], []
    for (t0, p0, _), (t1, p1, _) in zip(amostras, amostras[1:]):
        ponto = [round(t1, 1)]
        if not nomes:
            # 'total' primeiro, depois cpu0, cpu1... na ordem do numero.
            nomes = ["total"] + sorted((n for n in p1 if n != "total"),
                                       key=lambda n: int(n[3:] or 0))
        for nome in nomes:
            if nome not in p0 or nome not in p1:
                ponto.append(0.0)
                continue
            ocupado = p1[nome][0] - p0[nome][0]
            total = p1[nome][1] - p0[nome][1]
            ponto.append(round(100.0 * ocupado / total, 1) if total > 0 else 0.0)
        serie_cpu.append(ponto)

    serie_memoria = []
    for instante, _, memoria in amostras:
        ram_total, ram_usada, swap_total, swap_usada = memoria
        serie_memoria.append([
            round(instante, 1),
            round(100.0 * ram_usada / ram_total, 1) if ram_total else 0.0,
            round(100.0 * swap_usada / swap_total, 1) if swap_total else 0.0,
        ])

    memoria_agora = amostras[-1][2] if amostras else _le_memoria()
    ram_total, ram_usada, swap_total, swap_usada = memoria_agora

    discos = []
    vistos = set()
    try:
        with open("/proc/mounts", encoding="utf-8") as arquivo:
            for linha in arquivo:
                campos = linha.split()
                if len(campos) < 3 or campos[2] not in TIPOS_DISCO:
                    continue
                dispositivo, ponto = campos[0], campos[1].replace("\\040", " ")
                if dispositivo in vistos:
                    continue
                vistos.add(dispositivo)
                try:
                    estado = os.statvfs(ponto)
                except OSError:
                    continue
                total = estado.f_blocks * estado.f_frsize
                # f_bavail, nao f_bfree: o reservado para o root nao esta
                # livre para quem usa a maquina.
                livre = estado.f_bavail * estado.f_frsize
                usado = total - estado.f_bfree * estado.f_frsize
                discos.append({
                    "ponto": ponto, "dispositivo": dispositivo,
                    "tipo": campos[2], "total": total, "usado": usado,
                    "livre": livre,
                    "percentual": round(100.0 * usado / total, 1) if total else 0.0,
                })
    except OSError:
        pass

    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "agora": round(time.time(), 1),
        "intervalo": INTERVALO_AMOSTRA,
        "janela": JANELA_TRAFEGO,
        "basico": basico,
        "processadores": nomes,
        "serie_cpu": serie_cpu,
        "serie_memoria": serie_memoria,
        "memoria": {"ram_total": ram_total, "ram_usada": ram_usada,
                    "swap_total": swap_total, "swap_usada": swap_usada},
        "discos": sorted(discos, key=lambda d: d["ponto"]),
    }



# --------------------------------------- regras de firewall vindas do painel
#
# AQUI O PAINEL ESCREVE FIREWALL, e por isso este e o codigo mais desconfiado
# do arquivo. Duas decisoes carregam a seguranca:
#
# 1. O painel manda CAMPOS, nunca texto de regra. Cada campo tem um nome
#    conhecido e um formato conferido aqui; a linha do nft e montada por este
#    codigo. Aceitar 'a regra pronta' seria aceitar shell: o fragmento e um
#    script executado como root pelo ghop-nftables.
# 2. O que o painel escreve mora em /etc/ghop/nftables/regras.json (DADO) e
#    vira /etc/ghop/nft.d/painel.sh (GERADO). Nao ha caminho em que uma
#    string do painel chegue a um shell sem passar pela validacao.
#
# Uma protecao estrutural de graca: os fragmentos sao aplicados DEPOIS das
# regras base, e o nftables decide na primeira que casa. Como as regras base
# ja aceitam SSH e a faixa 7000-7100 vindos da LAN, uma regra de bloqueio
# escrita aqui nao consegue cortar o proprio canal do painel.
ARQ_REGRAS_PAINEL = "/etc/ghop/nftables/regras.json"
ARQ_FRAGMENTO_PAINEL = "/etc/ghop/nft.d/painel.sh"

FAMILIAS = ("inet", "ip", "ip6")
TIPOS_CADEIA = ("filter", "nat", "route")
GANCHOS = ("prerouting", "input", "forward", "output", "postrouting")
POLITICAS = ("accept", "drop")
VEREDITOS = ("accept", "drop", "reject", "masquerade", "counter")

FORMATO_NOME_NFT = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{0,31}$")
FORMATO_IFACE = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")
FORMATO_ENDERECO = re.compile(r"^[0-9a-fA-F:.]{1,45}(/\d{1,3})?$")
FORMATO_PORTA = re.compile(r"^\d{1,5}(-\d{1,5})?$")
FORMATO_COMENTARIO = re.compile(r"^[a-zA-Z0-9 _.:/-]{0,60}$")

# Campo aceito -> (como vira nft, formato do valor). Nada fora daqui entra.
CAMPOS_REGRA = {
    "iifname": ("iifname", FORMATO_IFACE),
    "oifname": ("oifname", FORMATO_IFACE),
    "saddr": ("ip saddr", FORMATO_ENDERECO),
    "daddr": ("ip daddr", FORMATO_ENDERECO),
    "sport": ("sport", FORMATO_PORTA),
    "dport": ("dport", FORMATO_PORTA),
}
PROTOCOLOS = ("tcp", "udp", "icmp")
ESTADOS_CT = ("new", "established", "related", "invalid")


def _le_regras_painel():
    try:
        with open(ARQ_REGRAS_PAINEL, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
    except (OSError, ValueError):
        dados = {}
    for chave in ("tabelas", "cadeias", "regras"):
        dados.setdefault(chave, [])
    return dados


def _grava_regras_painel(dados):
    os.makedirs(os.path.dirname(ARQ_REGRAS_PAINEL), exist_ok=True)
    temporario = ARQ_REGRAS_PAINEL + ".novo"
    with open(temporario, "w", encoding="utf-8") as arquivo:
        json.dump(dados, arquivo, indent=2, ensure_ascii=False)
        arquivo.write("\n")
    os.chmod(temporario, 0o644)
    os.replace(temporario, ARQ_REGRAS_PAINEL)


def _entre_aspas(valor):
    """Valor citado para o NFT, atravessando o shell inteiro.

    O fragmento e um script: escrever 'comment "x"' faz o bash comer as
    aspas e o nft receber x cru, o que quebra em qualquer valor com ':'.
    Envolver em aspas simples entrega as duplas ao nft. Os valores ja
    passaram pelas expressoes acima, entao nao ha aspas dentro deles.
    """
    return "'\"" + valor + "\"'"


def _chave_de(especie, item):
    """Como o painel nomeia uma tabela ou cadeia para poder apaga-la."""
    if especie == "tabelas":
        return f'{item["familia"]}/{item["nome"]}'
    return f'{item["familia"]}/{item["tabela"]}/{item["nome"]}'


def _linha_de_regra(regra):
    """Monta a linha do nft a partir dos campos JA validados."""
    partes = []
    if regra.get("iifname"):
        partes.append("iifname " + _entre_aspas(regra["iifname"]))
    if regra.get("oifname"):
        partes.append("oifname " + _entre_aspas(regra["oifname"]))
    if regra.get("saddr"):
        partes.append(f'ip saddr {regra["saddr"]}')
    if regra.get("daddr"):
        partes.append(f'ip daddr {regra["daddr"]}')
    protocolo = regra.get("protocolo")
    if protocolo:
        if regra.get("sport") or regra.get("dport"):
            # 'tcp dport 80' ja implica o protocolo; nao se repete 'ip protocol'.
            if regra.get("sport"):
                partes.append(f'{protocolo} sport {regra["sport"]}')
            if regra.get("dport"):
                partes.append(f'{protocolo} dport {regra["dport"]}')
        else:
            partes.append(f'meta l4proto {protocolo}')
    if regra.get("estado"):
        partes.append(f'ct state {regra["estado"]}')
    # 'counter' em toda regra, como nas regras base: sem contador nao ha como
    # saber se ela pega alguma coisa.
    partes.append("counter")
    veredito = regra.get("veredito")
    if veredito and veredito != "counter":
        partes.append(veredito)
    partes.append("comment " + _entre_aspas("ghop:" + regra["id"]))
    return " ".join(partes)


def _gera_fragmento_painel():
    """Escreve /etc/ghop/nft.d/painel.sh a partir do JSON. Nada de texto livre."""
    dados = _le_regras_painel()
    linhas = [
        "# GERADO pelo ghop-agente a partir de " + ARQ_REGRAS_PAINEL + ".",
        "# Nao edite: a proxima mudanca feita no painel sobrescreve.",
        "",
    ]
    for tabela in dados["tabelas"]:
        linhas.append(f'nft add table {tabela["familia"]} {tabela["nome"]}')
    for cadeia in dados["cadeias"]:
        if cadeia.get("gancho"):
            corpo = (f'{{ type {cadeia["tipo"]} hook {cadeia["gancho"]} '
                     f'priority {cadeia["prioridade"]}; '
                     f'policy {cadeia["politica"]}; }}')
            linhas.append(f'nft add chain {cadeia["familia"]} {cadeia["tabela"]} '
                          f'{cadeia["nome"]} \'{corpo}\'')
        else:
            # Cadeia sem gancho: so e percorrida por quem saltar para ela.
            linhas.append(f'nft add chain {cadeia["familia"]} {cadeia["tabela"]} '
                          f'{cadeia["nome"]}')
    for regra in dados["regras"]:
        linhas.append(f'nft add rule {regra["familia"]} {regra["tabela"]} '
                      f'{regra["cadeia"]} {_linha_de_regra(regra)}')
    os.makedirs(os.path.dirname(ARQ_FRAGMENTO_PAINEL), exist_ok=True)
    temporario = ARQ_FRAGMENTO_PAINEL + ".novo"
    with open(temporario, "w", encoding="utf-8") as arquivo:
        arquivo.write("\n".join(linhas) + "\n")
    os.chmod(temporario, 0o755)
    os.replace(temporario, ARQ_FRAGMENTO_PAINEL)


def _aplica_firewall():
    """Reaplica o ruleset inteiro: base + fragmentos, na ordem de sempre."""
    try:
        _executa_leitura(["systemctl", "restart", "ghop-nftables.service"], tempo=30)
    except Recusado as erro:
        raise Recusado(f"regras gravadas, mas o firewall nao recarregou: {erro}")


def _confere(valor, formato, campo):
    if not isinstance(valor, str) or not formato.match(valor):
        raise Recusado(f"{campo} invalido: {valor!r}")
    return valor


def comando_firewall(argumentos):
    """Cria e apaga tabela, cadeia e regra ESCRITAS PELO PAINEL. ESCREVE.

    So mexe no que o painel criou. As regras base e os fragmentos dos outros
    papeis (a 53 do dns, a 67 do dhcp) nao sao tocados daqui: quem manda
    neles e o instalador de cada papel, e mistura-los aqui faria duas mãos
    escreverem o mesmo arquivo.
    """
    acao = argumentos.get("acao")
    if not os.path.isdir(os.path.dirname(ARQ_REGRAS_PAINEL)):
        raise Recusado("o papel nftables nao esta instalado nesta maquina")
    dados = _le_regras_painel()

    if acao == "tabela":
        familia = argumentos.get("familia", "inet")
        if familia not in FAMILIAS:
            raise Recusado(f"familia {familia!r} desconhecida ({', '.join(FAMILIAS)})")
        nome = _confere(argumentos.get("nome"), FORMATO_NOME_NFT, "nome")
        if any(t["familia"] == familia and t["nome"] == nome for t in dados["tabelas"]):
            raise Recusado(f"a tabela {familia} {nome} ja existe aqui")
        dados["tabelas"].append({"familia": familia, "nome": nome})

    elif acao == "cadeia":
        familia = argumentos.get("familia", "inet")
        if familia not in FAMILIAS:
            raise Recusado(f"familia {familia!r} desconhecida")
        tabela = _confere(argumentos.get("tabela"), FORMATO_NOME_NFT, "tabela")
        nome = _confere(argumentos.get("nome"), FORMATO_NOME_NFT, "nome")
        gancho = argumentos.get("gancho") or ""
        if gancho and gancho not in GANCHOS:
            raise Recusado(f"gancho {gancho!r} desconhecido ({', '.join(GANCHOS)})")
        tipo = argumentos.get("tipo", "filter")
        if tipo not in TIPOS_CADEIA:
            raise Recusado(f"tipo {tipo!r} desconhecido")
        politica = argumentos.get("politica", "accept")
        if politica not in POLITICAS:
            raise Recusado(f"politica {politica!r} desconhecida")
        try:
            prioridade = int(argumentos.get("prioridade", 0))
        except (TypeError, ValueError):
            raise Recusado("prioridade deve ser inteiro")
        if any(c["familia"] == familia and c["tabela"] == tabela and c["nome"] == nome
               for c in dados["cadeias"]):
            raise Recusado(f"a cadeia {nome} ja existe em {tabela}")
        dados["cadeias"].append({
            "familia": familia, "tabela": tabela, "nome": nome, "tipo": tipo,
            "gancho": gancho, "prioridade": prioridade, "politica": politica})

    elif acao == "regra":
        familia = argumentos.get("familia", "inet")
        if familia not in FAMILIAS:
            raise Recusado(f"familia {familia!r} desconhecida")
        regra = {
            "id": f"{int(time.time()):x}{len(dados['regras']):02x}",
            "familia": familia,
            "tabela": _confere(argumentos.get("tabela"), FORMATO_NOME_NFT, "tabela"),
            "cadeia": _confere(argumentos.get("cadeia"), FORMATO_NOME_NFT, "cadeia"),
        }
        for campo, (_, formato) in CAMPOS_REGRA.items():
            valor = argumentos.get(campo)
            if valor:
                regra[campo] = _confere(valor, formato, campo)
        protocolo = argumentos.get("protocolo")
        if protocolo:
            if protocolo not in PROTOCOLOS:
                raise Recusado(f"protocolo {protocolo!r} desconhecido")
            regra["protocolo"] = protocolo
        if (regra.get("sport") or regra.get("dport")) and not regra.get("protocolo"):
            raise Recusado("porta exige protocolo (tcp ou udp)")
        estado = argumentos.get("estado")
        if estado:
            partes = [e.strip() for e in estado.split(",")]
            if any(e not in ESTADOS_CT for e in partes):
                raise Recusado(f"estado deve ser: {', '.join(ESTADOS_CT)}")
            regra["estado"] = ",".join(partes)
        veredito = argumentos.get("veredito", "accept")
        if veredito not in VEREDITOS:
            raise Recusado(f"veredito {veredito!r} desconhecido ({', '.join(VEREDITOS)})")
        regra["veredito"] = veredito
        regra["nota"] = _confere(argumentos.get("nota", ""), FORMATO_COMENTARIO, "nota")
        if len(regra) <= 6:
            raise Recusado("regra sem nenhuma condicao: informe ao menos um campo")
        dados["regras"].append(regra)

    elif acao == "remover":
        especie = argumentos.get("especie")
        if especie not in ("tabelas", "cadeias", "regras"):
            raise Recusado("especie deve ser tabelas, cadeias ou regras")
        chave = argumentos.get("id")
        antes = len(dados[especie])
        if especie == "regras":
            dados["regras"] = [r for r in dados["regras"] if r["id"] != chave]
        else:
            # A chave de tabela e 'familia/nome'; a de cadeia,
            # 'familia/tabela/nome'. Montar as duas com o mesmo f-string
            # deixava 'inet//painel' na tabela, e nada casava.
            dados[especie] = [x for x in dados[especie]
                              if _chave_de(especie, x) != chave]
        if len(dados[especie]) == antes:
            raise Recusado(f"nao achei {chave!r} em {especie}")
        # Apagar do JSON nao apaga do kernel: o ruleset e reescrito inteiro
        # ao reaplicar, e e isso que faz a remocao valer.

    else:
        raise Recusado(
            f"acao {acao!r} desconhecida (tabela, cadeia, regra, remover)")

    _grava_regras_painel(dados)
    _gera_fragmento_painel()
    _aplica_firewall()
    registra(f"firewall: {acao}")
    return {"acao": acao, "tabelas": len(dados["tabelas"]),
            "cadeias": len(dados["cadeias"]), "regras": len(dados["regras"])}


# --------------------------------------------------- acao sobre um papel
#
# AQUI O AGENTE DEIXA DE SO LER. E o primeiro comando que muda a maquina, e
# por isso e o mais amarrado do arquivo:
#
#   - o papel vem de uma TABELA fixa, e o script e o que a tabela diz. Nada
#     do painel entra no caminho do arquivo nem na linha de comando;
#   - a acao vem de uma lista de quatro, traduzida aqui para o subcomando;
#   - o repositorio precisa ser de root e nao gravavel por mais ninguem,
#     senao qualquer usuario local escreveria o script que o agente (root)
#     vai rodar -- seria escalar privilegio de graca;
#   - 'lojmIt' e 'agente' NAO entram: parar o lojmIt derruba rota, NAT e
#     firewall da rede inteira, e parar o agente corta o canal por onde a
#     ordem chegou. Quem quiser mexer nesses dois vai ate a maquina.
#
# A acao roda destacada, por systemd-run, e o comando responde na hora: uma
# instalacao demora minutos (apt), e prender a conexao ate o fim seria pedir
# para o painel travar. O acompanhamento e pelo comando 'acao'.
DIR_REPO = os.environ.get("GHOP_REPO", "/opt/ghop")
ARQ_ACAO = "/var/ghop/acao.json"
ARQ_ACAO_LOG = "/var/ghop/acao.log"
UNIDADE_ACAO = "ghop-acao"

GERENCIAVEIS = {
    "coletor": "projects/ghop-request/requests.sh",
    "nftables": "projects/ghop-nftables/nftables.sh",
    "dns": "projects/ghop-dns/dns.sh",
    "wifi": "projects/ghop-wifi/wifi.sh",
    "dhcp": "projects/ghop-dhcp/dhcp.sh",
    "filtro": "projects/ghop-filtro/filtro.sh",
    "balanceador": "projects/ghop-balanceador/balanceador.sh",
}

# GERENCIAVEIS ⊆ PAPEIS: comando_papel le PAPEIS[papel] para decidir a trava
# do desinstalar. Papel acrescentado num dicionario e esquecido no outro
# passaria pela trava calado -- e o tipo de divergencia que o CLAUDE.md
# chama de "armadilha dos oito lugares". Melhor nao subir.
if not set(GERENCIAVEIS) <= set(PAPEIS):
    raise SystemExit(
        "ghop-agente: papel gerenciavel sem entrada em PAPEIS: "
        + ", ".join(sorted(set(GERENCIAVEIS) - set(PAPEIS))))

# O que o painel pede -> o que o script do papel entende.
ACOES = {
    "instalar": "--sim",
    "iniciar": "ligar",
    "parar": "desligar",
    "desinstalar": "desinstalar",
}


def _confere_repositorio(caminho):
    """Recusa repositorio que nao seja de root ou que outros possam escrever.

    O agente roda como root e vai executar o que estiver ali. Se um usuario
    comum puder editar o script, ele manda no root da maquina -- e o GHop
    teria aberto o buraco que existe para vigiar.
    """
    atual = os.path.abspath(caminho)
    while True:
        try:
            estado = os.stat(atual)
        except OSError as erro:
            raise Recusado(f"nao consegui olhar {atual}: {erro}")
        if estado.st_uid != 0:
            raise Recusado(
                f"{atual} nao pertence ao root; o agente nao roda script de "
                "diretorio que outro usuario controla")
        if estado.st_mode & 0o022:
            raise Recusado(
                f"{atual} e gravavel por grupo ou por outros; ajuste para 755 "
                "antes de mandar acao")
        if atual == "/":
            return
        atual = os.path.dirname(atual)


def comando_papel(argumentos):
    """Instala, inicia, para ou desinstala um papel DESTA maquina.

    Devolve assim que a acao comeca; o resultado se acompanha com 'acao'.
    """
    papel = argumentos.get("papel")
    acao = argumentos.get("acao")
    if sobra := set(argumentos) - {"papel", "acao"}:
        raise Recusado(f"argumento desconhecido: {sorted(sobra)}")
    if papel not in GERENCIAVEIS:
        raise Recusado(
            f"papel {papel!r} nao pode ser gerenciado daqui. "
            f"Ha: {', '.join(sorted(GERENCIAVEIS))}")
    if acao not in ACOES:
        raise Recusado(f"acao {acao!r} desconhecida. Ha: {', '.join(ACOES)}")

    # Desinstalar so desfaz o que FOMOS NOS que fizemos, e a trava vale nos
    # papeis que o agente reconhece SEM instalacao nossa ('basta_a_unidade'):
    # so nesses o servico pode ser de outra pessoa. Nos demais a ausencia da
    # marca e outra coisa -- unidade orfa que alguem precisa poder limpar --
    # e dizer "nao e nosso" ali seria mentira.
    definicao = PAPEIS[papel]  # GERENCIAVEIS esta contido em PAPEIS (ver abaixo)
    if (acao == "desinstalar" and definicao.get("basta_a_unidade")
            and not os.path.exists(definicao["marca"])):
        raise Recusado(
            f"{papel} nao foi instalado pelo GHop nesta maquina "
            f"({definicao['marca']} nao existe): desinstalar mexeria em "
            "configuracao que nao e nossa. Para desligar o servico use 'parar'.")

    _confere_repositorio(DIR_REPO)
    script = os.path.join(DIR_REPO, GERENCIAVEIS[papel])
    if not os.path.isfile(script):
        raise Recusado(f"{script} nao existe nesta maquina")

    # Uma acao por vez: sao instaladores mexendo nos mesmos arquivos, e duas
    # ao mesmo tempo dariam um estado que ninguem sabe explicar depois.
    if _estado_unidade(UNIDADE_ACAO + ".service")[0] in ("activating", "active"):
        raise Recusado("ja ha uma acao em andamento nesta maquina")

    subprocess.run(["systemctl", "reset-failed", UNIDADE_ACAO + ".service"],
                   capture_output=True, timeout=10)
    inicio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        os.makedirs(os.path.dirname(ARQ_ACAO), exist_ok=True)
        with open(ARQ_ACAO, "w", encoding="utf-8") as arquivo:
            json.dump({"papel": papel, "acao": acao, "quando": inicio,
                       "script": script}, arquivo)
        # O log comeca do zero a cada acao. A unidade grava com 'append', e
        # sem truncar aqui a tela mostrava a saida da acao ANTERIOR em cima
        # da atual -- que e o pior tipo de engano: dado certo, contexto errado.
        with open(ARQ_ACAO_LOG, "w", encoding="utf-8") as arquivo:
            arquivo.write(f"=== {acao} de {papel} em {inicio} ===\n")
        _executa_leitura([
            "systemd-run", f"--unit={UNIDADE_ACAO}", "--collect",
            "--property=StandardOutput=append:" + ARQ_ACAO_LOG,
            "--property=StandardError=append:" + ARQ_ACAO_LOG,
            "/bin/bash", script, ACOES[acao],
        ], tempo=20)
    except OSError as erro:
        raise Recusado(f"nao consegui iniciar a acao: {erro}")

    registra(f"acao '{acao}' no papel '{papel}' iniciada")
    return {"papel": papel, "acao": acao, "quando": inicio, "iniciada": True}


def comando_acao(argumentos):
    """Como esta (ou como terminou) a ultima acao pedida. Leitura pura."""
    if argumentos:
        raise Recusado("acao nao aceita argumentos")

    ultima = {}
    try:
        with open(ARQ_ACAO, encoding="utf-8") as arquivo:
            ultima = json.load(arquivo)
    except (OSError, ValueError):
        pass

    saida = ""
    try:
        with open(ARQ_ACAO_LOG, encoding="utf-8", errors="replace") as arquivo:
            saida = "".join(arquivo.readlines()[-200:])
    except OSError:
        pass

    ativo, _ = _estado_unidade(UNIDADE_ACAO + ".service")
    resultado = ""
    try:
        resultado = _executa_leitura(
            ["systemctl", "show", UNIDADE_ACAO + ".service", "-p", "Result",
             "--value"]).strip()
    except Recusado:
        pass

    return {
        "quando": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ultima": ultima,
        "andando": ativo in ("activating", "active"),
        "resultado": resultado,
        "saida": saida,
    }


# O conjunto fechado. Acrescentar aqui e uma decisao de arquitetura, nao um
# detalhe: cada comando novo amplia o que o painel pode mandar fazer.

# ----------------------------------------------------- papel: balanceador

DIR_GHOP_BALANCEADOR = "/etc/ghop/balanceador"
ARQ_REGRAS_BALANCEADOR = os.path.join(DIR_GHOP_BALANCEADOR, "regras.json")
# O gerador e NOSSO programa, em caminho fixo, chamado sem um argumento que
# venha do painel. Ler o estado por ele, e nao reimplementando a leitura
# aqui, e o que impede as duas pontas de divergirem sobre o que e "placa
# ativa" -- a conta de carrier e gateway mora num lugar so.
ARQ_GERADOR_BALANCEADOR = "/usr/local/sbin/ghop-balanceador.py"
UNIDADE_BALANCEADOR = "ghop-balanceador.service"
UNIDADE_FIREWALL = "ghop-nftables.service"

ALGORITMOS_BALANCEADOR = ("rodizio", "afinidade")
# "origem" casa quem PEDIU (ip saddr), e e como se prende uma maquina a
# uma placa. Os outros dois casam para onde vai.
TIPOS_REGRA_BALANCEADOR = ("cidr", "exato", "origem")
LIMITE_REGRAS_BALANCEADOR = 500
PESO_MAXIMO_BALANCEADOR = 32
# Nome de PLACA, que e tudo o que o painel conhece de uma saida. Interface e
# gateway sao fato da maquina e vivem em /etc/ghop/balanceador/placas: aceita-los
# do painel seria aceitar shell por outro caminho, porque interface entra em
# regra de nft e em linha de comando do 'ip'.
FORMATO_PLACA = re.compile(r"^[a-z][a-z0-9_]{0,15}$")


def comando_balanceador(argumentos):
    """Placas de saida, pesos, algoritmo e as listas em vigor.

    Quem responde de verdade e o gerador ('--estado'), porque e ele que sabe
    o que conta como placa ativa: carrier de pe E gateway conhecido. Duplicar
    essa conta aqui daria duas respostas diferentes para a mesma pergunta no
    dia em que uma das duas mudasse.
    """
    if argumentos:
        raise Recusado("balanceador nao aceita argumentos")
    _exige_papel("balanceador")

    ativo, habilitado = _estado_unidade(UNIDADE_BALANCEADOR)
    estado = {}
    erro = ""
    try:
        resultado = subprocess.run([ARQ_GERADOR_BALANCEADOR, "--estado"],
                                   capture_output=True, text=True, timeout=10)
        if resultado.returncode == 0:
            estado = json.loads(resultado.stdout)
        else:
            erro = resultado.stderr.strip()[:500]
    except (OSError, ValueError, subprocess.SubprocessError) as falha:
        erro = str(falha)[:500]

    return {
        "ativo": ativo,
        "habilitado": habilitado,
        "algoritmo": estado.get("algoritmo", ""),
        "lan": estado.get("lan", ""),
        "sorteio": estado.get("sorteio", False),
        "slots_total": estado.get("slots_total", 0),
        "placas": estado.get("placas", []),
        "regras": estado.get("regras", []),
        "descartadas": estado.get("descartadas", 0),
        "regras_quebradas": estado.get("regras_quebradas", False),
        "erro": erro,
    }


def comando_rotear(argumentos):
    """Grava as listas, os pesos e o algoritmo do balanceador. ESCREVE.

    Estado inteiro, nao delta -- molde do 'filtrar', e pelo mesmo motivo: nao
    ha outra fonte de regra nesta maquina, entao mandar tudo nao apaga o que
    veio de outro lugar, e painel que perdeu uma mensagem nao deixa destino
    preso a uma placa para sempre.

    CAMPOS, nunca texto de regra nem nome de interface: placa (pelo NOME),
    tipo, valor e nota. O que sai daqui e DADO em JSON; quem o transforma em
    regra de nft e o gerador, que confere tudo outra vez.

    Reaplicar e preciso, ao contrario do filtro: o que vale no kernel e o
    fragmento gerado, nao o arquivo. Conexao em curso nao se perde nisso --
    cada uma guarda a placa escolhida na propria marca de conntrack.
    """
    algoritmo = argumentos.get("algoritmo", "rodizio")
    placas = argumentos.get("placas")
    regras = argumentos.get("regras")
    if sobra := set(argumentos) - {"algoritmo", "placas", "regras"}:
        raise Recusado(f"argumento desconhecido: {sorted(sobra)}")
    if not os.path.isdir(DIR_GHOP_BALANCEADOR):
        raise Recusado("o papel balanceador nao esta instalado nesta maquina")
    if algoritmo not in ALGORITMOS_BALANCEADOR:
        raise Recusado(f"algoritmo deve ser um de {ALGORITMOS_BALANCEADOR}")
    if not isinstance(placas, list) or not isinstance(regras, list):
        raise Recusado("placas e regras devem ser listas")
    if len(regras) > LIMITE_REGRAS_BALANCEADOR:
        raise Recusado(f"no maximo {LIMITE_REGRAS_BALANCEADOR} regras")

    pesos = []
    for bruta in placas:
        if not isinstance(bruta, dict):
            raise Recusado("cada placa deve ser um objeto")
        if sobra := set(bruta) - {"nome", "peso"}:
            raise Recusado(f"campo desconhecido em placa: {sorted(sobra)}")
        nome = bruta.get("nome")
        if not isinstance(nome, str) or not FORMATO_PLACA.match(nome):
            raise Recusado(f"nome de placa invalido: {nome!r}")
        try:
            peso = int(bruta.get("peso", 1))
        except (TypeError, ValueError):
            raise Recusado(f"peso de '{nome}' nao e numero")
        if not 1 <= peso <= PESO_MAXIMO_BALANCEADOR:
            raise Recusado(f"peso de '{nome}' fora de 1..{PESO_MAXIMO_BALANCEADOR}")
        pesos.append({"nome": nome, "peso": peso})

    limpas = []
    for bruta in regras:
        if not isinstance(bruta, dict):
            raise Recusado("cada regra deve ser um objeto")
        if sobra := set(bruta) - {"placa", "tipo", "valor", "nota"}:
            raise Recusado(f"campo desconhecido em regra: {sorted(sobra)}")
        placa, tipo = bruta.get("placa"), bruta.get("tipo", "cidr")
        valor, nota = bruta.get("valor"), bruta.get("nota") or ""
        if not isinstance(placa, str) or not FORMATO_PLACA.match(placa):
            raise Recusado(f"nome de placa invalido em regra: {placa!r}")
        if tipo not in TIPOS_REGRA_BALANCEADOR:
            raise Recusado(f"tipo deve ser um de {TIPOS_REGRA_BALANCEADOR}")
        if not isinstance(valor, str) or not isinstance(nota, str):
            raise Recusado("valor e nota devem ser texto")
        if len(nota) > 200:
            raise Recusado("nota longa demais (200 caracteres)")
        valor = _destino_balanceador(tipo, valor.strip())
        limpas.append({"placa": placa, "tipo": tipo, "valor": valor,
                       "nota": nota})

    dado = {
        "versao": 1,
        "algoritmo": algoritmo,
        "atualizado": time.strftime("%Y-%m-%d %H:%M:%S"),
        "placas": pesos,
        "regras": limpas,
    }
    try:
        temporario = ARQ_REGRAS_BALANCEADOR + ".novo"
        with open(temporario, "w", encoding="utf-8") as arquivo:
            json.dump(dado, arquivo, indent=2, ensure_ascii=False)
            arquivo.write("\n")
        os.chmod(temporario, 0o644)
        os.replace(temporario, ARQ_REGRAS_BALANCEADOR)
    except OSError as falha:
        raise Recusado(f"nao consegui gravar as regras: {falha}")

    # Caminhos FIXOS, nada do painel aqui. Primeiro o gerador reescreve o
    # fragmento e as rotas, depois o firewall o aplica -- nesta ordem, senao
    # o firewall aplicaria o fragmento velho.
    aplicou, aviso = True, ""
    for comando in ([ARQ_GERADOR_BALANCEADOR, "--aplicar"],
                    ["systemctl", "restart", UNIDADE_FIREWALL]):
        try:
            resultado = subprocess.run(comando, capture_output=True,
                                       text=True, timeout=60)
            if resultado.returncode != 0:
                aplicou = False
                aviso = resultado.stderr.strip()[:500]
                break
        except (OSError, subprocess.SubprocessError) as falha:
            aplicou, aviso = False, str(falha)[:500]
            break

    registra(f"balanceador: {len(limpas)} regra(s), {len(pesos)} peso(s), "
             f"algoritmo {algoritmo}, aplicou={aplicou}")
    return {"total": len(limpas), "placas": len(pesos),
            "algoritmo": algoritmo, "aplicou": aplicou, "aviso": aviso}


def _destino_balanceador(tipo, valor):
    """'198.51.100.0/24' ou '198.51.100.7'. Recusa o que nao for isso.

    Nao se usa ipaddress de proposito, como no gerador: aceitar '10' como
    10.0.0.0 transformaria erro de digitacao em regra larga, que aqui quer
    dizer uma /8 inteira presa a uma placa.
    """
    def octetos(texto):
        partes = texto.split(".")
        if len(partes) != 4:
            return False
        for parte in partes:
            if not parte.isdigit() or not 0 <= int(parte) <= 255:
                return False
            if len(parte) > 1 and parte[0] == "0":
                return False
        return True

    if tipo == "exato" or (tipo == "origem" and "/" not in valor):
        if not octetos(valor):
            raise Recusado(f"valor invalido: {valor!r} (IPv4)")
        return valor
    endereco, barra, prefixo = valor.partition("/")
    if not barra or not octetos(endereco) or not prefixo.isdigit():
        raise Recusado(f"valor invalido: {valor!r} (CIDR, ex. 198.51.100.0/24)")
    if not 0 <= int(prefixo) <= 32:
        raise Recusado(f"prefixo fora de 0..32: {valor!r}")
    return f"{endereco}/{int(prefixo)}"


COMANDOS = {
    "resumo": comando_resumo,
    "monitorar": comando_monitorar,
    "eventos": comando_eventos,
    "interfaces": comando_interfaces,
    "rotas": comando_rotas,
    "vizinhos": comando_vizinhos,
    "conexoes": comando_conexoes,
    "trafego": comando_trafego,
    "papeis": comando_papeis,
    "dhcp": comando_dhcp,
    "dns": comando_dns,
    "wifi": comando_wifi,
    "nftables": comando_nftables,
    "filtro": comando_filtro,
    "filtrar": comando_filtrar,
    "balanceador": comando_balanceador,
    "rotear": comando_rotear,
    "sistema": comando_sistema,
    "firewall": comando_firewall,
    "papel": comando_papel,
    "acao": comando_acao,
    "listas": comando_listas,
    "lista": comando_lista,
    "limpar": comando_limpar,
}


def responde(pedido):
    """Traduz um pedido ja decodificado na resposta correspondente."""
    if not isinstance(pedido, dict):
        return {"id": None, "ok": False, "erro": "pedido deve ser um objeto"}

    identificador = pedido.get("id")
    if not isinstance(identificador, (str, int, type(None))):
        identificador = None

    nome = pedido.get("comando")
    funcao = COMANDOS.get(nome) if isinstance(nome, str) else None
    if funcao is None:
        # Nao diz quais existem: quem tem certificado de painel ja sabe.
        return {"id": identificador, "ok": False, "erro": f"comando desconhecido: {nome!r}"}

    argumentos = pedido.get("argumentos") or {}
    if not isinstance(argumentos, dict):
        return {"id": identificador, "ok": False, "erro": "argumentos deve ser um objeto"}

    try:
        return {"id": identificador, "ok": True, "dados": funcao(argumentos)}
    except Recusado as erro:
        return {"id": identificador, "ok": False, "erro": str(erro)}
    except Exception as erro:  # noqa: BLE001 - agente nao cai por causa de um pedido
        registra(f"erro inesperado em {nome!r}: {type(erro).__name__}")
        return {"id": identificador, "ok": False, "erro": "erro interno"}


def atende(tls, painel):
    """Serve um painel ja autenticado, uma mensagem por linha, ate o fim."""
    fluxo = tls.makefile("rwb")
    while True:
        linha = fluxo.readline(LIMITE_LINHA)
        if not linha:
            return
        if not linha.endswith(b"\n"):
            # Ou a linha estourou o teto, ou a conexao morreu no meio.
            registra(f"{painel}: linha longa demais ou truncada, encerrando")
            return
        try:
            pedido = json.loads(linha.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            resposta = {"id": None, "ok": False, "erro": "JSON invalido"}
        else:
            resposta = responde(pedido)
            registra(f"{painel}: {pedido.get('comando')!r} ok={resposta['ok']}")
        fluxo.write(json.dumps(resposta).encode("utf-8") + b"\n")
        fluxo.flush()


def conversa(bruto, endereco, contexto):
    """Faz o handshake, confere quem e, e so entao atende."""
    painel = None
    try:
        bruto.settimeout(TEMPO_LIMITE)
        with contexto.wrap_socket(bruto, server_side=True) as tls:
            painel = nome_comum(tls.getpeercert())
            # A CA ja garantiu que o certificado e legitimo; falta garantir
            # que e de PAINEL. Certificado de agente e emitido pela mesma CA.
            if not painel or not painel.startswith(PREFIXO_PAINEL):
                registra(f"recusado: CN {painel!r} nao e de painel")
                return
            registra(f"{painel}: conectado de {endereco[0]}")
            atende(tls, painel)
    except ssl.SSLError as erro:
        registra(f"handshake recusado de {endereco[0]}: {str(erro)[:80]}")
    except (socket.timeout, TimeoutError):
        registra(f"{painel or endereco[0]}: tempo esgotado")
    except OSError as erro:
        registra(f"{painel or endereco[0]}: conexao perdida ({erro})")
    finally:
        try:
            bruto.close()
        except OSError:
            pass


def monta_contexto():
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Os dois lados sao nossos e falam Python moderno: nao ha por que aceitar
    # menos que TLS 1.3.
    contexto.minimum_version = ssl.TLSVersion.TLSv1_3
    contexto.load_cert_chain(ARQ_CERT, ARQ_CHAVE)
    contexto.load_verify_locations(ARQ_CA)
    # Sem certificado nao se fala com o agente. E o ponto do mTLS.
    contexto.verify_mode = ssl.CERT_REQUIRED
    return contexto


def main():
    for arquivo in (ARQ_CERT, ARQ_CHAVE, ARQ_CA):
        if not os.path.exists(arquivo):
            registra(f"faltando {arquivo}. Emita na maquina do operador e traga"
                     " presencialmente -- nunca pela rede.")
            return 1

    try:
        contexto = monta_contexto()
    except ssl.SSLError as erro:
        registra(f"certificado ou chave invalidos: {erro}")
        return 1

    escuta = socket.socket()
    escuta.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    escuta.bind((ESCUTA, PORTA))
    escuta.listen(16)
    registra(f"escutando em {ESCUTA}:{PORTA}, comandos: {sorted(COMANDOS)}")

    encerrando = threading.Event()

    def para(*_):
        encerrando.set()
        # Fecha a escuta para tirar o accept() do bloqueio.
        try:
            escuta.close()
        except OSError:
            pass

    signal.signal(signal.SIGTERM, para)
    signal.signal(signal.SIGINT, para)

    # O amostrador de trafego nasce com o agente: e o que faz 'trafego' ter
    # historico quando o painel abrir a tela, e nao so a partir dali.
    threading.Thread(target=amostra_trafego, args=(encerrando,), daemon=True).start()

    while not encerrando.is_set():
        try:
            bruto, endereco = escuta.accept()
        except OSError:
            break
        # Uma thread por painel: um cliente lento nao pode calar o agente.
        threading.Thread(
            target=conversa, args=(bruto, endereco, contexto), daemon=True
        ).start()

    registra("encerrado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
