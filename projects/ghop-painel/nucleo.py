"""Nucleo do painel do GHop: cadastro dos nos e canal mTLS com os agentes.

SEM Qt, de proposito. Aqui mora o que o painel *faz*; a interface e casca
descartavel por cima -- hoje uma CLI (ghop-painel.py), amanha PySide6. Nada
neste arquivo imprime, pergunta ou encerra o processo: erro vira ErroGHop, e
quem tem tela decide como mostrar.

Duas consequencias praticas para quem escrever a casca Qt:

  - Toda chamada que fala com um agente BLOQUEIA (conexao, handshake,
    resposta). Chame fora da thread de UI, senao a janela congela.
  - A senha da chave do painel entra uma vez, no construtor. O nucleo nao
    pergunta nada a ninguem.

A chave primaria de um no e o NOME, nunca o endereco: com NAT aninhado o mesmo
IP privado existe em lugares diferentes, e endereco muda sem avisar. Por isso
toda conexao confere o CN do certificado contra o nome pedido antes de mandar
qualquer comando, e recadastrar o mesmo nome so troca o endereco.
"""

import glob
import ipaddress
import json
import os
import re
import socket
import ssl
import urllib.parse

DIR_CA = os.environ.get("GHOP_CA_DIR", os.path.expanduser("~/.ghop/ca"))
DIR_EMITIDOS = os.path.join(DIR_CA, "emitidos")
ARQ_CA = os.path.join(DIR_CA, "ca.crt")
ARQ_NOS = os.path.join(os.path.expanduser("~/.ghop"), "nos.json")

PREFIXO_AGENTE = "ghop-agente-"
PREFIXO_PAINEL = "ghop-painel-"
PORTA_PADRAO = 7000
TEMPO_LIMITE = 30
LIMITE_LINHA = 8 * 1024 * 1024

# Mesma regra do ca.sh: o nome vira parte do CN e nome de arquivo.
FORMATO_NOME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")

# O conjunto e fechado, e a casca nao inventa comando: ela oferece o que
# estiver aqui. Acrescentar e decisao de arquitetura -- ver docs/arquitetura.md.
#
# Esta e a lista do que o AGENTE de fato implementa hoje. Nao confundir com as
# visoes abaixo: visao e o que a tela mostra, comando e o que existe do outro
# lado. Visao cujo comando nao esta aqui simplesmente ainda nao funciona.
COMANDOS = ("resumo", "monitorar", "eventos", "interfaces", "rotas", "vizinhos",
            "conexoes", "trafego", "papeis", "dhcp", "dns", "wifi", "nftables",
            "filtro", "sistema", "papel", "acao", "listas", "lista", "firewall",
            "filtrar", "limpar")

# Papeis do GHop que rendem uma TELA propria, e o comando que a alimenta. O
# agente diz quais existem naquela maquina ('papeis'); a casca so desenha o
# que estiver nesta tabela E vier na resposta -- papel novo no agente sem
# entrada aqui nao ganha tela, em vez de quebrar a que existe.
#
# Nao confundir com a LISTA de papeis: 'papeis()' devolve tudo o que o agente
# reportar, inclusive coletor e lojmIt, que nao tem tela. Quem pergunta "o
# que existe nesta maquina" (a tela Servicos) precisa da lista inteira.
#
# 'visao': a tela e inteira, no nivel de 'Dados', em vez de aba dentro dela.
# 'antes': onde ela entra, em ordem de preferencia -- o primeiro nome que
# EXISTIR naquele tipo de no ganha. E uma lista porque 'saida' so existe em
# no do tipo lojmIt; num webserver a analise se chama 'servico', e sem o
# segundo candidato as visoes de papel caiam todas no fim da fileira.
PAPEIS = {
    # Tela cheia, como Roteamento e DNS: quem entrega endereco na rede manda
    # em quem fala com quem, e a lista de concessoes cresce. Aparece em todo
    # no que TENHA isc-dhcp-server, instalado por nos ou nao -- o agente
    # reconhece o servico pela unidade e diz de onde ele veio em 'origem'.
    "dhcp": {"rotulo": "DHCP", "comando": "dhcp",
             "descricao": "Quem recebeu endereco nesta rede, e o que o DHCP entrega.",
             "visao": True, "antes": ("saida", "servico")},
    # Como o Roteamento, o DNS rende tela cheia: sao dois assuntos (este
    # resolvedor e o servidor de cima) e uma lista que cresce.
    "dns": {"rotulo": "DNS", "comando": "dns",
            "descricao": "O resolvedor da LAN, o servidor de cima e o que foi negado.",
            "visao": True, "antes": ("saida", "servico")},
    "wifi": {"rotulo": "Wi-Fi", "comando": "wifi",
             "descricao": "O radio, a rede que ele anuncia e quem esta associado."},
    # Este nao rende aba dentro de 'Dados': rende uma VISAO inteira, no
    # mesmo nivel de 'Dados' e 'Analise de saida'. 'antes' diz onde ela
    # entra quando o no tiver o papel -- firewall e assunto de tela cheia,
    # nao de aba escondida.
    "nftables": {"rotulo": "Roteamento", "comando": "nftables",
                 "descricao": "O firewall em vigor: tabelas, cadeias, regras e contadores.",
                 "visao": True, "antes": ("saida", "servico")},
    # Tela cheia como o Roteamento, e pelo mesmo motivo: sao regras
    # ordenadas, que o operador escreve e reordena, mais o que elas
    # pegaram. Aba escondida nao serve para o que se edita.
    "filtro": {"rotulo": "Filtro", "comando": "filtro",
               "descricao": "O que a LAN pode alcancar por nome (SNI e Host), e o que foi negado.",
               "visao": True, "antes": ("saida", "servico")},
}

# Os que ESCREVEM no agente; todo o resto de COMANDOS e leitura. Ficam
# anotados aqui porque a distincao importa na hora de acrescentar o proximo:
# comando de leitura e barato de aceitar, comando de escrita amplia o que o
# painel pode causar.
COMANDOS_ESCREVEM = ("monitorar", "papel", "lista", "firewall", "filtrar",
                     "limpar")

# As acoes que o painel pode pedir sobre um papel, com o aviso que a tela tem
# de mostrar ANTES de mandar. O texto nao e enfeite: 'parar' e 'desinstalar'
# mexem em rede alheia, e quem clica precisa saber o que cai junto.
ACOES_PAPEL = {
    "instalar": {
        "rotulo": "Instalar",
        "aviso": "Instala e liga o papel nesta maquina. Pode demorar minutos "
                 "(apt) e mexe na configuracao dela.",
    },
    "iniciar": {
        "rotulo": "Iniciar",
        "aviso": "Liga o servico do papel, que ja esta instalado aqui.",
    },
    "parar": {
        "rotulo": "Parar",
        "aviso": "Para o servico e o tira do boot (ele nao volta sozinho "
                 "quando a maquina reiniciar). A configuracao fica; o que ele "
                 "fazia deixa de ser feito ate voltar. No papel Roteamento "
                 "isto APAGA o firewall: a LAN perde a internet e a maquina "
                 "fica exposta. Servico que ja estava na maquina antes do "
                 "GHop e so PARADO, e continua habilitado no boot.",
    },
    "desinstalar": {
        "rotulo": "Desinstalar",
        "aviso": "Para o servico e desfaz o que o instalador fez, restaurando "
                 "a configuracao anterior. NAO apaga dado coletado.",
    },
}

# Papeis que o agente aceita gerenciar. 'lojmIt' e 'agente' ficam de fora de
# proposito: um derruba rota e firewall, o outro corta o proprio canal.
PAPEIS_GERENCIAVEIS = ("coletor", "dns", "wifi", "dhcp", "nftables", "filtro")

# Como se diz ao operador de onde veio um servico. Fica aqui, e nao na
# janela, porque as duas cascas mostram a mesma coluna e nao podem divergir:
# a janela escrevia "ja estava aqui" enquanto a linha de comando imprimia
# 'sistema' cru.
ORIGENS_PAPEL = {"ghop": "GHop", "sistema": "ja estava aqui"}

# O que o cruzamento das fontes da topologia QUER DIZER, em uma linha. Fica
# aqui pelo mesmo motivo de ORIGENS_PAPEL: as duas cascas mostram a mesma
# coluna e nao podem divergir. E o texto nao e enfeite -- "fala sem concessao
# nossa" e a unica linha da topologia que aponta um aparelho que ninguem
# cadastrou, e ele so aparece porque as tres fontes discordam.
LEITURAS_DE_FONTE = (
    (("dhcp",), "so concessao: nao falou (desligado?)"),
    (("wifi",), "no radio, sem endereco ainda"),
    (("dhcp", "wifi"), "no radio com concessao, mas calado"),
)


def leitura_das_fontes(fontes):
    """O que dizer de um host, dadas as fontes que o viram. Pode ser ''."""
    tem = set(fontes)
    for combinacao, texto in LEITURAS_DE_FONTE:
        if tem == set(combinacao):
            return texto
    if "vizinho" in tem and "dhcp" not in tem:
        return "fala sem concessao nossa (fixo?)"
    return ""


# Uma "visao" e um jeito de olhar um no: um rotulo e o comando que a alimenta.
VISOES = {
    # 'maquina' abre a janela: antes de perguntar o que a maquina FAZ, ver
    # o que ela E -- processador, memoria, disco. Tela cheia por causa do
    # disco: nenhuma outra aba responde "vai encher quando?".
    "maquina": {
        "rotulo": "Maquina",
        "comando": "sistema",
        "descricao": "Processador, memoria, disco e versoes desta maquina.",
    },
    # 'servicos' e a primeira: e a unica tela que MUDA a maquina, e o lugar
    # de olhar antes de qualquer leitura -- papel parado explica tela vazia.
    # Nao confundir com 'servico' (Analise de servico), que e o que a maquina
    # OFERECE para fora e ainda nao existe.
    "servicos": {
        "rotulo": "Servicos",
        "comando": "papeis",
        "descricao": "Papeis do GHop nesta maquina: instalar, iniciar, parar, desinstalar.",
    },
    # 'dados' vem antes das analises: e a maquina em si -- o que ela e, nao
    # o que ela faz. Por dentro tem abas por assunto (rede, e o que vier).
    "dados": {
        "rotulo": "Dados",
        # O comando que decide se a visao existe; as abas internas podem
        # usar outros (rotas), cada uma de leitura.
        "comando": "interfaces",
        "descricao": "A maquina como esta agora: interfaces de rede, enderecos, rotas.",
    },
    "saida": {
        "rotulo": "Analise de saida",
        "comando": "resumo",
        "descricao": "O que esta maquina pediu para fora: dominios e IPs, so contados.",
    },
    "servico": {
        "rotulo": "Analise de servico",
        "comando": "servicos",
        "descricao": "O que esta maquina serve, e para quem.",
    },
}

# O TIPO de um no diz quais visoes fazem sentido nele: um lojmIt se olha pela
# saida, um servidor web pelo servico que oferece.
#
# Nao ha visao de TOPOLOGIA aqui, e a ausencia e decisao: topologia e
# propriedade da REDE, nao de uma maquina -- o lojmIt e apenas mais uma
# maquina, e olha-la nao responde "como a rede esta ligada". Ela mora no
# menu Inventario, ao lado de dominios e IPs, que e onde vivem as coisas que
# atravessam os nos. (O metodo 'Painel.topologia(no)' continua existindo: e
# a peca que a janela do Inventario compoe, um no de cada vez.)
#
# O tipo mora no PAINEL, nao no agente, e e conveniencia de tela -- nunca
# autorizacao. Quem recusa comando e o conjunto fechado do agente; se o painel
# errar o tipo, o agente responde "comando desconhecido" e nada acontece de
# ruim. Nao apoie decisao de seguranca nisto.
TIPOS = {
    "lojmIt": {"rotulo": "lojmIt",
                "visoes": ("maquina", "servicos", "dados", "saida")},
    "webserver": {"rotulo": "Servidor web",
                  "visoes": ("maquina", "servicos", "dados", "servico")},
}

TIPO_PADRAO = "lojmIt"

# Tipo que mudou de nome depois de ja haver cadastro gravado com o antigo. A
# traducao acontece na LEITURA e nao reescreve o arquivo: o nos.json so e
# regravado quando o operador mexe nele, e ai ja sai com o nome novo.
TIPOS_RENOMEADOS = {"gateway": "lojmIt"}


def visoes_de(tipo):
    """Visoes de um tipo de no, ja resolvidas. Tipo desconhecido nao tem nenhuma."""
    definicao = TIPOS.get(tipo)
    if not definicao:
        return []
    return [dict(VISOES[chave], chave=chave) for chave in definicao["visoes"]
            if chave in VISOES]


# --------------------------------------------------------------- fabricante
#
# Os tres primeiros bytes de um MAC sao o OUI, que a IEEE atribui a um
# fabricante. Saber que o aparelho e "Apple" ou "Espressif" e muito mais util
# do que ler 'f0:0b:a5:...' -- e nao custa pedido nenhum: a consulta e LOCAL,
# numa base que o pacote 'ieee-data' do Debian instala. Consultar fabricante
# por API seria o painel falando com servico externo sozinho, e aqui nada
# consulta sem o clique do operador.
#
# Sem a base, a funcao devolve '' e as telas seguem mostrando o MAC: e
# enfeite util, nao dado de que alguem dependa.
BASES_OUI = (
    "/usr/share/ieee-data/oui.csv",       # pacote ieee-data (o mais provavel)
    "/usr/share/ieee-data/oui.txt",
    "/var/lib/ieee-data/oui.csv",
    "/usr/share/nmap/nmap-mac-prefixes",  # nmap, se estiver instalado
    "/usr/share/wireshark/manuf",         # wireshark, idem
)

_fabricantes = None

# Fica nomeado porque a tela precisa DISTINGUI-LO de um fabricante de verdade:
# 'Apple' serve de etiqueta na caixa, 'MAC aleatorio' nao -- e explicacao.
MAC_ALEATORIO = "MAC aleatorio"


def _carrega_oui():
    """Le a primeira base de OUI que existir. {'aabbcc': 'Nome'}."""
    tabela = {}
    for caminho in BASES_OUI:
        if not os.path.exists(caminho):
            continue
        try:
            with open(caminho, encoding="utf-8", errors="replace") as arquivo:
                for bruto in arquivo:
                    linha = bruto.strip()
                    if not linha or linha.startswith("#"):
                        continue
                    if caminho.endswith(".csv"):
                        # Registry,Assignment,Organization Name,Address
                        campos = linha.split(",")
                        if len(campos) < 3 or campos[0] == "Registry":
                            continue
                        prefixo, nome = campos[1], campos[2].strip('" ')
                    else:
                        # 'AABBCC  Nome' (nmap) ou 'AA:BB:CC	Nome' (manuf)
                        campos = linha.replace("\t", " ").split(None, 1)
                        if len(campos) != 2:
                            continue
                        prefixo, nome = campos[0], campos[1].split("#")[0].strip()
                    prefixo = prefixo.replace(":", "").replace("-", "").lower()
                    if len(prefixo) == 6 and nome:
                        tabela.setdefault(prefixo, nome)
        except OSError:
            continue
        if tabela:
            break
    return tabela


def fabricante(mac):
    """O fabricante de um MAC pelo OUI, ou '' se nao der para dizer.

    'MAC aleatorio' NAO e desconhecimento: e informacao. Celular e tablet
    modernos sorteiam o endereco a cada rede por privacidade, e marcam isso
    no proprio MAC (o bit de administracao local, o penultimo do primeiro
    byte). Procurar fabricante nesse caso nao acha nada -- e nao acharia
    mesmo com a base completa --, entao dizer 'aleatorio' explica a lacuna
    em vez de deixar o operador achando que a base falhou.
    """
    global _fabricantes
    limpo = (mac or "").replace(":", "").replace("-", "").lower()
    if len(limpo) < 6:
        return ""
    try:
        primeiro = int(limpo[:2], 16)
    except ValueError:
        return ""
    if primeiro & 0b10:
        return MAC_ALEATORIO
    if _fabricantes is None:
        _fabricantes = _carrega_oui()
    return _fabricantes.get(limpo[:6], "")


def _ordem_de_ip(texto):
    """Chave de ordenacao para IP em texto. Sem IP vai para o fim."""
    try:
        endereco = ipaddress.ip_address(texto)
    except ValueError:
        return (2, 0, b"")
    return (endereco.version == 6, endereco.version, endereco.packed)


def comando_existe(comando):
    """Se o agente de hoje implementa este comando."""
    return comando in COMANDOS


# ---------------------------------------------------------------- cadastro

ARQ_CADASTRO = os.path.join(os.path.expanduser("~/.ghop"), "cadastro.json")

# Nada entra sozinho: as duas sao decisao explicita do operador, e "dispensado"
# e gravado tanto quanto "cadastrado". Sem registrar o nao, um item recusado
# volta a parecer novo toda vez, e a pergunta se repete para sempre.
DECISOES = ("cadastrado", "dispensado")


class Cadastro:
    """Inventario das entidades que o operador ja olhou: dominios e IPs.

    E GERAL, e isso e o ponto: uma entidade e uma so, atravessando todos os
    nos. Se 'exemplo.com' foi reconhecido olhando o lojmIt, ele ja esta
    reconhecido quando aparecer noutro no -- juntar as visoes e tarefa do
    painel, e um cadastro por no desfaria justamente isso.

    Nao se confunde com as listas. Aqui e VAREJO: item a item, exato, com a
    nota do que voce descobriu. Listas sao ATACADO: regras de sufixo, cidr e
    regex que classificam na leitura. Um item pode estar cadastrado e tambem
    coberto por uma regra -- sao perguntas diferentes ("eu ja olhei isto?" e
    "isto e esperado ou ruim?").
    """

    def __init__(self, caminho=None):
        # Resolve na CHAMADA, nao na definicao: com 'caminho=ARQ_CADASTRO' o
        # valor do modulo era congelado no import, e apontar o painel para
        # outro cadastro deixava de funcionar -- inclusive em teste, que
        # entao escrevia no arquivo de verdade do operador.
        self.caminho = caminho or ARQ_CADASTRO

    @staticmethod
    def _vazio():
        return {especie: {} for especie in ESPECIES}

    def tudo(self):
        if not os.path.exists(self.caminho):
            return self._vazio()
        try:
            with open(self.caminho, encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
        except (OSError, json.JSONDecodeError) as falha:
            raise ErroGHop(f"nao consegui ler {self.caminho}: {falha}")
        completo = self._vazio()
        for especie in ESPECIES:
            entrada = dados.get(especie)
            if isinstance(entrada, dict):
                completo[especie] = entrada
        return completo

    def _grava(self, cadastro):
        os.makedirs(os.path.dirname(self.caminho), exist_ok=True)
        temporario = self.caminho + ".novo"
        try:
            with open(temporario, "w", encoding="utf-8") as arquivo:
                json.dump(cadastro, arquivo, ensure_ascii=False, indent=2)
                arquivo.write("\n")
            os.chmod(temporario, 0o600)
            os.replace(temporario, self.caminho)
        except OSError as falha:
            raise ErroGHop(f"nao consegui gravar {self.caminho}: {falha}")

    def obtem(self, especie, valor):
        """O registro desta entidade, ou None se ainda nao foi decidida."""
        if especie not in ESPECIES:
            raise ErroGHop(f"especie desconhecida: {especie!r}.")
        return self.tudo()[especie].get(valor)

    def registra(self, especie, valor, decisao, nota="", no=None):
        """Grava a decisao do operador sobre uma entidade.

        Reregistrar o mesmo valor atualiza a decisao e a nota, mas preserva
        'primeiro' -- quando voce olhou aquilo pela primeira vez nao muda por
        voce ter mudado de ideia depois.
        """
        if especie not in ESPECIES:
            raise ErroGHop(f"especie desconhecida: {especie!r}.")
        if decisao not in DECISOES:
            raise ErroGHop(f"decisao desconhecida: {decisao!r}. Ha: {', '.join(DECISOES)}.")
        if not valor:
            raise ErroGHop("valor vazio.")

        cadastro = self.tudo()
        antigo = cadastro[especie].get(valor) or {}
        # 'nos' guarda de onde voce estava olhando ao decidir -- nao e "todos
        # os nos em que isto aparece", que exigiria varrer todo mundo.
        nos = list(antigo.get("nos") or [])
        if no and no not in nos:
            nos.append(no)
        cadastro[especie][valor] = {
            "decisao": decisao,
            "nota": nota,
            "primeiro": antigo.get("primeiro") or _agora(),
            "ultimo": _agora(),
            "nos": nos,
        }
        self._grava(cadastro)
        return cadastro[especie][valor]

    def esquece(self, especie, valor):
        cadastro = self.tudo()
        if valor not in cadastro[especie]:
            raise ErroGHop(f"{valor} nao esta no cadastro.")
        removido = cadastro[especie].pop(valor)
        self._grava(cadastro)
        return removido

    # ------------------------------------------------------- monitoracao

    def monitora(self, valor, ligado=True):
        """Liga ou desliga a monitoracao de um IP externo.

        So vale para IP, e so para IP CADASTRADO: o inventario define quem
        pode ser monitorado, e a escolha acontece dentro dele. Item
        dispensado -- olhado e recusado -- nao entra.

        Marcar aqui nao mexe em no nenhum: e decisao local. Levar a lista
        aos agentes e passo separado e explicito, porque e ele que fala na
        rede.
        """
        cadastro = self.tudo()
        registro = cadastro["ips"].get(valor)
        if registro is None:
            raise ErroGHop(f"{valor} nao esta no inventario. Cadastre antes.")
        if registro.get("decisao") != "cadastrado":
            raise ErroGHop(
                f"{valor} esta '{registro.get('decisao')}'. So se monitora o "
                "que foi cadastrado.")
        registro["monitorado"] = bool(ligado)
        registro["ultimo"] = _agora()
        self._grava(cadastro)
        return registro

    def monitorados(self):
        """IPs marcados para monitoracao, em ordem. E o que vai aos agentes."""
        return sorted(
            valor for valor, registro in self.tudo()["ips"].items()
            if registro.get("monitorado") and registro.get("decisao") == "cadastrado")


def _agora():
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ------------------------------------------------------------------ listas

ARQ_LISTAS = os.path.join(os.path.expanduser("~/.ghop"), "listas.json")

# Tipos de regra. 'sufixo' e 'cidr' sao os que se quer usar no dia a dia;
# 'regex' existe para o caso que os outros nao cobrem, e cobra o preco de ter
# de escrever escape de ponto.
TIPOS_DOMINIO = ("sufixo", "exato", "regex")
TIPOS_IP = ("cidr", "exato", "regex")
ESPECIES = {"dominios": TIPOS_DOMINIO, "ips": TIPOS_IP}

# Branca: conhecido e esperado -- some da vista. Negra: conhecido e ruim --
# aparece em destaque e NUNCA some.
#
# A ordem importa: 'negra' e consultada primeiro, entao uma regra branca larga
# nao pode engolir um item marcado como ruim. Esconder o que se marcou como
# perigoso seria o pior defeito possivel nesta parte.
LISTAS = ("negra", "branca")


def _casa_regex(padrao, texto):
    # re.search, nao fullmatch: quem quiser ancorar poe ^ e $. Padrao ruim aqui
    # so custa tempo de leitura na propria maquina do operador.
    try:
        return re.search(padrao, texto) is not None
    except re.error:
        return False


def casa_dominio(regra, nome):
    tipo, valor = regra.get("tipo"), regra.get("valor", "")
    if tipo == "sufixo":
        # Fronteira de rotulo: 'exemplo.com' cobre 'a.exemplo.com' e o proprio
        # 'exemplo.com', mas NAO 'malexemplo.com'. Sem isso a whitelist vira
        # buraco: bastaria registrar um dominio terminado no nome confiavel.
        valor = valor.lstrip(".").lower()
        nome = nome.lower()
        return nome == valor or nome.endswith("." + valor)
    if tipo == "exato":
        return nome.lower() == valor.lower()
    if tipo == "regex":
        return _casa_regex(valor, nome)
    return False


def casa_ip(regra, endereco):
    tipo, valor = regra.get("tipo"), regra.get("valor", "")
    if tipo == "cidr":
        try:
            return ipaddress.ip_address(endereco) in ipaddress.ip_network(valor, strict=False)
        except ValueError:
            return False
    if tipo == "exato":
        try:
            return ipaddress.ip_address(endereco) == ipaddress.ip_address(valor)
        except ValueError:
            return False
    if tipo == "regex":
        return _casa_regex(valor, endereco)
    return False


def valida_regra(especie, tipo, valor):
    """Recusa regra que nao vai funcionar, na hora de cadastrar.

    Erro de regra que so aparece na leitura e erro que se descobre tarde: a
    lista fica parecendo aplicada e nao esta.
    """
    if especie not in ESPECIES:
        raise ErroGHop(f"especie desconhecida: {especie!r}. Ha: {', '.join(ESPECIES)}.")
    if tipo not in ESPECIES[especie]:
        raise ErroGHop(f"tipo {tipo!r} nao vale para {especie}. "
                       f"Ha: {', '.join(ESPECIES[especie])}.")
    if not valor:
        raise ErroGHop("valor vazio.")
    if tipo == "regex":
        try:
            re.compile(valor)
        except re.error as falha:
            raise ErroGHop(f"regex invalida: {falha}")
    if tipo == "cidr":
        try:
            ipaddress.ip_network(valor, strict=False)
        except ValueError as falha:
            raise ErroGHop(f"CIDR invalido: {falha}")
    if especie == "ips" and tipo == "exato":
        try:
            ipaddress.ip_address(valor)
        except ValueError as falha:
            raise ErroGHop(f"IP invalido: {falha}")
    return True


# ------------------------------------------------------------------- rdap

# RDAP e o whois moderno: JSON estruturado, sobre HTTPS, e serve para dominio
# e para IP com o mesmo cliente. A porta 43 do whois classico atravessa mal
# rede restritiva, e falar o protocolo cru exigiria perseguir referral na mao.
SERVIDOR_RDAP = "https://rdap.org"
TEMPO_RDAP = 15

# Quantas vezes subir um rotulo procurando o dominio registrado. RDAP responde
# pelo dominio, nao pelo host: 'wpad.example.org' nao existe como objeto, mas
# 'example.org' existe.
TENTATIVAS_RDAP = 4


class ConsultaAtiva(Exception):
    """Falha de uma consulta que SAI PARA A REDE. Separada de ErroGHop porque
    a casca precisa poder dizer que o problema foi la fora, nao aqui."""


def _rdap_bruto(caminho):
    import urllib.error
    import urllib.request
    pedido = urllib.request.Request(
        f"{SERVIDOR_RDAP}/{caminho}",
        headers={"Accept": "application/rdap+json", "User-Agent": "ghop-painel"})
    try:
        with urllib.request.urlopen(pedido, timeout=TEMPO_RDAP) as resposta:
            return json.load(resposta)
    except urllib.error.HTTPError as falha:
        if falha.code == 404:
            return None
        raise ConsultaAtiva(f"RDAP respondeu {falha.code} para {caminho}")
    except urllib.error.URLError as falha:
        raise ConsultaAtiva(f"nao alcancei o RDAP: {falha.reason}")
    except (TimeoutError, OSError) as falha:
        raise ConsultaAtiva(f"falha de rede no RDAP: {falha}")
    except json.JSONDecodeError:
        raise ConsultaAtiva("o RDAP respondeu algo que nao e JSON")


def _texto_entidade(entidade):
    """Nome legivel de uma entidade RDAP, que vem em vCard aninhado."""
    cartao = entidade.get("vcardArray")
    if isinstance(cartao, list) and len(cartao) > 1:
        for campo in cartao[1]:
            if isinstance(campo, list) and len(campo) > 3 and campo[0] == "fn":
                return str(campo[3])
    return entidade.get("handle", "")


def _resume_rdap(dados):
    """Os poucos campos que importam na triagem, como pares [rotulo, valor].

    Pares, e nao dicionario com forma propria, para a casca poder exibir
    qualquer servico do mesmo jeito: quem sabe o que e relevante e o cliente
    do servico, nao a tela.

    A idade do registro e o que mais diz: dominio criado ontem e sinal
    diferente de dominio criado em 2009.
    """
    pares = []
    nome = dados.get("ldhName") or dados.get("handle") or ""
    if nome:
        pares.append(["nome", nome])
    if dados.get("startAddress"):
        pares.append(["faixa", f"{dados['startAddress']} - {dados.get('endAddress')}"])
    if dados.get("country"):
        pares.append(["pais", dados["country"]])
    if dados.get("status"):
        pares.append(["estado", ", ".join(dados["status"])])

    for evento in dados.get("events") or []:
        acao, data = evento.get("eventAction"), evento.get("eventDate")
        if acao and data:
            pares.append([acao, data])

    vistos = set()
    for entidade in dados.get("entities") or []:
        for papel in entidade.get("roles") or []:
            if papel not in vistos:
                vistos.add(papel)
                pares.append([papel, _texto_entidade(entidade)])

    servidores = [s.get("ldhName", "") for s in dados.get("nameservers") or []]
    servidores = [s for s in servidores if s]
    if servidores:
        pares.append(["nameservers", ", ".join(servidores)])
    return pares


# ------------------------------------------------------- servicos externos

DIR_CONSULTAS = os.path.join(os.path.expanduser("~/.ghop"), "consultas")
ARQ_ENV = os.path.expanduser("~/.env")


def segredo(nome):
    """Le uma credencial do ambiente ou de ~/.env. Nunca do repositorio.

    Chave de API e segredo: nao entra em arquivo versionado nem em
    ~/.ghop, e nao aparece em linha de comando (que vaza no ps). ~/.env e
    onde o operador ja guarda as outras credenciais da casa.
    """
    valor = os.environ.get(nome)
    if valor:
        return valor.strip()
    try:
        with open(ARQ_ENV, encoding="utf-8") as arquivo:
            for linha in arquivo:
                chave, igual, resto = linha.partition("=")
                if igual and chave.strip() == nome:
                    return resto.strip().strip("'\"")
    except OSError:
        pass
    return None


class CacheConsultas:
    """Guarda o que um servico externo respondeu, por entidade.

    Dois motivos, e nenhum deles e velocidade.

    Privacidade: consultar e acao ativa e atribuivel -- cada pergunta conta
    ao servidor, e a quem estiver no caminho, que alguem investiga aquele
    nome. Sem cache, abrir a mesma tela tres vezes pergunta tres vezes.

    Custo: servico pago cobra por consulta. Aqui o cache deixa de ser
    conveniencia e vira controle de gasto -- reconsultar tem de ser ato
    deliberado, nunca efeito colateral de abrir uma janela.

    E ha um terceiro ganho, de prova: o que o servico respondeu NAQUELA data
    so se sabe se foi guardado. Reputacao muda; o retrato, nao.

    Um arquivo por entidade, e nao um banco unico: resposta e volumosa, e um
    arquivo so seria reescrito inteiro a cada consulta.

    Fica em claro, como o resto de ~/.ghop -- ver a analise em
    docs/evolucao.md sobre por que cifrar so isto seria teatro.
    """

    def __init__(self, servico, diretorio=None):
        self.servico = servico
        self.diretorio = os.path.join(diretorio or DIR_CONSULTAS, servico)

    def _arquivo(self, especie, valor):
        # Dominio e IP tem charset limitado, mas ':' de IPv6 e caractere ruim
        # em nome de arquivo. O valor real fica dentro, e e conferido na
        # leitura, entao um choque de nome nao devolve a resposta errada.
        seguro = "".join(c if (c.isalnum() or c in ".-_") else "_" for c in valor)
        return os.path.join(self.diretorio, especie, seguro[:200] + ".json")

    def obtem(self, especie, valor):
        caminho = self._arquivo(especie, valor)
        if not os.path.exists(caminho):
            return None
        try:
            with open(caminho, encoding="utf-8") as arquivo:
                registro = json.load(arquivo)
        except (OSError, json.JSONDecodeError):
            return None
        return registro if registro.get("valor") == valor else None

    def guarda(self, especie, valor, consultado, resumo, bruto):
        caminho = self._arquivo(especie, valor)
        os.makedirs(os.path.dirname(caminho), exist_ok=True)
        registro = {
            "servico": self.servico,
            "especie": especie,
            "valor": valor,
            "respondeu_por": consultado,
            "consultado_em": _agora(),
            "resumo": resumo,
            "bruto": bruto,
        }
        temporario = caminho + ".novo"
        try:
            with open(temporario, "w", encoding="utf-8") as arquivo:
                json.dump(registro, arquivo, ensure_ascii=False, indent=2)
                arquivo.write("\n")
            os.chmod(temporario, 0o600)
            os.replace(temporario, caminho)
        except OSError as falha:
            raise ErroGHop(f"nao consegui gravar {caminho}: {falha}")
        return registro

    def esquece(self, especie, valor):
        caminho = self._arquivo(especie, valor)
        try:
            os.remove(caminho)
        except FileNotFoundError:
            raise ErroGHop(f"{valor} nao esta no cache de {self.servico}.")
        except OSError as falha:
            raise ErroGHop(f"nao consegui apagar {caminho}: {falha}")

    def quantos(self):
        total = {}
        for especie in ESPECIES:
            pasta = os.path.join(self.diretorio, especie)
            try:
                total[especie] = len([n for n in os.listdir(pasta)
                                      if n.endswith(".json")])
            except OSError:
                total[especie] = 0
        return total


class UsoServico:
    """Conta quantas consultas este painel gastou, por dia.

    O plano gratuito do IPQS da 35 por DIA e 1.000 por mes. Sem contador, o
    operador descobre que estourou quando a API recusa -- e ai ja gastou a
    tentativa. Mostrar o consumo antes de clicar e o que torna o limite
    administravel.

    A conta e LOCAL e so enxerga o que saiu deste painel: consulta feita pelo
    site do servico, por outra maquina ou por outro programa nao aparece
    aqui. E estimativa para orientar, nao a verdade da fatura.
    """

    def __init__(self, servico, diretorio=None):
        self.caminho = os.path.join(diretorio or DIR_CONSULTAS, servico, "uso.json")

    def _tudo(self):
        try:
            with open(self.caminho, encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
            return dados if isinstance(dados, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def registra(self):
        dias = self._tudo()
        hoje = _agora()[:10]
        dias[hoje] = int(dias.get(hoje, 0)) + 1
        # Guarda so o ano corrente de dias: o arquivo nao precisa crescer para
        # sempre, e nenhuma janela de contagem passa de um mes.
        recentes = dict(sorted(dias.items())[-400:])
        os.makedirs(os.path.dirname(self.caminho), exist_ok=True)
        try:
            with open(self.caminho, "w", encoding="utf-8") as arquivo:
                json.dump(recentes, arquivo, indent=2)
                arquivo.write("\n")
            os.chmod(self.caminho, 0o600)
        except OSError:
            pass  # perder a contagem nao justifica derrubar a consulta

    def resumo(self):
        dias = self._tudo()
        hoje = _agora()[:10]
        return {"dia": int(dias.get(hoje, 0)),
                "mes": sum(int(v) for k, v in dias.items() if k[:7] == hoje[:7])}


def _ipqs_bruto(caminho):
    import urllib.error
    import urllib.request
    pedido = urllib.request.Request(
        f"{SERVIDOR_IPQS}/{caminho}", headers={"User-Agent": "ghop-painel"})
    try:
        with urllib.request.urlopen(pedido, timeout=TEMPO_IPQS) as resposta:
            return json.load(resposta)
    except urllib.error.HTTPError as falha:
        raise ConsultaAtiva(f"IPQualityScore respondeu {falha.code}")
    except urllib.error.URLError as falha:
        raise ConsultaAtiva(f"nao alcancei o IPQualityScore: {falha.reason}")
    except (TimeoutError, OSError) as falha:
        raise ConsultaAtiva(f"falha de rede no IPQualityScore: {falha}")
    except json.JSONDecodeError:
        raise ConsultaAtiva("o IPQualityScore respondeu algo que nao e JSON")


# Campos que valem na triagem, na ordem em que se quer ler. O bruto fica
# guardado inteiro de qualquer forma; isto e so o que sobe para a tela.
_CAMPOS_IPQS_IP = [
    ("fraud_score", "risco (0-100)"), ("country_code", "pais"),
    ("region", "regiao"), ("city", "cidade"), ("ISP", "provedor"),
    ("organization", "organizacao"), ("ASN", "ASN"),
    ("connection_type", "tipo de conexao"), ("proxy", "proxy"),
    ("vpn", "vpn"), ("tor", "tor"), ("active_vpn", "vpn ativa"),
    ("active_tor", "tor ativo"), ("recent_abuse", "abuso recente"),
    ("bot_status", "bot"), ("abuse_velocity", "velocidade de abuso"),
]
_CAMPOS_IPQS_URL = [
    ("risk_score", "risco (0-100)"), ("unsafe", "inseguro"),
    ("domain", "dominio"), ("ip_address", "IP"), ("server", "servidor"),
    ("domain_rank", "posicao do dominio"), ("domain_age", "idade do dominio"),
    ("category", "categoria"), ("dns_valid", "DNS valido"),
    ("parking", "estacionado"), ("spamming", "spam"), ("malware", "malware"),
    ("phishing", "phishing"), ("suspicious", "suspeito"), ("adult", "adulto"),
]


def _consulta_ipqs(especie, valor):
    """IPQualityScore. CUSTA CREDITO -- ver UsoServico e o limite do plano."""
    chave = segredo(CHAVE_IPQS)
    if not chave:
        raise ConsultaAtiva(
            f"{CHAVE_IPQS} nao encontrada. Ponha a chave da API no ambiente "
            "ou em ~/.env -- nunca em arquivo versionado.")

    if especie == "ips":
        dados = _ipqs_bruto(f"ip/{chave}/{urllib.parse.quote(valor)}")
        campos = _CAMPOS_IPQS_IP
    else:
        dados = _ipqs_bruto(f"url/{chave}/{urllib.parse.quote(valor, safe='')}")
        campos = _CAMPOS_IPQS_URL

    if not dados.get("success", False):
        raise ConsultaAtiva(
            dados.get("message") or "o IPQualityScore recusou a consulta.")

    pares = []
    for chave_campo, rotulo in campos:
        if chave_campo in dados and dados[chave_campo] not in ("", None):
            valor_campo = dados[chave_campo]
            if isinstance(valor_campo, bool):
                valor_campo = "sim" if valor_campo else "nao"
            elif isinstance(valor_campo, dict):
                # 'domain_age' vem como {human, timestamp, iso}: mostrar o
                # dicionario cru seria jogar a estrutura da API na cara de
                # quem so quer saber a idade.
                valor_campo = (valor_campo.get("human")
                               or valor_campo.get("iso") or valor_campo)
            pares.append([rotulo, str(valor_campo)])
    # O bruto guardado nao pode conter a chave: ela nao esta na resposta, mas
    # 'request_id' e afins ficam, e isso e o que se quer para auditoria.
    return pares, valor, dados


SERVIDOR_IPQS = "https://ipqualityscore.com/api/json"
# Nome da variavel onde a chave da API mora. Fica aqui, e nao espalhada, para
# haver um lugar so a mudar quando a chave for trocada.
CHAVE_IPQS = "GHOP_IP_QUALITY_KEY"
TEMPO_IPQS = 20

# Registro dos servicos externos. Acrescentar um servico e mexer so aqui e na
# aba correspondente -- a tela e generica, e le 'resumo' como pares.
SERVICOS = {
    "rdap": {
        "nome": "RDAP",
        "especies": ("dominios", "ips"),
        "consulta": lambda especie, valor: consulta_rdap(especie, valor),
        "custa": False,
        "rotulo": {"dominios": "Whois", "ips": "Alocacao do bloco"},
        "descricao": {
            "dominios": "Quem registrou o dominio, quando e ate quando.",
            "ips": "IP nao tem whois: ninguem registra um endereco. O que da "
                   "para buscar e a alocacao no RIR -- qual bloco contem este "
                   "endereco, para quem foi alocado, em que pais, e o contato "
                   "de abuso.",
        },
    },
    "ipqs": {
        "nome": "IPQualityScore",
        "especies": ("dominios", "ips"),
        "consulta": _consulta_ipqs,
        "custa": True,
        "limite": {"dia": 35, "mes": 1000},
        "rotulo": {"dominios": "IPQualityScore", "ips": "IPQualityScore"},
        "descricao": {
            "dominios": "Reputacao do dominio: risco, phishing, malware, "
                        "spam, idade e categoria.",
            "ips": "Reputacao do endereco: risco, proxy, VPN, Tor, bot e "
                   "abuso recente.",
        },
    },
}


def consulta_servico(servico, especie, valor, forcar=False):
    """Consulta um servico externo, com cache. -> registro guardado.

    Sem forcar, entidade ja consultada NAO gera trafego nem gasto: devolve o
    que foi guardado, com a data. Com forcar, pergunta de novo e sobrescreve
    -- e o que se usa para saber se algo mudou, e o que custa credito num
    servico pago.
    """
    definicao = SERVICOS.get(servico)
    if definicao is None:
        raise ErroGHop(f"servico desconhecido: {servico!r}.")
    if especie not in definicao["especies"]:
        raise ErroGHop(f"{definicao['nome']} nao atende {especie}.")

    cache = CacheConsultas(servico)
    if not forcar:
        guardado = cache.obtem(especie, valor)
        if guardado is not None:
            return dict(guardado, do_cache=True)

    resumo, consultado, bruto = definicao["consulta"](especie, valor)
    # So conta quando de fato saiu para a rede. Acerto do cache nao gasta.
    UsoServico(servico).registra()
    registro = cache.guarda(especie, valor, consultado, resumo, bruto)
    return dict(registro, do_cache=False)


def consulta_rdap(especie, valor):
    """Consulta RDAP de um dominio ou IP. BLOQUEIA e SAI PARA A REDE.

    ATENCAO: isto e uma acao ATIVA e atribuivel ao operador. Perguntar pelo
    dominio conta ao servidor RDAP -- e a quem estiver no caminho -- que
    alguem esta investigando aquilo. Por isso nao deve ser disparada sozinha
    ao abrir uma tela: quem manda consultar e o operador, de propria vontade.

    Roda no PAINEL, nunca no agente. Dar ao agente um comando que faz pedido
    de saida o transformaria em proxy da rede observada, e o conjunto fechado
    de comandos existe exatamente para isso nao acontecer.

    Devolve (resumo, nome_consultado, bruto). O nome consultado pode nao ser
    o valor pedido: RDAP responde pelo dominio registrado, entao para um host
    o cliente sobe rotulos ate achar -- e quem le precisa saber de qual objeto
    e a resposta.
    """
    if especie == "ips":
        dados = _rdap_bruto(f"ip/{valor}")
        if dados is None:
            raise ConsultaAtiva(f"o RDAP nao conhece {valor}.")
        return _resume_rdap(dados), valor, dados

    nome = valor.strip(".").lower()
    for _ in range(TENTATIVAS_RDAP):
        dados = _rdap_bruto(f"domain/{nome}")
        if dados is not None:
            return _resume_rdap(dados), nome, dados
        partes = nome.split(".")
        if len(partes) <= 2:
            break
        nome = ".".join(partes[1:])
    raise ConsultaAtiva(f"o RDAP nao conhece {valor} nem os dominios acima dele.")


# Varredura de texto atras de entidades. Deliberadamente generosa: e melhor
# oferecer um candidato a mais, que o operador descarta com um olhar, do que
# esconder um nameserver ou um bloco que era justamente a pista.
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_RE_IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?\b")
# Nome de host: rotulos separados por ponto, terminando em letra (TLD nunca e
# so numero -- e o que separa 'exemplo.com' de '192.168.0.1').
_RE_DOMINIO = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")


# E-mail e tratado antes da varredura geral: sem isso a parte local
# ('fulano.silva' de fulano.silva@exemplo.com) e capturada como se fosse
# dominio, porque o ultimo pedaco parece TLD. Alem de errado, isso jogaria
# fragmento de endereco de pessoa dentro do inventario.
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,63})\b")

# Nome de arquivo tambem passa pelo padrao de dominio ('geofeed.csv',
# 'termos.pdf'). Lista curta do que aparece em resposta de RDAP.
_EXTENSOES = {
    "pdf", "csv", "json", "txt", "html", "htm", "xml", "zip", "gz", "tar",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "md", "log", "conf", "cfg",
    "yml", "yaml", "sh", "py", "js", "css", "exe", "dll", "doc", "docx",
}


def _limpa_dominio(nome):
    nome = nome.strip(".").lower()
    if not nome or len(nome) > 253 or "." not in nome:
        return None
    # Consulta reversa fala de um IP que ja seria capturado como IP.
    if nome.endswith(".in-addr.arpa") or nome.endswith(".ip6.arpa"):
        return None
    if nome.rsplit(".", 1)[-1] in _EXTENSOES:
        return None
    return nome


def extrai_entidades(texto):
    """Varre um texto qualquer atras de dominios e IPs. -> {'dominios','ips'}

    Feito para a resposta do whois/RDAP, onde moram as entidades que a
    triagem quer: nameservers do dominio, o bloco de onde o endereco veio, o
    dominio do contato de abuso. Sao coisas que so aparecem depois de
    consultar, e que se perderiam se o operador tivesse de copiar na mao.

    Trabalha sobre TEXTO, nao sobre a estrutura do RDAP, e de proposito: cada
    registro devolve um formato diferente, e varrer o texto pega o que
    interessa em todos eles sem um parser por RIR.

    Nao decide nada -- so oferece candidatos. Quem adiciona e o operador.
    """
    texto = texto or ""
    ips, dominios = {}, {}

    # E-mail primeiro: guarda so o dominio e apaga o endereco inteiro do
    # texto, para a varredura seguinte nao ver a parte local como dominio.
    for dominio_email in _RE_EMAIL.findall(texto):
        nome = _limpa_dominio(dominio_email)
        if nome:
            dominios[nome] = True
    texto = _RE_EMAIL.sub(" ", texto)

    for achado in _RE_IPV4.findall(texto) + _RE_IPV6.findall(texto):
        try:
            if "/" in achado:
                # Guarda a rede na forma canonica: '77.37.40.0/22'.
                valor = str(ipaddress.ip_network(achado, strict=False))
            else:
                valor = str(ipaddress.ip_address(achado))
        except ValueError:
            continue
        ips[valor] = True

    for achado in _RE_DOMINIO.findall(texto):
        nome = _limpa_dominio(achado)
        if nome:
            dominios[nome] = True

    return {"dominios": sorted(dominios), "ips": sorted(ips)}


def sugestao_regra(especie, valor, tipo):
    """Valor inicial plausivel ao criar uma regra a partir de uma linha vista.

    Existe porque o erro comum e classificar mais estreito do que se quer:
    marcar 'wpad.example.org' quando o que incomoda e 'example.org' inteiro,
    e ter de voltar ali toda vez que aparecer outro nome no mesmo dominio.
    A sugestao e ponto de partida, nao decisao -- o campo continua editavel.
    """
    if especie == "dominios":
        if tipo == "sufixo":
            partes = valor.split(".")
            # Sobe um rotulo, mas nunca ate um dominio de topo: 'a.exemplo.com'
            # sugere 'exemplo.com', e 'exemplo.com' sugere ele mesmo.
            return ".".join(partes[1:]) if len(partes) > 2 else valor
        if tipo == "regex":
            return "^" + re.escape(valor) + "$"
        return valor

    if tipo == "cidr":
        try:
            endereco = ipaddress.ip_address(valor)
        except ValueError:
            return valor
        prefixo = 24 if endereco.version == 4 else 64
        return str(ipaddress.ip_network(f"{valor}/{prefixo}", strict=False))
    if tipo == "regex":
        return "^" + re.escape(valor) + "$"
    return valor


class Listas:
    """Whitelist de dominios e de IPs, do painel.

    Mora no painel e nao no agente. Duas consequencias, que sao o motivo de
    ser assim: mudar a lista nao toca em servidor nenhum, e a classificacao
    acontece na LEITURA -- ao acrescentar uma regra, todo o historico ja
    coletado e reclassificado junto, sem recoletar nada.

    O que esta na whitelist E COLETADO normalmente; ela so decide o que
    aparece. Nao confundir com o filtro de LAN do coletor, que e outra coisa:
    aquilo nunca entra no banco, porque falar com a vizinhanca nao e pedir
    para fora.

    Dominio e IP sao listas SEPARADAS de proposito: liberar um dominio nao
    libera os IPs dele -- CDN troca endereco o tempo todo --, e a lista de IP
    envelhece mal.
    """

    def __init__(self, caminho=None):
        # Mesmo motivo do Cadastro: resolver na chamada, nao na definicao.
        self.caminho = caminho or ARQ_LISTAS

    @staticmethod
    def _vazio():
        return {lista: {especie: [] for especie in ESPECIES} for lista in LISTAS}

    def tudo(self):
        if not os.path.exists(self.caminho):
            return self._vazio()
        try:
            with open(self.caminho, encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
        except (OSError, json.JSONDecodeError) as falha:
            raise ErroGHop(f"nao consegui ler {self.caminho}: {falha}")

        # Arquivo anterior a existencia da lista negra era so {dominios, ips}:
        # aquilo era tudo whitelist.
        if "dominios" in dados or "ips" in dados:
            dados = {"branca": dados, "negra": {}}

        completo = self._vazio()
        for lista in LISTAS:
            entrada = dados.get(lista) or {}
            for especie in ESPECIES:
                completo[lista][especie] = list(entrada.get(especie) or [])
        return completo

    def _grava(self, listas):
        os.makedirs(os.path.dirname(self.caminho), exist_ok=True)
        temporario = self.caminho + ".novo"
        try:
            with open(temporario, "w", encoding="utf-8") as arquivo:
                json.dump(listas, arquivo, ensure_ascii=False, indent=2)
                arquivo.write("\n")
            os.chmod(temporario, 0o600)
            os.replace(temporario, self.caminho)
        except OSError as falha:
            raise ErroGHop(f"nao consegui gravar {self.caminho}: {falha}")

    def _valida_lista(self, lista):
        if lista not in LISTAS:
            raise ErroGHop(f"lista desconhecida: {lista!r}. Ha: {', '.join(LISTAS)}.")

    def adiciona(self, lista, especie, tipo, valor, nota=""):
        self._valida_lista(lista)
        valida_regra(especie, tipo, valor)
        listas = self.tudo()
        for regra in listas[lista][especie]:
            if regra.get("tipo") == tipo and regra.get("valor") == valor:
                raise ErroGHop(f"esta regra ja existe na lista {lista} de {especie}.")
        listas[lista][especie].append({"tipo": tipo, "valor": valor, "nota": nota})
        self._grava(listas)

    def remove(self, lista, especie, indice):
        self._valida_lista(lista)
        if especie not in ESPECIES:
            raise ErroGHop(f"especie desconhecida: {especie!r}.")
        listas = self.tudo()
        regras = listas[lista][especie]
        if not 0 <= indice < len(regras):
            raise ErroGHop(f"nao ha regra {indice} na lista {lista} de {especie}.")
        removida = regras.pop(indice)
        self._grava(listas)
        return removida

    def regras(self, lista, especie):
        self._valida_lista(lista)
        return self.tudo()[lista][especie]

    def classifica_valor(self, especie, valor):
        """(classe, regra) de um unico valor. Classe vazia = ainda sem nome.

        Serve para quem tem um item na mao e nao um resumo inteiro -- o
        inventario, por exemplo, onde nao houve leitura de no nenhuma.
        """
        if especie not in ESPECIES:
            raise ErroGHop(f"especie desconhecida: {especie!r}.")
        casa = casa_dominio if especie == "dominios" else casa_ip
        return self._classe(self.tudo(), especie, valor, casa)

    def _classe(self, listas, especie, valor, casa):
        """Primeira lista que cobrir o valor. LISTAS poe 'negra' na frente."""
        for lista in LISTAS:
            for regra in listas[lista][especie]:
                if casa(regra, valor):
                    return lista, f"{regra['tipo']}:{regra['valor']}"
        return "", ""

    def classifica(self, dados):
        """Marca cada linha do resumo com a lista que a cobre, se alguma.

        Le as listas UMA vez para o lote inteiro: tudo() toca o disco, e fazer
        isso por linha custaria caro num resumo de mil linhas.

        Cada linha ganha 'classe' ('negra', 'branca' ou vazio para o que ainda
        nao tem nome) e 'regra', que diz qual regra pegou -- sem isso nao da
        para conferir a propria lista quando ela cresce.
        """
        listas = self.tudo()
        for linha in dados.get("dominios", []):
            linha["classe"], linha["regra"] = self._classe(
                listas, "dominios", linha["dominio"], casa_dominio)
        for linha in dados.get("ips", []):
            linha["classe"], linha["regra"] = self._classe(
                listas, "ips", linha["ip"], casa_ip)
        return dados


# ------------------------------------------------------------------ filtro

ARQ_FILTRO = os.path.join(os.path.expanduser("~/.ghop"), "filtro.json")

# O que o filtro de camada de aplicacao sabe casar. NAO ha 'regex' aqui, ao
# contrario das listas branca e negra: aquelas rodam na LEITURA, no painel,
# sobre dado ja coletado; estas rodam no CAMINHO DO DADO, a cada conexao da
# LAN. Expressao regular ali e latencia imprevisivel na rede inteira, e um
# jeito de o operador travar a propria saida sem entender por que.
TIPOS_FILTRO = ("sufixo", "exato", "prefixo", "contem")
ACOES_FILTRO = ("bloquear", "permitir")
POLITICAS_FILTRO = ("permitir", "bloquear")
# Espelha o limite do agente. Conferir aqui tambem e recusar antes de gastar
# uma conexao mTLS; quem de fato recusa continua sendo o agente.
LIMITE_REGRAS_FILTRO = 500

# Mesmo formato que o agente exige. Duplicado de proposito e nao importado:
# sao dois programas em maquinas diferentes, e o dia em que divergirem o
# agente e quem manda -- ele recusa, e a mensagem dele aparece na tela.
FORMATO_NOME_FILTRO = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


class Filtro:
    """Regras do filtro de camada de aplicacao, do painel.

    Moram aqui e nao no no, pelo mesmo motivo das listas branca e negra: o
    agente e burro, recebe a lista pronta e a aplica. A diferenca em relacao
    as listas do resolvedor e que estas NAO sao so classificacao -- elas
    bloqueiam de verdade, e por isso 'bloquear' e uma acao escolhida regra a
    regra, e nunca a lista negra inteira. Quer-se VER quem fala com um
    dominio ruim antes de cega-lo.

    Um conjunto so, levado a todo no que tenha o papel. Nao ha regra por no:
    duas politicas de saida na mesma infra sao duas coisas para manter em
    sincronia, e a primeira vez que divergirem ninguem vai saber qual esta
    valendo.
    """

    def __init__(self, caminho=None):
        self.caminho = caminho or ARQ_FILTRO

    def tudo(self):
        """{'politica': str, 'regras': [...]} do disco. Sem arquivo, vazio."""
        if not os.path.exists(self.caminho):
            return {"politica": "permitir", "regras": []}
        try:
            with open(self.caminho, encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
        except (OSError, json.JSONDecodeError) as falha:
            raise ErroGHop(f"nao consegui ler {self.caminho}: {falha}")
        politica = dados.get("politica")
        return {
            "politica": politica if politica in POLITICAS_FILTRO else "permitir",
            "regras": [regra for regra in (dados.get("regras") or [])
                       if isinstance(regra, dict)],
        }

    def _grava(self, dados):
        os.makedirs(os.path.dirname(self.caminho), exist_ok=True)
        temporario = self.caminho + ".novo"
        try:
            with open(temporario, "w", encoding="utf-8") as arquivo:
                json.dump(dados, arquivo, ensure_ascii=False, indent=2)
                arquivo.write("\n")
            os.chmod(temporario, 0o600)
            os.replace(temporario, self.caminho)
        except OSError as falha:
            raise ErroGHop(f"nao consegui gravar {self.caminho}: {falha}")

    def define_politica(self, politica):
        """'permitir' (bloqueia so o que estiver nas regras) ou 'bloquear'.

        'bloquear' e lista branca: nada sai sem regra que permita, INCLUSIVE
        conexao sem nome legivel. Fecha o buraco do SNI ausente e quebra
        tudo o que nao foi previsto -- e escolha do operador, com aviso.
        """
        if politica not in POLITICAS_FILTRO:
            raise ErroGHop(f"politica deve ser uma de {', '.join(POLITICAS_FILTRO)}.")
        dados = self.tudo()
        dados["politica"] = politica
        self._grava(dados)
        return dados

    def adiciona(self, tipo, valor, acao, nota="", posicao=None):
        """Acrescenta uma regra. A ORDEM importa: a primeira que casa decide.

        'posicao' insere antes daquele indice -- e como se abre excecao
        dentro de um bloqueio largo, pondo o 'permitir' especifico acima do
        'bloquear' geral. Sem posicao, vai para o fim.
        """
        if tipo not in TIPOS_FILTRO:
            raise ErroGHop(f"tipo deve ser um de {', '.join(TIPOS_FILTRO)}.")
        if acao not in ACOES_FILTRO:
            raise ErroGHop(f"acao deve ser uma de {', '.join(ACOES_FILTRO)}.")
        valor = (valor or "").strip().lower().rstrip(".")
        if not FORMATO_NOME_FILTRO.match(valor):
            raise ErroGHop(
                f"'{valor}' nao e um nome de host. O filtro compara o nome que a "
                "conexao pede (SNI ou Host), entao a regra tem de ser um nome.")
        nota = (nota or "").strip()
        if len(nota) > 200:
            raise ErroGHop("a nota tem no maximo 200 caracteres.")
        dados = self.tudo()
        if len(dados["regras"]) >= LIMITE_REGRAS_FILTRO:
            raise ErroGHop(
                f"o filtro aceita no maximo {LIMITE_REGRAS_FILTRO} regras -- ele as "
                "percorre a cada conexao da LAN. Lista grande e assunto do resolvedor.")
        regra = {"tipo": tipo, "valor": valor, "acao": acao, "nota": nota}
        if regra in dados["regras"]:
            raise ErroGHop("essa regra ja existe.")
        if posicao is None:
            dados["regras"].append(regra)
        else:
            dados["regras"].insert(max(0, int(posicao)), regra)
        self._grava(dados)
        return regra

    def remove(self, indice):
        """Tira a regra daquele indice. Devolve a que saiu."""
        dados = self.tudo()
        try:
            regra = dados["regras"].pop(int(indice))
        except (IndexError, ValueError, TypeError):
            raise ErroGHop(f"nao ha regra de indice {indice}.")
        self._grava(dados)
        return regra

    def move(self, indice, destino):
        """Muda uma regra de lugar. Ordem e semantica aqui, nao arrumacao."""
        dados = self.tudo()
        try:
            regra = dados["regras"].pop(int(indice))
        except (IndexError, ValueError, TypeError):
            raise ErroGHop(f"nao ha regra de indice {indice}.")
        dados["regras"].insert(max(0, min(int(destino), len(dados["regras"]))), regra)
        self._grava(dados)
        return regra

    def decide(self, nome):
        """(acao, regra) que este nome receberia. Mesma ordem do filtro real.

        Existe para a tela poder responder "e se?" sem esperar alguem
        tropecar na regra. Repete a logica do ghop-filtro.py de proposito --
        importar o programa do agente aqui prenderia o painel ao codigo que
        roda na maquina observada.
        """
        dados = self.tudo()
        nome = (nome or "").strip().lower().rstrip(".")
        for regra in dados["regras"]:
            valor = (regra.get("valor") or "").lower()
            tipo = regra.get("tipo")
            casou = (
                (tipo == "exato" and nome == valor)
                or (tipo == "sufixo" and (nome == valor or nome.endswith("." + valor)))
                or (tipo == "prefixo" and nome.startswith(valor))
                or (tipo == "contem" and valor in nome))
            if casou:
                return regra.get("acao"), f"{tipo} {valor}"
        return dados["politica"], f"politica {dados['politica']}"


class ErroGHop(Exception):
    """Qualquer falha que a casca deva mostrar ao operador."""


def nome_comum(certificado):
    for campo in (certificado or {}).get("subject", ()):
        for chave, valor in campo:
            if chave == "commonName":
                return valor
    return None


def valida_nome(nome):
    if not FORMATO_NOME.match(nome or ""):
        raise ErroGHop(
            f"nome invalido '{nome}'. Use letras, numeros, ponto, hifen e sublinhado.")
    return nome


def separa_endereco(texto):
    """'host', 'host:porta' ou '[ipv6]:porta' -> (host, porta)."""
    if texto.startswith("["):
        fecha = texto.find("]")
        if fecha < 0:
            raise ErroGHop(f"endereco IPv6 sem ']': {texto}")
        host, resto = texto[1:fecha], texto[fecha + 1:]
        if resto and not resto.startswith(":"):
            raise ErroGHop(f"endereco invalido: {texto}")
        porta = resto[1:] if resto else str(PORTA_PADRAO)
    elif texto.count(":") == 1:
        host, _, porta = texto.partition(":")
    else:
        host, porta = texto, str(PORTA_PADRAO)
    if not host:
        raise ErroGHop(f"endereco sem host: {texto}")
    if not porta.isdigit():
        raise ErroGHop(f"porta invalida em {texto}")
    return host, int(porta)


def paineis_emitidos():
    """Nomes de painel que existem em ~/.ghop/ca/emitidos."""
    achados = sorted(glob.glob(os.path.join(DIR_EMITIDOS, PREFIXO_PAINEL + "*.crt")))
    return [os.path.basename(a)[:-4] for a in achados]


class Painel:
    """O painel: conhece os nos e sabe falar com eles.

    nome_painel  identidade a usar; None escolhe a unica emitida
    senha        senha da chave do painel, que e cifrada em disco
    """

    def __init__(self, nome_painel=None, senha=None):
        if nome_painel:
            self.nome = (nome_painel if nome_painel.startswith(PREFIXO_PAINEL)
                         else PREFIXO_PAINEL + nome_painel)
        else:
            emitidos = paineis_emitidos()
            if not emitidos:
                raise ErroGHop(
                    f"nenhum painel emitido em {DIR_EMITIDOS}. Rode './ca.sh painel <nome>'.")
            if len(emitidos) > 1:
                curtos = ", ".join(n[len(PREFIXO_PAINEL):] for n in emitidos)
                raise ErroGHop(f"ha mais de um painel emitido ({curtos}). Escolha um.")
            self.nome = emitidos[0]

        self.cert = os.path.join(DIR_EMITIDOS, self.nome + ".crt")
        self.chave = os.path.join(DIR_EMITIDOS, self.nome + ".key")
        for arquivo in (ARQ_CA, self.cert, self.chave):
            if not os.path.exists(arquivo):
                raise ErroGHop(f"{arquivo} nao encontrado.")
        self.senha = senha
        self.listas = Listas()
        # Nao se chama 'filtro': esse nome e do METODO que le o filtro de um
        # no. Atributo e metodo com o mesmo nome deixam a chamada virar
        # 'Filtro nao e chamavel' dentro de uma thread -- e a tela so nao
        # atualiza. Mesma pedra em que 'listas_dns' ja tropecou.
        self.regras_filtro = Filtro()

    # ------------------------------------------------------------ cadastro

    def nos(self):
        """{nome: {'endereco': str, 'porta': int, 'tipo': str}}, do disco."""
        if not os.path.exists(ARQ_NOS):
            return {}
        try:
            with open(ARQ_NOS, encoding="utf-8") as arquivo:
                dados = json.load(arquivo)
        except (OSError, json.JSONDecodeError) as falha:
            raise ErroGHop(f"nao consegui ler {ARQ_NOS}: {falha}")
        registro = dados.get("nos")
        if not isinstance(registro, dict):
            return {}
        # Cadastro anterior ao campo 'tipo' vira lojmIt: era o unico tipo que
        # existia quando eles foram gravados.
        for entrada in registro.values():
            entrada.setdefault("tipo", TIPO_PADRAO)
            # O tipo 'gateway' foi renomeado para 'lojmIt'. Sem esta linha,
            # todo no ja cadastrado abriria dizendo "tipo nao tem visao
            # definida" -- o nome do tipo esta GRAVADO no nos.json de quem
            # cadastrou antes, e trocar a tabela nao reescreve o disco.
            if entrada.get("tipo") in TIPOS_RENOMEADOS:
                entrada["tipo"] = TIPOS_RENOMEADOS[entrada["tipo"]]
        return registro

    def _grava(self, nos):
        os.makedirs(os.path.dirname(ARQ_NOS), exist_ok=True)
        # Escreve ao lado e troca: interrupcao no meio nao deixa cadastro
        # pela metade, e o painel nao pode perder a lista de nos.
        temporario = ARQ_NOS + ".novo"
        try:
            with open(temporario, "w", encoding="utf-8") as arquivo:
                json.dump({"nos": nos}, arquivo, ensure_ascii=False, indent=2)
                arquivo.write("\n")
            os.chmod(temporario, 0o600)
            os.replace(temporario, ARQ_NOS)
        except OSError as falha:
            raise ErroGHop(f"nao consegui gravar {ARQ_NOS}: {falha}")

    def adiciona_no(self, nome, endereco, tipo=TIPO_PADRAO, testar=True):
        """Cadastra ou atualiza um no. Devolve (endereco_anterior, novo).

        Com testar=True faz o handshake antes de gravar: cadastrar sem
        conferir e cadastrar um engano, e o engano so aparece meses depois.
        """
        valida_nome(nome)
        if tipo not in TIPOS:
            conhecidos = ", ".join(sorted(TIPOS))
            raise ErroGHop(f"tipo de no desconhecido: {tipo!r}. Ha: {conhecidos}.")
        host, porta = separa_endereco(endereco)
        if testar:
            self.conecta(nome, host, porta).close()

        nos = self.nos()
        anterior = nos.get(nome)
        nos[nome] = {"endereco": host, "porta": porta, "tipo": tipo}
        self._grava(nos)
        antes = (f"{anterior['endereco']}:{anterior['porta']}" if anterior else None)
        return antes, f"{host}:{porta}"

    def tipo_de(self, nome):
        nos = self.nos()
        if nome not in nos:
            raise ErroGHop(f"no '{nome}' nao cadastrado.")
        return nos[nome].get("tipo", TIPO_PADRAO)

    def remove_no(self, nome):
        nos = self.nos()
        if nome not in nos:
            raise ErroGHop(f"no '{nome}' nao esta cadastrado.")
        del nos[nome]
        self._grava(nos)

    def endereco_de(self, nome):
        nos = self.nos()
        if nome not in nos:
            conhecidos = ", ".join(sorted(nos)) or "nenhum"
            raise ErroGHop(f"no '{nome}' nao cadastrado. Conhecidos: {conhecidos}.")
        return nos[nome]["endereco"], nos[nome]["porta"]

    # --------------------------------------------------------------- canal

    def _contexto(self):
        contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # Validacao por CN, feita em conecta() -- nao pelo hostname do TLS,
        # que olharia para o endereco. Endereco nao identifica maquina.
        contexto.check_hostname = False
        contexto.minimum_version = ssl.TLSVersion.TLSv1_3
        contexto.load_verify_locations(ARQ_CA)
        try:
            contexto.load_cert_chain(self.cert, self.chave, password=self.senha)
        except ssl.SSLError:
            raise ErroGHop("nao consegui abrir a chave do painel: senha errada?")
        return contexto

    def conecta(self, no, host=None, porta=None):
        """Canal aberto e autenticado com um no. Quem abre, fecha. BLOQUEIA."""
        if host is None:
            host, porta = self.endereco_de(no)
        esperado = PREFIXO_AGENTE + no
        contexto = self._contexto()
        try:
            bruto = socket.create_connection((host, porta), timeout=TEMPO_LIMITE)
        except OSError as falha:
            raise ErroGHop(f"nao consegui falar com {host}:{porta}: {falha}")
        try:
            tls = contexto.wrap_socket(bruto)
        except ssl.SSLError as falha:
            bruto.close()
            raise ErroGHop(f"TLS recusado por {host}:{porta}: {falha}")
        except OSError as falha:
            bruto.close()
            raise ErroGHop(f"conexao perdida com {host}:{porta}: {falha}")

        visto = nome_comum(tls.getpeercert())
        if visto != esperado:
            tls.close()
            raise ErroGHop(
                f"quem atendeu em {host}:{porta} diz ser '{visto}', nao '{esperado}'.")
        return tls

    def executa(self, no, comando, argumentos=None):
        """Manda um comando a um no e devolve os dados. BLOQUEIA.

        Recusa comando fora de COMANDOS antes de abrir a conexao: quem tem
        tela nao deve conseguir inventar comando que o agente nao tem.
        """
        if comando not in COMANDOS:
            raise ErroGHop(f"comando desconhecido: {comando!r}. Ha: {', '.join(COMANDOS)}.")
        pedido = {"id": "1", "comando": comando, "argumentos": argumentos or {}}
        with self.conecta(no) as tls:
            tls.sendall(json.dumps(pedido).encode("utf-8") + b"\n")
            linha = tls.makefile("rb").readline(LIMITE_LINHA)
        if not linha:
            raise ErroGHop(f"{no} fechou a conexao sem responder.")
        try:
            resposta = json.loads(linha.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ErroGHop(f"resposta ilegivel de {no}.")
        if not resposta.get("ok"):
            erro = str(resposta.get("erro") or "")
            # O conjunto de comandos vive em DOIS lugares que tem de bater, e
            # a conferencia do painel ('comando not in COMANDOS', acima) so
            # sabe do lado de ca. Painel novo com agente velho passa por ela e
            # e recusado la, com um texto que nao diz o que fazer -- e o que
            # fazer nao e obvio: o que roda no no nao e o arquivo do
            # repositorio, entao copiar a arvore e reiniciar o servico nao
            # resolve. Tem de republicar.
            if erro.startswith("comando desconhecido"):
                raise ErroGHop(
                    f"{no} nao implementa '{comando}': o agente dessa maquina e "
                    f"mais antigo que este painel. Republique NA MAQUINA com "
                    f"'sudo <repositorio>/install.sh agente --sim' -- copiar a "
                    f"arvore nao basta, o que roda e /usr/local/sbin/ghop-agente.py.")
            raise ErroGHop(f"{no} recusou '{comando}': {erro}")
        return resposta.get("dados") or {}

    def sincroniza_monitoracao(self, no=None):
        """Leva a lista de IPs monitorados aos nos. BLOQUEIA.

        Sem 'no', vai a todos os cadastrados: o inventario e geral, e querer
        saber quem fala com um IP nao faz sentido em uma maquina so. Cada no
        recebe a lista inteira, nao um delta -- estado, e nao mensagem, para
        um envio perdido nao deixar IP orfao sendo observado para sempre.

        Devolve {no: total aceito} e {no: erro} para o que falhou, em vez de
        parar no primeiro: um no desligado nao pode impedir os outros.
        """
        ips = Cadastro().monitorados()
        alvos = [no] if no else sorted(self.nos())
        aceitos, falhas = {}, {}
        for nome in alvos:
            try:
                dados = self.executa(nome, "monitorar", {"ips": ips})
                aceitos[nome] = dados.get("total", 0)
            except ErroGHop as falha:
                falhas[nome] = str(falha)
        return aceitos, falhas

    def eventos(self, no, ip=None, dia=None, limite=None):
        """Eventos gravados num no para os IPs monitorados. BLOQUEIA."""
        argumentos = {}
        if ip:
            argumentos["ip"] = ip
        if dia:
            argumentos["dia"] = dia
        if limite:
            argumentos["limite"] = int(limite)
        return self.executa(no, "eventos", argumentos)

    def interfaces(self, no):
        """Interfaces de rede de um no, como estao agora. BLOQUEIA."""
        return self.executa(no, "interfaces")

    def rotas(self, no):
        """Rotas e regras de politica de um no, como estao agora. BLOQUEIA."""
        return self.executa(no, "rotas")

    def conexoes(self, no):
        """O mapa de quem falou com quem, acumulado pelo agente. BLOQUEIA.

        Nao e "as conexoes agora": o agente le a tabela do kernel de tempos
        em tempos e vai juntando os pares. Por isso a resposta traz 'desde',
        'intervalo' e 'vivas' -- quem desenha tem de poder dizer que fluxo
        curto entre duas amostras nao aparece.
        """
        return self.executa(no, "conexoes")

    def topologia_geral(self, nos=None):
        """A topologia de TODOS os nos, ja juntada por aparelho. BLOQUEIA.

        Devolve (linhas, por_no, falhas). 'linhas' e uma por aparelho --
        nao por (no, aparelho) --, porque a pergunta que so esta tela responde e "este
        aparelho aparece em quantas das minhas redes?". Atras de cada NAT os
        clientes colapsam num endereco so, e o mesmo celular visto no lojmIt
        de casa e noutro nao tem como se reconhecer la; aqui tem, pelo MAC.

        'por_no' e a resposta crua de cada um, que a tabela nao usa mas o
        DESENHO precisa: aparelho se junta entre maquinas, interface nao --
        cada no tem as suas, e um desenho so misturaria segmentos que nao se
        tocam.

        No que nao responde vira uma entrada em 'falhas' e os outros seguem:
        maquina desligada nao pode esvaziar a tela inteira.

        Em serie, de proposito por enquanto: sao quatro comandos por no, e
        parelelizar antes de existir o segundo no seria complicar por nada.
        Quem chama daqui ja esta fora da thread de UI.
        """
        alvos = nos if nos is not None else sorted(self.nos())
        aparelhos, por_no, falhas = {}, {}, {}
        for nome in alvos:
            try:
                dados = self.topologia(nome)
            except ErroGHop as falha:
                falhas[nome] = str(falha)
                continue
            por_no[nome] = dados
            for host in dados.get("hosts") or []:
                # A chave e a mesma do cruzamento de um no so: MAC quando ha,
                # e o IP como ultimo recurso -- que nao junta nada entre nos,
                # e esta certo que nao junte (o mesmo IP privado existe atras
                # de cada NAT, e afirmar que sao o mesmo seria invencao).
                mac = host.get("mac") or ""
                chave = mac or f"{nome}:{(host.get('ips') or ['?'])[0]}"
                linha = aparelhos.setdefault(chave, {
                    "mac": mac, "nome": "", "ips": [], "nos": [],
                    "fontes": [], "segmentos": [], "saida": False,
                })
                linha["nome"] = linha["nome"] or host.get("nome", "")
                linha["saida"] = linha["saida"] or bool(host.get("saida"))
                if nome not in linha["nos"]:
                    linha["nos"].append(nome)
                for ip in host.get("ips") or []:
                    if ip not in linha["ips"]:
                        linha["ips"].append(ip)
                for fonte in host.get("fontes") or []:
                    if fonte not in linha["fontes"]:
                        linha["fontes"].append(fonte)
                segmento = f"{nome}:{host.get('interface') or '-'}"
                if segmento not in linha["segmentos"]:
                    linha["segmentos"].append(segmento)

        for linha in aparelhos.values():
            linha["ips"].sort(key=_ordem_de_ip)
        # Quem aparece em mais de um no primeiro: e a unica informacao que
        # esta tela tem e a de um no so nao tinha.
        ordem = lambda l: (-len(l["nos"]), not l["mac"],
                           _ordem_de_ip(l["ips"][0] if l["ips"] else ""))
        return sorted(aparelhos.values(), key=ordem), por_no, falhas

    def trafego(self, no):
        """Bytes por segundo por interface nos ultimos minutos. BLOQUEIA."""
        return self.executa(no, "trafego")

    def vizinhos(self, no):
        """Tabela ARP/NDP de um no: quem esta ao alcance dele. BLOQUEIA.

        Cru, como o agente devolveu. Quem quer a topologia -- este cruzado
        com quem entrega endereco e quem esta no radio -- chama 'topologia'.
        """
        return self.executa(no, "vizinhos")

    def topologia(self, no):
        """Quem esta na rede deste no, cruzando TODAS as fontes. BLOQUEIA.

        Nenhuma fonte sozinha responde "quem esta aqui", e o buraco de cada
        uma e conhecido:

          vizinhos  quem falou (ARP/NDP). Nao ve quem esta calado.
          dhcp      quem PEDIU endereco a nos. Nao ve endereco fixo, nem LAN
                    cujo servidor DHCP e de outro.
          wifi      quem esta associado ao radio. Nao ve o lado do cabo.
          interfaces  o que a maquina E: quais segmentos existem, e qual
                    deles e a saida (rota padrao).

        Cruzar e o ponto, e a diferenca entre as fontes vale mais do que
        cada uma: aparelho no 'dhcp' e ausente dos 'vizinhos' tem concessao
        e esta calado (desligado, provavelmente); aparelho nos 'vizinhos' e
        ausente do 'dhcp' fala sem nunca ter pedido endereco -- fixo, ou de
        um DHCP que nao e o nosso. 'fontes' de cada host diz qual dos casos
        e, e e por isso que ela vai na resposta.

        A chave e o MAC, nunca o IP: o mesmo IP privado existe atras de cada
        NAT, e a concessao de hoje e de outro amanha. Vizinho sem MAC
        (entrada FAILED, ninguem respondeu) entra pelo IP e fica marcado
        assim -- e informacao, e nao um host de verdade.

        Papel ausente NAO e erro: 'dhcp' e 'wifi' sao recusados onde nao
        existem, e isso vira uma linha em 'faltas' em vez de derrubar a
        tela. Uma maquina sem nenhum dos dois ainda tem topologia.
        """
        dados = {"no": no, "faltas": {}}
        # Estas duas sao a topologia: sem elas nao ha o que desenhar, e o
        # erro tem de subir.
        rede = self.executa(no, "interfaces")
        vizinhanca = self.executa(no, "vizinhos")
        dados["quando"] = vizinhanca.get("quando", "")
        dados["rota_padrao"] = rede.get("rota_padrao") or {}
        dados["interfaces"] = rede.get("interfaces") or []

        opcionais = {}
        for comando in ("dhcp", "wifi"):
            try:
                opcionais[comando] = self.executa(no, comando)
            except ErroGHop as falha:
                opcionais[comando] = {}
                dados["faltas"][comando] = str(falha)

        # Os MACs da propria maquina: bridge e membros repetem o mesmo
        # endereco, e sem isto o no aparece como vizinho de si mesmo.
        meus = {i.get("mac", "").lower() for i in dados["interfaces"] if i.get("mac")}

        hosts = {}

        def host_de(mac, ip=""):
            """A ficha de um aparelho, criada na primeira fonte que o vir."""
            chave = mac or f"ip:{ip}"
            return hosts.setdefault(chave, {
                "mac": mac, "ips": [], "nome": "", "interface": "",
                "estado": "", "fontes": [], "no": "", "sem_mac": not mac,
            })

        def anota(ficha, fonte, ip=""):
            if fonte not in ficha["fontes"]:
                ficha["fontes"].append(fonte)
            if ip and ip not in ficha["ips"]:
                ficha["ips"].append(ip)

        for vizinho in vizinhanca.get("vizinhos") or []:
            mac = vizinho.get("mac", "")
            if mac and mac in meus:
                continue
            ficha = host_de(mac, vizinho.get("ip", ""))
            anota(ficha, "vizinho", vizinho.get("ip", ""))
            ficha["interface"] = ficha["interface"] or vizinho.get("interface", "")
            ficha["estado"] = vizinho.get("estado", "")
            if vizinho.get("roteador"):
                ficha["roteador"] = True

        for concessao in opcionais["dhcp"].get("concessoes") or []:
            mac = (concessao.get("mac") or "").lower()
            ficha = host_de(mac, concessao.get("ip", ""))
            anota(ficha, "dhcp", concessao.get("ip", ""))
            # O nome vem do cliente e nao se confere: e etiqueta, nao
            # identidade. Serve para o operador reconhecer o aparelho.
            ficha["nome"] = ficha["nome"] or concessao.get("nome", "")
            ficha["dhcp"] = {"estado": concessao.get("estado", ""),
                             "fim": concessao.get("fim", "")}

        for cliente in opcionais["wifi"].get("clientes") or []:
            mac = (cliente.get("mac") or "").lower()
            ficha = host_de(mac)
            anota(ficha, "wifi")
            ficha["wifi"] = {"sinal": cliente.get("sinal", ""),
                             "rx_bytes": cliente.get("rx_bytes", 0),
                             "tx_bytes": cliente.get("tx_bytes", 0)}
            ficha["interface"] = ficha["interface"] or opcionais["wifi"].get("radio", "")

        # A saida: o roteador de cima costuma estar na tabela de vizinhos, e
        # marca-lo e o que fecha o desenho para o lado de fora.
        acima = dados["rota_padrao"].get("via", "")
        # Um vizinho pode ser outro no cadastrado. E PALPITE, por endereco --
        # identidade e por nome, e so o certificado a prova. A tela mostra
        # como sugestao; ninguem decide nada com isto.
        por_endereco = {}
        for nome, entrada in self.nos().items():
            if nome != no:
                por_endereco.setdefault(entrada.get("endereco", ""), nome)

        # Aparelho que so o DHCP viu nao tem interface: concessao guarda o
        # endereco, nao por onde ele chegou. Mas o endereco basta -- se o IP
        # cai na rede de uma das interfaces, o segmento e aquele. Sem isto o
        # aparelho ia parar num galho "(sem segmento)" ao lado da bridge que
        # o atende, que e desenho errado e nao falta de dado.
        redes = []
        for interface in dados["interfaces"]:
            if interface.get("tipo") == "loopback":
                continue
            for endereco in interface.get("enderecos") or []:
                try:
                    redes.append((ipaddress.ip_network(endereco, strict=False),
                                  interface["nome"]))
                except ValueError:
                    continue

        def segmento_de(ips):
            """A interface cuja rede contem algum destes IPs, ou ''."""
            for texto in ips:
                try:
                    endereco = ipaddress.ip_address(texto)
                except ValueError:
                    continue
                for rede, nome in redes:
                    if endereco in rede:
                        return nome
            return ""

        # Vizinho sem MAC entrou pelo IP; se outra fonte trouxe esse mesmo IP
        # com MAC, os dois sao o mesmo aparelho e viram uma ficha so. Sem
        # isto o mesmo endereco aparece duas vezes na tela.
        com_mac = {ip: f for f in hosts.values() if not f["sem_mac"] for ip in f["ips"]}
        for chave, ficha in list(hosts.items()):
            if not ficha["sem_mac"]:
                continue
            dono = next((com_mac[ip] for ip in ficha["ips"] if ip in com_mac), None)
            if dono is None:
                continue
            for fonte in ficha["fontes"]:
                if fonte not in dono["fontes"]:
                    dono["fontes"].append(fonte)
            dono["estado"] = dono["estado"] or ficha["estado"]
            dono["interface"] = dono["interface"] or ficha["interface"]
            del hosts[chave]

        for ficha in hosts.values():
            ficha["ips"].sort(key=_ordem_de_ip)
            if not ficha["interface"]:
                ficha["interface"] = segmento_de(ficha["ips"])
            if acima and acima in ficha["ips"]:
                ficha["saida"] = True
            for ip in ficha["ips"]:
                if ip in por_endereco:
                    ficha["no"] = por_endereco[ip]
                    break

        # Quem fala primeiro, depois quem so tem concessao; dentro disso, por
        # interface e endereco. O que esta vivo agora fica no alto da tela.
        def ordem(ficha):
            return ("vizinho" not in ficha["fontes"], ficha["interface"],
                    _ordem_de_ip(ficha["ips"][0] if ficha["ips"] else ""))

        dados["hosts"] = sorted(hosts.values(), key=ordem)
        return dados


    def papeis(self, no):
        """Quais papeis do GHop estao instalados num no. BLOQUEIA.

        Devolve TODOS os que o agente reportar, acrescentando o que o painel
        sabe daquele papel (rotulo, comando, onde vai a tela) quando ha
        entrada em PAPEIS. Nao filtra: quem pergunta "o que existe nesta
        maquina" -- a tela Servicos -- precisa da lista inteira, inclusive do
        coletor e do lojmIt, que nao tem tela propria. Filtrar aqui fazia o
        coletor aparecer para sempre como "nao instalado", com os botoes de
        parar e desinstalar desligados mesmo com ele rodando.

        Quem monta aba ou visao continua protegido do papel que nao sabe
        desenhar: o construtor sai de gui.ABAS_DE_PAPEL/VISOES_DE_PAPEL, e
        papel sem construtor e ignorado la.
        """
        dados = self.executa(no, "papeis")
        dados["papeis"] = [
            dict(papel, **PAPEIS.get(papel.get("chave"), {}))
            for papel in dados.get("papeis", [])
        ]
        return dados

    def dhcp(self, no):
        """Concessoes do DHCP de um no. BLOQUEIA."""
        return self.executa(no, "dhcp")

    def dns(self, no):
        """Estado do resolvedor de um no e o que ele negou. BLOQUEIA."""
        return self.executa(no, "dns")

    def wifi(self, no):
        """Radio, rede e clientes associados de um no. BLOQUEIA."""
        return self.executa(no, "wifi")

    def nftables(self, no):
        """Firewall em vigor num no, com contadores. BLOQUEIA."""
        return self.executa(no, "nftables")

    def filtro(self, no):
        """Filtro de camada de aplicacao de um no: regras e bloqueios. BLOQUEIA.

        Leitura pura. Quem ESCREVE regra e 'sincroniza_filtro'.
        """
        return self.executa(no, "filtro")

    def sincroniza_filtro(self, no=None):
        """Leva as regras do filtro aos nos. ESCREVE. BLOQUEIA.

        Molde do 'sincroniza_monitoracao': estado inteiro, nao delta, e sem
        'no' vai a todos os cadastrados. A politica de saida e uma so para a
        infra -- ver a classe Filtro --, entao sincronizar e levar a mesma
        lista a quem tiver o papel.

        Devolve {no: total aceito} e {no: erro}, em vez de parar no primeiro:
        no sem o papel instalado RECUSA, e isso e normal, nao e falha da
        sincronizacao. Quem nao tem o filtro simplesmente aparece em falhas.
        """
        dados = self.regras_filtro.tudo()
        alvos = [no] if no else sorted(self.nos())
        aceitos, falhas = {}, {}
        for nome in alvos:
            try:
                resposta = self.executa(nome, "filtrar", {
                    "politica": dados["politica"], "regras": dados["regras"]})
                aceitos[nome] = resposta.get("total", 0)
            except ErroGHop as falha:
                falhas[nome] = str(falha)
        return aceitos, falhas

    def sistema(self, no):
        """Processador, memoria, disco e versoes de um no. BLOQUEIA."""
        return self.executa(no, "sistema")

    def acao(self, no):
        """Como vai (ou como terminou) a ultima acao de papel pedida. BLOQUEIA.

        Leitura pura: quem PEDE a acao e 'papel'. A tela de Servicos chama
        isto em laco enquanto o instalador roda do outro lado.
        """
        return self.executa(no, "acao")

    def papel(self, no, papel, acao):
        """Instala, inicia, para ou desinstala um papel num no. BLOQUEIA.

        MUDA A MAQUINA. Volta assim que a acao COMECA do outro lado -- o
        instalador roda destacado la, e o andamento se acompanha chamando
        'acao' em laco.

        A recusa de papel e de acao invalidos e do AGENTE, que tem a tabela
        fechada: conferir aqui tambem seria duplicar a lista num segundo
        lugar para sair de sincronia depois.
        """
        return self.executa(no, "papel", {"papel": papel, "acao": acao})

    # Pedaco do texto colado que cabe com folga no limite de linha do
    # agente (64 kB), ja contando o que o JSON acrescenta ao escapar.
    PEDACO_LISTA = 32 * 1024

    def listas_dns(self, no, especie=None, lista=None):
        """Listas do resolvedor de um no; com especie e lista, as regras dela.

        Nao se chama 'listas': esse nome ja e do objeto das listas branca e
        negra do painel (self.listas), e um metodo com o mesmo nome ficaria
        encoberto pelo atributo -- a chamada virava 'Listas nao e chamavel'
        dentro de uma thread, e a tela so nao atualizava.
        """
        argumentos = {}
        if especie:
            argumentos["especie"] = especie
        if lista:
            argumentos["lista"] = lista
        return self.executa(no, "listas", argumentos)

    def envia_lista(self, no, especie, lista, texto, progresso=None):
        """Manda o texto COLADO pelo operador e o grava como uma lista. BLOQUEIA.

        Vai em pedacos porque uma lista publica tem megabytes. Cada pedaco e
        uma conexao nova -- o protocolo e uma pergunta por conexao --, entao
        'progresso' existe para a tela nao parecer travada.

        O painel nao baixa nada: o texto vem da area de transferencia de
        quem olhou o arquivo e decidiu. Essa e a diferenca entre importar e
        confiar.
        """
        self.executa(no, "lista", {"acao": "iniciar", "especie": especie,
                                   "lista": lista})
        total = len(texto)
        enviado = 0
        while enviado < total:
            pedaco = texto[enviado:enviado + self.PEDACO_LISTA]
            self.executa(no, "lista", {"acao": "parte", "especie": especie,
                                       "lista": lista, "texto": pedaco})
            enviado += len(pedaco)
            if progresso:
                progresso(enviado, total)
        return self.executa(no, "lista", {"acao": "concluir", "especie": especie,
                                          "lista": lista})

    def muda_lista(self, no, especie, lista, acao):
        """Liga, desliga ou apaga uma lista do resolvedor. BLOQUEIA."""
        if acao not in ("ativar", "desativar", "remover"):
            raise ErroGHop(f"acao {acao!r} desconhecida.")
        return self.executa(no, "lista", {"acao": acao, "especie": especie,
                                          "lista": lista})

    def firewall(self, no, acao, **campos):
        """Cria ou apaga tabela, cadeia e regra do firewall. BLOQUEIA.

        MUDA A MAQUINA, e e a mudanca mais perigosa que o painel faz. Manda
        CAMPOS, nunca texto de regra: quem monta a linha do nft e o agente,
        que confere cada campo. O ruleset e reaplicado inteiro depois.
        """
        argumentos = {"acao": acao}
        argumentos.update({c: v for c, v in campos.items() if v not in (None, "")})
        return self.executa(no, "firewall", argumentos)

    def limpar(self, no, especie, dia=None):
        """Apaga os contadores de dominios OU de IPs de um dia. BLOQUEIA.

        O UNICO comando que destroi dado coletado, e nao ha desfazer. O
        agente aceita uma especie e um dia por vez, e nunca toca em
        'eventos' (o registro dos IPs monitorados) nem na contagem de
        clientes do DNS.

        Quem pergunta "tem certeza?" e a tela: aqui nao ha caixa de dialogo,
        pela mesma razao de sempre -- o nucleo nao pergunta nada a ninguem.
        """
        if especie not in ("dominios", "ips"):
            raise ErroGHop(f"especie {especie!r} desconhecida.")
        argumentos = {"especie": especie}
        if dia:
            argumentos["dia"] = dia
        return self.executa(no, "limpar", argumentos)

    def regra_lista(self, no, especie, lista, nome, acao="adicionar"):
        """Acrescenta ou tira UMA regra de uma lista do resolvedor. BLOQUEIA.

        MUDA A MAQUINA: com a lista ativa, o nome passa a ser negado (ou
        liberado) para a LAN inteira daquele no.
        """
        if acao not in ("adicionar", "remover"):
            raise ErroGHop(f"acao {acao!r} desconhecida.")
        if not (nome or "").strip():
            raise ErroGHop("informe a regra.")
        return self.executa(no, "lista", {
            "acao": acao + "_regra", "especie": especie, "lista": lista,
            "nome": nome.strip()})

    def resumo(self, no, dia=None, limite=None, ocultar_brancos=True,
               minutos=None):
        """Contadores por IP e por dominio de um no, ja classificados.

        O agente entrega numero cru; quem classifica e o painel, aqui, na
        LEITURA -- e o que faz uma regra nova reclassificar o historico
        inteiro sem recoletar nada.

        Com ocultar_brancos, o que a whitelist cobre sai da lista e vira
        contagem em 'ocultos'. O dado continua coletado e continua no banco do
        agente: a lista decide o que se ve, nao o que existe.

        Com 'minutos', o agente devolve so quem teve contato dentro da
        janela. O 'total' de cada linha continua sendo o do DIA -- o banco do
        coletor guarda contador acumulado, nao evento a evento. A janela diz
        QUEM apareceu, nunca QUANTO falou naquele intervalo.

        Cuidado com o limite: ele e aplicado pelo AGENTE, antes desta
        filtragem. Se as primeiras linhas forem todas conhecidas, sobra pouca
        coisa -- peca limite maior quando a whitelist crescer. 'ocultos' diz
        quanto sumiu, para isso nao passar despercebido.
        """
        argumentos = {}
        if dia:
            argumentos["dia"] = dia
        if limite:
            argumentos["limite"] = int(limite)
        if minutos:
            argumentos["minutos"] = int(minutos)
        dados = self.listas.classifica(self.executa(no, "resumo", argumentos))

        # Agente velho nao conhece 'minutos': ignora o argumento e devolve o
        # dia inteiro, calado. Recusar aqui e melhor do que rotular de "10
        # min" uma tela com tudo -- numero errado com nome certo e pior do
        # que erro nenhum.
        if minutos and dados.get("minutos") != int(minutos):
            raise ErroGHop(
                f"o agente de {no} nao entende janela de tempo no resumo "
                "(versao antiga). Atualize o ghop-agente.py naquela maquina.")

        if ocultar_brancos:
            ocultos = {}
            for especie in ("dominios", "ips"):
                linhas = dados.get(especie, [])
                # So a branca esconde. O que esta na negra fica, sempre.
                visiveis = [linha for linha in linhas if linha["classe"] != "branca"]
                ocultos[especie] = len(linhas) - len(visiveis)
                dados[especie] = visiveis
            dados["ocultos"] = ocultos
        return dados
