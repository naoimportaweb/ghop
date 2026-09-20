"""textos.py -- os rotulos da interface, fora do codigo.

O modelo e o dos Resources do .NET, e vale a pena dizer qual parte dele foi
copiada: um arquivo NEUTRO (`recursos/textos.json`, em ingles) e um SATELITE
por idioma (`textos.pt.json`, `textos.tlh.json`). Chave que falta no satelite
cai no neutro -- CHAVE A CHAVE, nao arquivo a arquivo. E o que permite comecar
uma traducao com dez linhas e ir crescendo, em vez de ter de traduzir tudo
antes de ver qualquer coisa: o que falta aparece em ingles, nao em branco.

Por isso o neutro e o unico que NAO pode ter buraco. Ele e o chao.

O idioma vem de `GHOP_IDIOMA`, no ambiente ou no `~/.env`; sem ele, `en`. A
escolha e lida UMA vez, na carga do modulo -- trocar de idioma exige reabrir o
painel, que e como o .NET tambem se comporta (a cultura e fixada quando a
aplicacao sobe).

Codigo curto, de proposito: `en`, `pt`, `tlh`. Alem de ser o padrao ISO, tem um
efeito pratico aqui -- o `publish.sh` confere todo `GHOP_*` do `~/.env` contra a
arvore e barra a publicacao se achar o valor no codigo. Uma palavra por extenso
("portugues") apareceria neste arquivo e faria a publicacao parar; `pt`, nao.

NAO importa o nucleo. O caminho e o contrario -- o nucleo importa daqui --, e
uma seta de volta fecharia um ciclo de import. E tambem por isso a leitura do
`~/.env` esta repetida aqui em vez de reusar `nucleo.segredo()`: aquela funcao
diz, pelo nome, que o que ela le e segredo, e idioma nao e. Ler um knob publico
por ela corroeria o unico aviso que ela da.
"""

import json
import os

DIR_RECURSOS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recursos")
IDIOMA_PADRAO = "en"
VARIAVEL = "GHOP_IDIOMA"
ARQ_ENV = os.path.expanduser("~/.env")


def _do_ambiente(nome):
    """Le `nome` do ambiente ou do ~/.env. None se nao houver."""
    valor = os.environ.get(nome)
    if valor and valor.strip():
        return valor.strip()
    try:
        with open(ARQ_ENV, encoding="utf-8") as arquivo:
            for linha in arquivo:
                chave, igual, resto = linha.partition("=")
                if igual and chave.strip() == nome:
                    return resto.strip().strip("'\"") or None
    except OSError:
        pass
    return None


def _carregar(nome_arquivo):
    """Os textos de um arquivo de recurso. Ausente ou quebrado -> vazio."""
    caminho = os.path.join(DIR_RECURSOS, nome_arquivo)
    try:
        with open(caminho, encoding="utf-8") as arquivo:
            return json.load(arquivo).get("textos", {})
    except (OSError, ValueError):
        # Arquivo de idioma ausente ou malformado nao derruba o painel: o
        # neutro responde por tudo. Um painel em ingles e um painel; um painel
        # que nao abre, nao.
        return {}


IDIOMA = (_do_ambiente(VARIAVEL) or IDIOMA_PADRAO).strip().lower()
_NEUTRO = _carregar("textos.json")
_SATELITE = {} if IDIOMA == IDIOMA_PADRAO else _carregar("textos.%s.json" % IDIOMA)


def T(chave, **campos):
    """O texto de `chave` no idioma corrente, caindo no neutro se faltar.

    Chave inexistente nos DOIS devolve a propria chave. E feio na tela, e e
    para ser: rotulo em branco passa despercebido numa revisao, "papel.novo.
    rotulo" no meio da janela nao passa -- e ja diz onde consertar.
    """
    texto = _SATELITE.get(chave) or _NEUTRO.get(chave) or chave
    return texto.format(**campos) if campos else texto


def idiomas_disponiveis():
    """Os idiomas que tem arquivo em recursos/, comecando pelo neutro."""
    achados = [IDIOMA_PADRAO]
    try:
        for nome in sorted(os.listdir(DIR_RECURSOS)):
            if nome.startswith("textos.") and nome.endswith(".json"):
                codigo = nome[len("textos."):-len(".json")]
                if codigo and codigo not in achados:
                    achados.append(codigo)
    except OSError:
        pass
    return achados


def chaves_faltando(codigo):
    """Chaves do neutro que o satelite `codigo` nao tem. Base da guarda.

    Nao e so diagnostico: e o que um check automatico usa para reprovar um
    satelite com chave que o neutro nao conhece -- chave que so existe num
    idioma e texto que some quando alguem troca de idioma, e ninguem descobre
    ate acontecer.
    """
    satelite = _carregar("textos.%s.json" % codigo)
    return sorted(set(_NEUTRO) - set(satelite)), sorted(set(satelite) - set(_NEUTRO))
