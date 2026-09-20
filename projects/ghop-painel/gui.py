#!/usr/bin/env python3
"""Painel do GHop: janela PySide6 sobre o nucleo.

Casca descartavel. Nao ha uma linha de rede, de TLS ou de cadastro aqui --
tudo isso e do nucleo.py, que nao importa Qt. Se esta janela for jogada fora
amanha, o painel continua existindo.

Forma: MDI. A lista de nos fica a esquerda, sempre visivel; abrir um no abre
uma subjanela dele, e varias ficam abertas ao mesmo tempo. E o desenho que
corresponde ao trabalho: comparar o que duas maquinas estao fazendo e o motivo
de o painel existir -- atras de cada NAT os clientes colapsam em um endereco
so, e so daqui se ve o conjunto.

Cada TIPO de no oferece visoes diferentes: um lojmIt se olha pela saida, um
servidor web pelo servico. O tipo vem do cadastro, no nucleo. Visao cujo
comando o agente ainda nao implementa aparece dizendo isso, em vez de dar erro
ou, pior, de inventar dado.

Toda chamada ao nucleo que fala com agente BLOQUEIA, entao nenhuma acontece na
thread de UI: vao todas para o QThreadPool via Tarefa.

Uso:
  ./gui.py

Variaveis de ambiente: as mesmas do nucleo (GHOP_PAINEL, GHOP_CA_DIR,
GHOP_PAINEL_SENHA).
"""

import json
import os
import sys
import time

from PySide6.QtCore import (
    QObject, QRect, QRunnable, QSize, Qt, QThreadPool, QTimer, Signal, Slot)
from PySide6.QtGui import (
    QAction, QBrush, QColor, QFont, QFontMetrics, QIcon, QPainter, QPen,
    QPixmap)
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QDockWidget,
    QFormLayout, QFrame,
    QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMainWindow, QMdiArea, QMdiSubWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout, QWidget,
)

import estilo
import nucleo
from nucleo import ErroGHop, Painel
from textos import T

PAPEL_NO = Qt.UserRole
# A linha inteira viaja na celula: com ordenacao ligada o indice da tabela
# nao corresponde mais a ordem em que os dados chegaram.
PAPEL_LINHA = Qt.UserRole + 1


# ----------------------------------------------------------------- trabalho

class Sinais(QObject):
    pronto = Signal(object)
    falhou = Signal(str)


class Tarefa(QRunnable):
    """Roda uma funcao do nucleo fora da thread de UI.

    Existe porque toda conversa com agente bloqueia: um no fora do ar
    congelaria a janela inteira ate o timeout.
    """

    def __init__(self, funcao, *args, **kwargs):
        super().__init__()
        self.funcao, self.args, self.kwargs = funcao, args, kwargs
        self.sinais = Sinais()

    @Slot()
    def run(self):
        try:
            self.sinais.pronto.emit(self.funcao(*self.args, **self.kwargs))
        except ErroGHop as falha:
            self.sinais.falhou.emit(str(falha))
        except Exception as falha:  # noqa: BLE001 - casca nao cai por causa de um no
            self.sinais.falhou.emit(f"{type(falha).__name__}: {falha}")


def tabela(colunas, ordenar_por):
    """QTableWidget de leitura, ja ajustada. So aparencia.

    ordenar_por e a coluna de contagem: a analise de saida se le do mais
    pedido para o menos, e a tabela nasce assim. Fica como indicador do
    cabecalho, entao vale tambem nas recargas seguintes -- e se o operador
    clicar noutra coluna, e a escolha dele que passa a valer.
    """
    widget = QTableWidget(0, len(colunas))
    widget.setHorizontalHeaderLabels(colunas)
    widget.setEditTriggers(QTableWidget.NoEditTriggers)
    widget.setSelectionBehavior(QTableWidget.SelectRows)
    widget.setAlternatingRowColors(True)
    widget.verticalHeader().setVisible(False)
    widget.setSortingEnabled(True)
    # Numero e data se ajustam ao conteudo; o nome fica com a sobra. Sem isto
    # as datas saem cortadas, que e justamente o que se quer ler.
    colunas_widget = widget.horizontalHeader()
    colunas_widget.setSectionResizeMode(QHeaderView.ResizeToContents)
    colunas_widget.setSectionResizeMode(0, QHeaderView.Stretch)
    widget.sortByColumn(ordenar_por, Qt.DescendingOrder)
    return widget


def cabecalho(titulo, subtitulo=""):
    """Faixa de identificacao no topo de uma janela.

    Toda janela do painel abre dizendo o que e. Com MDI e varios dialogos
    abertos ao mesmo tempo, uma tela sem nome vira adivinhacao -- e duas
    telas parecidas (dominio e IP, por exemplo) sao indistinguiveis pelo
    conteudo sozinho.
    """
    faixa = QWidget()
    leiaute = QVBoxLayout(faixa)
    leiaute.setContentsMargins(0, 0, 0, 6)
    leiaute.setSpacing(1)

    nome = QLabel(titulo)
    fonte = nome.font()
    fonte.setPointSize(fonte.pointSize() + 3)
    fonte.setBold(True)
    nome.setFont(fonte)
    nome.setTextInteractionFlags(Qt.TextSelectableByMouse)
    leiaute.addWidget(nome)

    if subtitulo:
        detalhe = QLabel(subtitulo)
        detalhe.setStyleSheet("color: palette(mid);")
        detalhe.setTextInteractionFlags(Qt.TextSelectableByMouse)
        detalhe.setWordWrap(True)
        leiaute.addWidget(detalhe)
    return faixa


def celula(valor, numero=False):
    """Celula de tabela. Numero entra como numero para ordenar direito."""
    item = QTableWidgetItem()
    if numero:
        item.setData(Qt.DisplayRole, int(valor))
        item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
    else:
        item.setData(Qt.DisplayRole, str(valor))
    return item


# ------------------------------------------------------------------ visoes

class VisaoIndisponivel(QWidget):
    """Visao prevista para o tipo do no, mas que o agente ainda nao serve.

    Dizer isso e melhor que esconder a aba: quem olha fica sabendo que aquilo
    esta previsto e ainda nao existe, em vez de achar que o no nao tem nada.
    """

    def __init__(self, visao):
        super().__init__()
        leiaute = QVBoxLayout(self)
        leiaute.addStretch()
        titulo = QLabel(visao["rotulo"])
        fonte = titulo.font()
        fonte.setPointSize(fonte.pointSize() + 3)
        fonte.setBold(True)
        titulo.setFont(fonte)
        titulo.setAlignment(Qt.AlignCenter)
        leiaute.addWidget(titulo)
        for texto in (visao["descricao"],
                      T("msg.comando_nao_implementado").format(visao["comando"]),
                      T("msg.acrescentar_comando")):
            rotulo = QLabel(texto)
            rotulo.setAlignment(Qt.AlignCenter)
            rotulo.setWordWrap(True)
            rotulo.setStyleSheet("color: palette(mid);")
            leiaute.addWidget(rotulo)
        leiaute.addStretch()


class VisaoSaida(QWidget):
    """O que a maquina pediu para fora: dominios e IPs, so contados.

    O agente entrega numero cru; quem classifica e o nucleo, na leitura, pela
    whitelist do painel -- e o que faz uma regra nova reclassificar o
    historico inteiro sem recoletar nada.

    Por padrao o que a whitelist cobre nao aparece, e o rodape diz quantos
    sumiram. 'Mostrar conhecidos' traz de volta, em cinza, para conferir a
    propria lista. Em nenhum dos casos o dado deixa de existir no agente.

    Os botoes de janela respondem "QUEM apareceu nos ultimos N minutos", e
    nao "quanto falou nesses N minutos": o coletor guarda contador acumulado
    por chave, sem evento a evento, entao a coluna Total continua sendo a do
    dia. Por isso o cabecalho dela muda de nome quando ha janela ligada --
    numero certo com rotulo errado seria o pior dos dois mundos.
    """

    def __init__(self, painel, no, avisar):
        super().__init__()
        self.painel, self.no, self.avisar = painel, no, avisar
        self.pool = QThreadPool.globalInstance()

        leiaute = QVBoxLayout(self)

        controles = QHBoxLayout()
        controles.addWidget(QLabel(T("texto.dia")))
        self.dia = QLineEdit()
        self.dia.setPlaceholderText(T("dica.hoje_dd_mm_aaaa"))
        # Minimo junto com o maximo: so com teto, a linha de controles
        # espremia o campo ate 'h...' quando os botoes de janela entraram.
        self.dia.setMinimumWidth(120)
        self.dia.setMaximumWidth(140)
        controles.addWidget(self.dia)
        controles.addWidget(QLabel(T("texto.limite")))
        self.limite = QSpinBox()
        self.limite.setRange(1, 1000)
        self.limite.setValue(100)
        controles.addWidget(self.limite)
        self.botao = QPushButton(T("botao.atualizar"))
        self.botao.clicked.connect(self.recarrega)
        controles.addWidget(self.botao)

        # Janela de tempo. 'minutos = None' e o dia inteiro, que continua
        # sendo o padrao: quem abre a tela quer o dia, nao um recorte.
        self.minutos = None
        self.botoes_janela = {}
        for rotulo, quantos in (("Ultimos 10 min", 10),
                                ("Ultima meia hora", 30),
                                ("Ultima 1 hora", 60),
                                # "Tudo" e o dia inteiro, nao a historia toda:
                                # o banco do coletor e um por dia, e quem
                                # escolhe qual e o campo 'Dia' ao lado.
                                ("Tudo", None)):
            botao = QPushButton(rotulo)
            botao.setCheckable(True)
            botao.setChecked(quantos is None)
            botao.clicked.connect(
                lambda _=False, q=quantos: self.usa_janela(q))
            controles.addWidget(botao)
            self.botoes_janela[quantos] = botao

        # O unico botao desta tela que DESTROI. Fica depois de um separador
        # visual (o addStretch abaixo nao serve: e o que empurra o estado
        # para a direita), longe dos de janela, porque errar de botao aqui
        # nao tem desfazer.
        self.limpar = QPushButton(T("botao.limpar_coletado"))
        self.limpar.setToolTip(
            T("ajuda.apaga_do_agente_os"))
        self.limpar.clicked.connect(self.pede_limpeza)
        controles.addWidget(self.limpar)
        # O que a whitelist cobre some daqui, mas continua coletado no agente.
        # A caixa e para conferir a propria lista, nao para operar o dia a dia.
        self.mostrar_conhecidos = QCheckBox(T("opcao.mostrar_conhecidos"))
        self.mostrar_conhecidos.setToolTip(
            T("ajuda.exibe_tambem_o_que"))
        self.mostrar_conhecidos.toggled.connect(self.recarrega)
        controles.addWidget(self.mostrar_conhecidos)
        controles.addStretch()
        self.estado = QLabel("")
        controles.addWidget(self.estado)
        leiaute.addLayout(controles)

        self.abas = QTabWidget()
        self.dominios = tabela([T("coluna.dominio"), T("coluna.total"), T("coluna.primeiro"), T("coluna.ultimo")], 1)
        self.ips = tabela([T("coluna.ip"), T("coluna.porta"), T("coluna.total"), T("coluna.primeiro"), T("coluna.ultimo")], 2)
        self.dominios.itemDoubleClicked.connect(
            lambda item: self.abre_detalhe("dominios", item))
        self.ips.itemDoubleClicked.connect(
            lambda item: self.abre_detalhe("ips", item))
        self.abas.addTab(self.dominios, T("aba.dominios"))
        self.abas.addTab(self.ips, T("aba.ips"))
        leiaute.addWidget(self.abas)

    def pede_limpeza(self):
        """Apaga no agente os contadores da aba aberta. Pergunta antes.

        Age so sobre a especie VISIVEL: quem esta olhando dominios apaga
        dominios. Um botao que limpasse os dois de uma vez seria o dobro do
        estrago por um clique errado.
        """
        especie = "dominios" if self.abas.currentIndex() == 0 else "ips"
        rotulo = "dominios" if especie == "dominios" else "IPs"
        dia = self.dia.text().strip() or "hoje"
        visiveis = (self.dominios if especie == "dominios" else self.ips).rowCount()
        resposta = QMessageBox.question(
            self, "GHop",
            T("msg.apagar_no_agente_todos_os").format(rotulo, dia, self.no, visiveis),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if resposta != QMessageBox.Yes:
            return
        self.limpar.setEnabled(False)
        self.estado.setText(T("texto.limpando"))
        tarefa = Tarefa(self.painel.limpar, self.no, especie,
                        self.dia.text().strip() or None)
        tarefa.sinais.pronto.connect(self.limpou)
        tarefa.sinais.falhou.connect(self.limpeza_falhou)
        self.pool.start(tarefa)

    @Slot(object)
    def limpou(self, dados):
        self.limpar.setEnabled(True)
        self.avisar(T("msg.linha_s_de_apagada_s").format(self.no, dados.get('apagadas'), dados.get('especie'), dados.get('dia')))
        self.recarrega()

    @Slot(str)
    def limpeza_falhou(self, mensagem):
        self.limpar.setEnabled(True)
        self.estado.setText(T("texto.falhou"))
        self.avisar(f"{self.no}: {mensagem}")

    def usa_janela(self, minutos):
        """Troca a janela de tempo e recarrega. Botao aceso = janela em uso."""
        self.minutos = minutos
        for quantos, botao in self.botoes_janela.items():
            botao.setChecked(quantos == minutos)
        # A coluna Total nao muda de conteudo com a janela -- muda o que ela
        # QUER DIZER na frase que a tela conta. Renomear e mais honesto do
        # que deixar 'Total' sugerindo total da janela.
        rotulo = "Total (dia)" if minutos else "Total"
        self.dominios.horizontalHeaderItem(1).setText(rotulo)
        self.ips.horizontalHeaderItem(2).setText(rotulo)
        self.recarrega()

    def recarrega(self):
        self.botao.setEnabled(False)
        self.estado.setText(T("texto.consultando"))
        tarefa = Tarefa(self.painel.resumo, self.no,
                        dia=self.dia.text().strip() or None,
                        limite=self.limite.value(),
                        minutos=self.minutos,
                        ocultar_brancos=not self.mostrar_conhecidos.isChecked())
        tarefa.sinais.pronto.connect(self.preenche)
        tarefa.sinais.falhou.connect(self.deu_errado)
        self.pool.start(tarefa)

    def _pinta(self, tabela_alvo, i, linha):
        """Cor conforme a lista que pegou a linha, com a regra no tooltip.

        Cinza: whitelist -- so aparece com 'Mostrar conhecidos' marcado, e
        serve para conferir QUAL regra pegou o que.
        Vermelho: blacklist -- aparece sempre, e nao ha caixa que esconda.
        O que nao tem cor e o que ainda nao tem nome, que e o que interessa.
        """
        classe = linha.get("classe")
        if not classe:
            return
        if classe == "negra":
            cor, rotulo = QBrush(QColor(190, 40, 40)), "blacklist"
        else:
            cor, rotulo = QBrush(QColor(140, 140, 140)), "whitelist"
        for coluna in range(tabela_alvo.columnCount()):
            item = tabela_alvo.item(i, coluna)
            if item is not None:
                item.setForeground(cor)
                item.setToolTip(f"{rotulo}: {linha.get('regra', '')}")

    @Slot(object)
    def preenche(self, dados):
        self.botao.setEnabled(True)
        linhas = dados.get("dominios", [])
        self.dominios.setSortingEnabled(False)
        self.dominios.setRowCount(len(linhas))
        for i, linha in enumerate(linhas):
            principal = celula(linha["dominio"])
            principal.setData(PAPEL_LINHA, linha)
            self.dominios.setItem(i, 0, principal)
            self.dominios.setItem(i, 1, celula(linha["total"], numero=True))
            self.dominios.setItem(i, 2, celula(linha["primeiro"]))
            self.dominios.setItem(i, 3, celula(linha["ultimo"]))
            self._pinta(self.dominios, i, linha)
        self.dominios.setSortingEnabled(True)

        linhas = dados.get("ips", [])
        self.ips.setSortingEnabled(False)
        self.ips.setRowCount(len(linhas))
        for i, linha in enumerate(linhas):
            principal = celula(linha["ip"])
            principal.setData(PAPEL_LINHA, linha)
            self.ips.setItem(i, 0, principal)
            self.ips.setItem(i, 1, celula(linha["porta"], numero=True))
            self.ips.setItem(i, 2, celula(linha["total"], numero=True))
            self.ips.setItem(i, 3, celula(linha["primeiro"]))
            self.ips.setItem(i, 4, celula(linha["ultimo"]))
            self._pinta(self.ips, i, linha)
        self.ips.setSortingEnabled(True)

        self.abas.setTabText(0, T("aba.contagem").format(T("aba.dominios"), self.dominios.rowCount()))
        self.abas.setTabText(1, T("aba.contagem").format(T("aba.ips"), self.ips.rowCount()))

        # Quantos a whitelist tirou da vista. Dizer isso importa: o limite e
        # aplicado pelo AGENTE antes de filtrar, entao uma lista grande pode
        # esvaziar a tela sem que nada esteja errado.
        ocultos = dados.get("ocultos") or {}
        total_oculto = sum(ocultos.values())
        estado = f"dia {dados.get('dia')}"
        # Com janela, dizer desde QUANDO e o que o corte significa. Sem isso a
        # tela some com linha por motivo invisivel, que e como se desconfia de
        # ferramenta de vigilancia.
        if dados.get("minutos"):
            estado += T("texto.ultimos_min").format(
                dados["minutos"], (dados.get("desde") or "")[11:16])
        if total_oculto:
            estado += (f"  -  {total_oculto} ocultos pela whitelist"
                       f" ({ocultos.get('dominios', 0)} dom / {ocultos.get('ips', 0)} ip)")
        self.estado.setText(estado)

    def abre_detalhe(self, especie, item):
        tabela_alvo = self.dominios if especie == "dominios" else self.ips
        principal = tabela_alvo.item(item.row(), 0)
        linha = principal.data(PAPEL_LINHA) if principal else None
        if not linha:
            return
        dialogo = JanelaDetalhe(especie, linha, self.no, self)
        dialogo.exec()
        # Classificou? A leitura precisa refletir isso agora, nao no proximo
        # clique em Atualizar.
        if dialogo.mudou:
            self.recarrega()

    @Slot(str)
    def deu_errado(self, mensagem):
        self.botao.setEnabled(True)
        self.estado.setText(T("texto.falhou"))
        self.avisar(f"{self.no}: {mensagem}")


def a_vista(widget):
    """Se este widget esta REALMENTE sendo visto agora.

    isVisible() nao basta: uma subjanela do MDI atras de outra, ou minimizada,
    continua 'visivel' para o Qt. visibleRegion() vazia diz que nenhum pixel
    dela esta na tela -- e e isso que decide se vale perguntar ao agente.

    A regra: nada no painel consulta um no que ninguem esta olhando. Cada
    pergunta atravessa a rede e ocupa o agente da maquina observada, que
    pode ser fraca; deixar rodando atras de uma janela fechada seria gastar
    a maquina do outro por nada.
    """
    return widget.isVisible() and not widget.visibleRegion().isEmpty()


def botao_segundo_plano():
    """Botao de estado que libera a consulta a continuar sem ninguem olhando.

    Nasce DESLIGADO, e e assim que tem de ser: a regra da casa e nao gastar
    a maquina observada por nada. Ligado, ele diz 'eu sei o que estou
    fazendo, siga perguntando mesmo com a janela atras' -- serve para
    acompanhar um pico enquanto se trabalha noutra tela.

    Fica vermelho quando ligado porque, ao contrario do resto do painel,
    e um estado que continua custando depois que se olha para outro lado.
    """
    botao = QPushButton(T("botao.segundo_plano"))
    botao.setCheckable(True)
    botao.setChecked(False)
    botao.setToolTip(
        T("ajuda.desligado_as_perguntas_param"))
    botao.setStyleSheet(
        "QPushButton:checked { background: #a03030; color: white;"
        " font-weight: bold; }")
    return botao


def taxa_legivel(bytes_por_segundo):
    """'12,3 kB/s', '1,05 MB/s'. Em bytes, que e o que o contador conta."""
    valor = float(bytes_por_segundo or 0)
    for unidade in ("B/s", "kB/s", "MB/s", "GB/s"):
        if valor < 1000 or unidade == "GB/s":
            texto = f"{valor:.0f}" if unidade == "B/s" else f"{valor:.2f}".rstrip("0").rstrip(".")
            return f"{texto} {unidade}".replace(".", ",")
        valor /= 1000
    return ""


class GraficoTrafego(QWidget):
    """Uma interface: RX e TX em bytes/s nos ultimos minutos, desenhados a mao.

    QPainter puro, de proposito: QtCharts e modulo a mais, e este grafico e
    duas linhas com escala. O eixo do tempo e a janela que o agente guarda
    (10 min), ancorado no 'agora' dele, para o grafico nao andar quando o
    relogio daqui difere do de la. A escala vertical e o maior valor da
    janela, arredondado para cima, e a mesma para RX e TX -- comparar os dois
    e o que se quer ver.
    """

    COR_RX = QColor(40, 120, 200)
    COR_TX = QColor(210, 120, 30)
    # As margens sao calculadas no paintEvent a partir da fonte: numero como
    # '500 kB/s' e palavra como 'agora' mudam de largura com o tema, e
    # margem fixa foi o que fez os rotulos se encavalarem.
    FOLGA = 8
    # Respiro entre a linha do nome e o topo da escala. Sem ele o nome fica
    # colado no maior valor do eixo e os dois se leem como uma coisa so.
    RESPIRO_TITULO = 20

    def __init__(self, nome, series=None, formata=taxa_legivel):
        """series: [(rotulo, cor, indice no ponto)]. Por omissao, RX e TX.

        Serve para qualquer coisa medida por segundo: bytes de interface,
        pacotes de cadeia do firewall. O que muda e quantas linhas se
        desenha e como o numero e escrito -- o resto do eixo e igual.
        """
        super().__init__()
        self.nome = nome
        self.series = series or (("RX", self.COR_RX, 1), ("TX", self.COR_TX, 2))
        self.formata = formata
        self.pontos = []
        self.agora = 0.0
        self.janela = 600
        self.setMinimumHeight(120)

    def atualiza(self, pontos, agora, janela):
        self.pontos, self.agora, self.janela = pontos, agora, janela
        if pontos:
            resumo = ", ".join(f"{rotulo} {self.formata(pontos[-1][i])}"
                               for rotulo, _, i in self.series)
            self.setToolTip(f"{self.nome}: {resumo}")
        else:
            self.setToolTip(T("ajuda.sem_amostras_ainda").format(self.nome))
        self.update()

    @staticmethod
    def _teto(valor):
        """Escala 'redonda' acima do maximo: 1, 2, 5 vezes potencia de 10."""
        if valor <= 0:
            return 1000.0
        potencia = 10 ** int(len(str(int(valor))) - 1)
        for fator in (1, 2, 5, 10):
            if valor <= fator * potencia:
                return float(fator * potencia)
        return float(10 * potencia)

    def _politica(self, pintor, metrica, x, y, largura, linha, fraco, politica):
        """A politica da cadeia, no pe da cascata, com borda tracejada.

        Tracejada de proposito: nao e uma regra, e o que sobra quando
        nenhuma casou. Desenhada sempre, inclusive em cadeia vazia, onde ela
        e a unica coisa que acontece.
        """
        cor = self.CORES.get((politica or "").lower(), self.COR_OUTRO)
        altura = linha + 8

        # Seta curta ligando a ultima regra a politica: o pacote "cai" ate aqui.
        meio = x + largura // 2
        pintor.setPen(QPen(fraco, 1, Qt.DotLine))
        pintor.drawLine(meio, y - 5, meio, y + 1)

        pintor.setPen(QPen(cor.darker(140), 1, Qt.DashLine))
        pintor.setBrush(QColor(cor.red(), cor.green(), cor.blue(), 35))
        pintor.drawRoundedRect(x, y + 2, largura, altura, 4, 4)
        pintor.setPen(fraco)
        pintor.drawText(x + 6, y + 2, largura - 12, altura, Qt.AlignLeft | Qt.AlignVCenter,
                        T("texto.nenhuma_casou"))
        pintor.setPen(cor.darker(150))
        fonte = pintor.font()
        fonte.setBold(True)
        pintor.setFont(fonte)
        pintor.drawText(x + 6, y + 2, largura - 12, altura,
                        Qt.AlignRight | Qt.AlignVCenter,
                        (politica or T("texto.sem_politica")).upper())
        fonte.setBold(False)
        pintor.setFont(fonte)

    def paintEvent(self, _evento):
        pintor = QPainter(self)
        pintor.setRenderHint(QPainter.Antialiasing)
        paleta = self.palette()
        largura, altura = self.width(), self.height()

        fonte = pintor.font()
        fonte.setPointSize(max(7, fonte.pointSize() - 1))
        pintor.setFont(fonte)
        metrica = pintor.fontMetrics()
        linha_texto = metrica.height()
        texto_cor = paleta.color(paleta.ColorRole.WindowText)
        grade_cor = paleta.color(paleta.ColorRole.Mid)

        maximo = max((max(p[i] for _, _, i in self.series) for p in self.pontos),
                     default=0)
        teto = self._teto(maximo)
        rotulos_y = [self.formata(teto * i / 4) for i in range(5)]
        rotulos_x = ["agora"] + [f"-{m} min" for m in range(2, self.janela // 60 + 1, 2)]

        # Margens medidas no texto que de fato vai ser escrito. Fixas, elas
        # cortavam o 'agora' na direita e encavalavam o '0 B/s' com o
        # '-10 min' no canto de baixo.
        esquerda = max(metrica.horizontalAdvance(t) for t in rotulos_y) + self.FOLGA
        direita = metrica.horizontalAdvance(rotulos_x[0]) // 2 + self.FOLGA
        x0, x1 = esquerda, largura - direita
        y0 = linha_texto + 4 + self.RESPIRO_TITULO   # faixa do titulo
        y1 = altura - linha_texto - 4                # faixa das marcas de tempo
        if x1 - x0 < 40 or y1 - y0 < 24:
            return

        # Titulo: nome a esquerda, valor de agora a direita, com RX e TX na
        # propria cor -- a legenda vive aqui, e nao mais dentro do desenho,
        # onde tapava o comeco das linhas.
        faixa_titulo = linha_texto + 4
        direita_texto = largura - self.FOLGA
        if self.pontos:
            for prefixo, cor, indice in reversed(self.series):
                texto = f"{prefixo} {self.formata(self.pontos[-1][indice])}"
                largura_texto = metrica.horizontalAdvance(texto) + self.FOLGA
                direita_texto -= largura_texto
                pintor.setPen(cor)
                pintor.drawText(direita_texto, 0, largura_texto, faixa_titulo,
                                Qt.AlignRight | Qt.AlignVCenter, texto)
        else:
            texto = T("texto.sem_amostras")
            largura_texto = metrica.horizontalAdvance(texto) + self.FOLGA
            direita_texto -= largura_texto
            pintor.setPen(texto_cor)
            pintor.drawText(direita_texto, 0, largura_texto, faixa_titulo,
                            Qt.AlignRight | Qt.AlignVCenter, texto)
        # O nome fica com o que sobrou, encurtado se preciso: o valor de
        # agora e mais importante que ler 'enp1s0' inteiro numa janela
        # estreita, e sem isto os dois se sobrepunham.
        espaco_nome = max(0, direita_texto - 2 * self.FOLGA)
        fonte_nome = pintor.font()
        fonte_nome.setBold(True)
        pintor.setFont(fonte_nome)
        pintor.setPen(texto_cor)
        pintor.drawText(self.FOLGA, 0, espaco_nome, faixa_titulo,
                        Qt.AlignLeft | Qt.AlignVCenter,
                        QFontMetrics(fonte_nome).elidedText(
                            self.nome, Qt.ElideRight, espaco_nome))
        pintor.setFont(fonte)

        # Grade horizontal, com o valor na margem da esquerda.
        for i, rotulo in enumerate(rotulos_y):
            y = y1 - (y1 - y0) * i / 4
            pintor.setPen(QPen(grade_cor, 1, Qt.DotLine))
            pintor.drawLine(x0, int(y), x1, int(y))
            pintor.setPen(texto_cor)
            pintor.drawText(0, int(y) - linha_texto // 2, esquerda - self.FOLGA, linha_texto,
                            Qt.AlignRight | Qt.AlignVCenter, rotulo)

        # Marcas de tempo, da direita para a esquerda: 'agora' e o que
        # importa, e e ele que fica ancorado na borda.
        ocupado = largura + self.FOLGA
        for i, rotulo in enumerate(rotulos_x):
            x = x1 - (x1 - x0) * (i * 120) / self.janela
            if x < x0 - 1:
                break
            pintor.setPen(QPen(grade_cor, 1, Qt.DotLine))
            pintor.drawLine(int(x), y0, int(x), y1)
            largura_texto = metrica.horizontalAdvance(rotulo)
            # Preso dentro do widget: sem isto o primeiro e o ultimo saiam
            # pela borda, e era o que aparecia cortado.
            esquerda_texto = min(max(0, int(x) - largura_texto // 2), largura - largura_texto)
            # Numa janela estreita nao cabem todas as marcas: escreve so as
            # que nao encostam na anterior. A linha da grade fica de todo
            # jeito, entao a escala continua legivel.
            if esquerda_texto + largura_texto + self.FOLGA > ocupado:
                continue
            ocupado = esquerda_texto
            pintor.setPen(texto_cor)
            pintor.drawText(esquerda_texto, y1 + 2, largura_texto, linha_texto,
                            Qt.AlignCenter, rotulo)

        if not self.pontos:
            return

        def ponto(instante, valor):
            fracao = 1 - (self.agora - instante) / self.janela
            x = x0 + (x1 - x0) * min(1.0, max(0.0, fracao))
            y = y1 - (y1 - y0) * min(1.0, valor / teto)
            return x, y

        for _, cor, indice in self.series:
            pintor.setPen(QPen(cor, 1.5))
            anterior = None
            for p in self.pontos:
                atual_xy = ponto(p[0], p[indice])
                if anterior is not None:
                    pintor.drawLine(int(anterior[0]), int(anterior[1]),
                                    int(atual_xy[0]), int(atual_xy[1]))
                anterior = atual_xy


class AbaPapel(QWidget):
    """Base das abas que existem so quando o no tem aquele papel do GHop.

    Cada uma pede o seu comando, monta as proprias tabelas e nada mais. A
    aba so e criada depois de 'papeis' dizer que o papel esta la, entao aqui
    nao ha caso de 'nao instalado'.

    Quem tem GRAFICO poe AO_VIVO = True e ganha, de graca, o mesmo par que
    as outras telas com grafico: a caixa 'Ao vivo' e o botao 'Segundo
    plano'. Tela de tabela nao ganha, porque tabela nao envelhece em
    segundos e ficar perguntando seria gastar o no a toa.
    """

    AO_VIVO = False
    INTERVALO = 5000

    def __init__(self, painel, no, avisar, funcao):
        super().__init__()
        self.painel, self.no, self.avisar = painel, no, avisar
        self.funcao = funcao
        self.pool = QThreadPool.globalInstance()
        self.leiaute = QVBoxLayout(self)
        self.leiaute.setContentsMargins(0, 6, 0, 0)
        linha = QHBoxLayout()
        self.botao = QPushButton(T("botao.atualizar"))
        self.botao.clicked.connect(self.recarrega)
        linha.addWidget(self.botao)
        self.relogio = None
        if self.AO_VIVO:
            self.ao_vivo = QCheckBox(T("opcao.ao_vivo", s=self.INTERVALO // 1000))
            self.ao_vivo.setChecked(True)
            linha.addWidget(self.ao_vivo)
            self.fundo = botao_segundo_plano()
            linha.addWidget(self.fundo)
            self.relogio = QTimer(self)
            self.relogio.setInterval(self.INTERVALO)
            self.relogio.timeout.connect(self.recarrega)
            self.ao_vivo.toggled.connect(self._ajusta_relogio)
            self.fundo.toggled.connect(self._ajusta_relogio)
        self.resumo = QLabel("")
        linha.addWidget(self.resumo)
        linha.addStretch()
        self.estado = QLabel("")
        self.estado.setStyleSheet("color: palette(mid);")
        linha.addWidget(self.estado)
        self.leiaute.addLayout(linha)
        self.monta()

    def monta(self):
        """Cria as tabelas da aba. Implementada por quem herda."""

    def _ajusta_relogio(self, *_):
        if self.relogio is None:
            return
        if self.ao_vivo.isChecked() and (self.isVisible() or self.fundo.isChecked()):
            self.relogio.start()
        else:
            self.relogio.stop()

    def showEvent(self, evento):
        super().showEvent(evento)
        self._ajusta_relogio()

    def hideEvent(self, evento):
        super().hideEvent(evento)
        if self.relogio is not None and not self.fundo.isChecked():
            self.relogio.stop()

    def recarrega(self):
        # Tique do relogio so vale se alguem estiver olhando, ou se o
        # 'Segundo plano' estiver ligado de proposito.
        if self.relogio is not None and self.sender() is self.relogio and not (
                a_vista(self) or self.fundo.isChecked()):
            self.relogio.stop()
            return
        self.botao.setEnabled(False)
        self.estado.setText(T("texto.consultando"))
        tarefa = Tarefa(self.funcao, self.no)
        tarefa.sinais.pronto.connect(self._chegou)
        tarefa.sinais.falhou.connect(self._falhou)
        self.pool.start(tarefa)

    @Slot(object)
    def _chegou(self, dados):
        self.botao.setEnabled(True)
        self.estado.setText(T("texto.em").format(dados.get('quando')))
        self.preenche(dados)

    @Slot(str)
    def _falhou(self, mensagem):
        self.botao.setEnabled(True)
        self.estado.setText(T("texto.falhou"))
        # No que nao responde nao vira fonte de pedido repetido: para o
        # relogio e deixa o operador reabrir quando quiser.
        if self.relogio is not None:
            self.relogio.stop()
        self.avisar(f"{self.no}: {mensagem}")

    def preenche(self, dados):
        """Poe os dados nas tabelas. Implementada por quem herda."""


class VisaoDHCP(AbaPapel):
    """Quem recebeu endereco nesta rede. E onde celular e tablet aparecem.

    Herda de AbaPapel como VisaoDNS e VisaoRoteamento: a classe da o ciclo
    "consulta o agente quando aparece", nao o lugar na tela.
    """

    def monta(self):
        self.concessoes = tabela(
            [T("coluna.ip"), T("coluna.mac"), T("coluna.nome"), T("coluna.estado"), T("coluna.inicio"), T("coluna.fim")], 0)
        self.concessoes.sortByColumn(0, Qt.AscendingOrder)
        self.leiaute.addWidget(self.concessoes)

    def preenche(self, dados):
        configuracao = dados.get("configuracao") or {}
        self.resumo.setText(
            T("texto.faixa_roteador_resolvedor_de").format(configuracao.get('faixa', '?'), configuracao.get('roteador', '?'), configuracao.get('resolvedor', '?'), dados.get('ativas', 0), dados.get('total', 0)))
        linhas = dados.get("concessoes", [])
        self.concessoes.setSortingEnabled(False)
        self.concessoes.setRowCount(len(linhas))
        for i, concessao in enumerate(linhas):
            self.concessoes.setItem(i, 0, celula(concessao.get("ip", "")))
            self.concessoes.setItem(i, 1, celula(concessao.get("mac", "")))
            self.concessoes.setItem(i, 2, celula(concessao.get("nome", "")))
            self.concessoes.setItem(i, 3, celula(concessao.get("estado", "")))
            self.concessoes.setItem(i, 4, celula(concessao.get("inicio", "")))
            self.concessoes.setItem(i, 5, celula(concessao.get("fim", "")))
            # Concessao vencida em cinza: o aparelho pode nem estar mais ali.
            if concessao.get("estado") != "active":
                for coluna in range(self.concessoes.columnCount()):
                    item = self.concessoes.item(i, coluna)
                    if item is not None:
                        item.setForeground(QBrush(QColor(140, 140, 140)))
        self.concessoes.setSortingEnabled(True)


def tabela_chave_valor(titulo):
    """Tabela de duas colunas para 'coisa: valor'. Sem cabecalho de coluna.

    Serve onde a informacao e uma ficha, nao uma lista: cada linha e um
    campo. Tabela em vez de rotulos soltos porque assim se copia o valor.
    """
    widget = QTableWidget(0, 2)
    widget.setHorizontalHeaderLabels([titulo, ""])
    widget.setEditTriggers(QTableWidget.NoEditTriggers)
    widget.verticalHeader().setVisible(False)
    widget.setAlternatingRowColors(True)
    cabeca = widget.horizontalHeader()
    cabeca.setSectionResizeMode(0, QHeaderView.ResizeToContents)
    cabeca.setSectionResizeMode(1, QHeaderView.Stretch)
    return widget


def preenche_ficha(widget, pares):
    """Poe [(campo, valor)] numa tabela de ficha, ignorando valor vazio."""
    pares = [(c, v) for c, v in pares if v not in (None, "", [])]
    widget.setRowCount(len(pares))
    for i, (campo, valor) in enumerate(pares):
        widget.setItem(i, 0, celula(campo))
        widget.setItem(i, 1, celula(valor))



class DialogoColarLista(QDialog):
    """Onde o operador COLA o texto de uma lista.

    Nao ha botao de baixar, e nao vai haver: o agente nunca faz pedido para
    fora, e o painel tambem nao busca sozinho. Quem baixou, abriu e leu o
    arquivo foi uma pessoa -- e e essa leitura que separa importar de
    confiar cegamente numa URL.
    """

    def __init__(self, especie, pai=None, nome=""):
        super().__init__(pai)
        self.setWindowTitle(T("janela.colar_lista"))
        self.resize(700, 520)
        leiaute = QVBoxLayout(self)
        rotulo = "negacao (blacklist)" if especie == "negados" else "excecao (whitelist)"
        leiaute.addWidget(cabecalho(
            T("texto.colar_lista_de").format(rotulo),
            T("texto.um_nome_por_linha")))
        formulario = QFormLayout()
        self.nome = QLineEdit(nome)
        self.nome.setPlaceholderText(T("dica.minusculas_digitos_e_hifen"))
        formulario.addRow(T("campo.nome_da_lista"), self.nome)
        leiaute.addLayout(formulario)
        self.texto = QPlainTextEdit()
        self.texto.setPlaceholderText(T("dica.cole_aqui_o_conteudo"))
        leiaute.addWidget(self.texto, 1)
        self.contagem = QLabel("")
        self.contagem.setStyleSheet("color: palette(mid);")
        self.texto.textChanged.connect(self._conta)
        leiaute.addWidget(self.contagem)
        botoes = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        botoes.accepted.connect(self.accept)
        botoes.rejected.connect(self.reject)
        leiaute.addWidget(botoes)

    def _conta(self):
        texto = self.texto.toPlainText()
        linhas = sum(1 for l in texto.splitlines() if l.strip())
        self.contagem.setText(
            T("texto.linha_s_kb_envio").format(linhas, len(texto) // 1024))

    def valores(self):
        return self.nome.text().strip(), self.texto.toPlainText()


class PainelListasDNS(QWidget):
    """Uma especie de lista (negados ou permitidos) e as regras de cada uma."""

    def __init__(self, especie, painel, no, avisar, recarrega_pai):
        super().__init__()
        self.especie, self.painel, self.no = especie, painel, no
        self.avisar, self.recarrega_pai = avisar, recarrega_pai
        self.pool = QThreadPool.globalInstance()

        leiaute = QVBoxLayout(self)
        leiaute.setContentsMargins(0, 6, 0, 0)
        botoes = QHBoxLayout()
        self.nova = QPushButton(T("botao.colar_nova_lista"))
        self.nova.clicked.connect(lambda: self.cola())
        botoes.addWidget(self.nova)
        self.substituir = QPushButton(T("botao.substituir_a_selecionada"))
        self.substituir.clicked.connect(self.substitui)
        botoes.addWidget(self.substituir)
        self.ligar = QPushButton(T("botao.ativar_desativar"))
        self.ligar.clicked.connect(self.alterna)
        botoes.addWidget(self.ligar)
        self.apagar = QPushButton(T("botao.apagar_lista"))
        self.apagar.clicked.connect(self.remove)
        botoes.addWidget(self.apagar)
        botoes.addStretch()
        self.progresso = QLabel("")
        self.progresso.setStyleSheet("color: palette(mid);")
        botoes.addWidget(self.progresso)
        leiaute.addLayout(botoes)

        self.listas = tabela([T("coluna.lista"), T("coluna.ativa"), T("coluna.regras"), T("coluna.origem"), T("coluna.quando")], 2)
        self.listas.sortByColumn(0, Qt.AscendingOrder)
        self.listas.itemSelectionChanged.connect(self.abre_selecionada)
        leiaute.addWidget(self.listas, 1)

        self.titulo_regras = QLabel(T("texto.regras_selecione_uma_lista"))
        leiaute.addWidget(self.titulo_regras)
        self.regras = tabela([T("coluna.regra"), T("coluna.nota")], 0)
        leiaute.addWidget(self.regras, 2)

        # Regra a regra, na lista que estiver selecionada acima. Sem caixa de
        # confirmacao: o clique no botao ja e o ato explicito, a regra
        # aparece na tabela em seguida e desfazer e um clique. Confirmacao
        # aqui viraria ruido, e ruido ensina a clicar em 'sim' sem ler --
        # que e o que estraga a confirmacao onde ela importa (apagar lista).
        regra = QHBoxLayout()
        regra.addWidget(QLabel(T("texto.regra")))
        self.nova_regra = QLineEdit()
        self.nova_regra.setPlaceholderText(
            T("dica.exemplo_com_exato_com"))
        self.nova_regra.returnPressed.connect(lambda: self.muda_regra("adicionar"))
        regra.addWidget(self.nova_regra)
        self.botao_add_regra = QPushButton(T("botao.adicionar"))
        self.botao_add_regra.clicked.connect(lambda: self.muda_regra("adicionar"))
        regra.addWidget(self.botao_add_regra)
        self.botao_tira_regra = QPushButton(T("botao.tirar_a_selecionada"))
        self.botao_tira_regra.clicked.connect(lambda: self.muda_regra("remover"))
        regra.addWidget(self.botao_tira_regra)
        leiaute.addLayout(regra)

    # ------------------------------------------------------------ leitura

    def mostra(self, entradas):
        """Poe a lista de listas na tabela de cima."""
        self.listas.setSortingEnabled(False)
        self.listas.setRowCount(len(entradas))
        for i, entrada in enumerate(entradas):
            principal = celula(entrada.get("nome", ""))
            principal.setData(PAPEL_LINHA, entrada)
            self.listas.setItem(i, 0, principal)
            self.listas.setItem(i, 1, celula("sim" if entrada.get("ativa") else "nao"))
            self.listas.setItem(i, 2, celula(entrada.get("regras") or 0, numero=True))
            self.listas.setItem(i, 3, celula(entrada.get("origem", "")))
            self.listas.setItem(i, 4, celula(entrada.get("em", "")))
            # Lista desativada em cinza: ela existe, mas nao esta valendo.
            if not entrada.get("ativa"):
                for coluna in range(self.listas.columnCount()):
                    item = self.listas.item(i, coluna)
                    if item is not None:
                        item.setForeground(QBrush(QColor(140, 140, 140)))
        self.listas.setSortingEnabled(True)

    def _selecionada(self):
        linha = self.listas.currentRow()
        if linha < 0:
            return None
        item = self.listas.item(linha, 0)
        return item.data(PAPEL_LINHA) if item else None

    def abre_selecionada(self):
        entrada = self._selecionada()
        if not entrada:
            return
        self.titulo_regras.setText(T("texto.regras_de_lendo").format(entrada['nome']))
        tarefa = Tarefa(self.painel.listas_dns, self.no, self.especie, entrada["nome"])
        tarefa.sinais.pronto.connect(self._mostra_regras)
        tarefa.sinais.falhou.connect(lambda m: self.avisar(f"{self.no}: {m}"))
        self.pool.start(tarefa)

    @Slot(object)
    def _mostra_regras(self, dados):
        escolhida = dados.get("escolhida") or {}
        if escolhida.get("especie") != self.especie:
            return
        regras = escolhida.get("regras") or []
        self.regras.setSortingEnabled(False)
        self.regras.setRowCount(len(regras))
        for i, regra in enumerate(regras):
            self.regras.setItem(i, 0, celula(regra.get("regra", "")))
            self.regras.setItem(i, 1, celula(regra.get("nota", "")))
        self.regras.setSortingEnabled(True)
        self.titulo_regras.setText(
            f"Regras de '{escolhida.get('lista')}': {len(regras)}"
            + (T("texto.mostrando_primeiras")
               if escolhida.get("cortada") else ""))

    # ------------------------------------------------------------- escrita

    def muda_regra(self, acao):
        entrada = self._selecionada()
        if not entrada:
            self.avisar(T("msg.selecione_primeiro_a_lista_que"))
            return
        if acao == "adicionar":
            nome = self.nova_regra.text().strip()
        else:
            linha = self.regras.currentRow()
            item = self.regras.item(linha, 0) if linha >= 0 else None
            nome = item.text() if item else self.nova_regra.text().strip()
        if not nome:
            self.avisar(T("msg.digite_a_regra_ou_selecione"))
            return
        self.progresso.setText(T("texto.em_2").format(acao, nome, entrada['nome']))
        tarefa = Tarefa(self.painel.regra_lista, self.no, self.especie,
                        entrada["nome"], nome, acao)
        tarefa.sinais.pronto.connect(self._regra_mudou)
        tarefa.sinais.falhou.connect(self._falhou)
        self.pool.start(tarefa)

    @Slot(object)
    def _regra_mudou(self, dados):
        self.nova_regra.clear()
        self.progresso.setText(
            T("texto.na_lista").format(dados.get('nome'), dados.get('acao', '').replace('_regra', ''), dados.get('regras')))
        # Recarrega as duas tabelas: a contagem da lista mudou junto.
        self.abre_selecionada()
        self.recarrega_pai()

    def cola(self, nome=""):
        dialogo = DialogoColarLista(self.especie, self, nome)
        if dialogo.exec() != QDialog.Accepted:
            return
        nome, texto = dialogo.valores()
        if not nome or not texto.strip():
            self.avisar(T("msg.informe_o_nome_da_lista"))
            return
        self.progresso.setText(T("texto.enviando"))
        for botao in (self.nova, self.substituir, self.ligar, self.apagar):
            botao.setEnabled(False)
        tarefa = Tarefa(self.painel.envia_lista, self.no, self.especie, nome, texto)
        tarefa.sinais.pronto.connect(self._enviou)
        tarefa.sinais.falhou.connect(self._falhou)
        self.pool.start(tarefa)

    def substitui(self):
        entrada = self._selecionada()
        if not entrada:
            self.avisar(T("msg.selecione_a_lista_a_substituir"))
            return
        self.cola(entrada["nome"])

    def alterna(self):
        entrada = self._selecionada()
        if not entrada:
            return
        acao = "desativar" if entrada.get("ativa") else "ativar"
        self._muda(entrada["nome"], acao,
                   T("msg.ativar_lista").format(
                       acao.capitalize(), entrada["nome"], self.no))

    def remove(self):
        entrada = self._selecionada()
        if not entrada:
            return
        self._muda(entrada["nome"], "remover",
                   T("msg.apagar_lista").format(entrada["nome"], self.no))

    def _muda(self, nome, acao, pergunta):
        if QMessageBox.question(self, "GHop", pergunta,
                                QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.No) != QMessageBox.Yes:
            return
        self.progresso.setText(f"{acao}...")
        tarefa = Tarefa(self.painel.muda_lista, self.no, self.especie, nome, acao)
        tarefa.sinais.pronto.connect(self._enviou)
        tarefa.sinais.falhou.connect(self._falhou)
        self.pool.start(tarefa)

    @Slot(object)
    def _enviou(self, dados):
        for botao in (self.nova, self.substituir, self.ligar, self.apagar):
            botao.setEnabled(True)
        if "aceitas" in dados:
            self.progresso.setText(
                f"{dados['lista']}: {dados['aceitas']} linha(s) gravada(s)"
                + (f", {dados['recusadas']} recusada(s)" if dados.get("recusadas") else ""))
        else:
            self.progresso.setText(f"{dados.get('lista')}: {dados.get('acao')}")
        self.recarrega_pai()

    @Slot(str)
    def _falhou(self, mensagem):
        for botao in (self.nova, self.substituir, self.ligar, self.apagar):
            botao.setEnabled(True)
        self.progresso.setText(T("texto.recusado"))
        self.avisar(f"{self.no}: {mensagem}")


class VisaoDNS(AbaPapel):
    """O resolvedor da LAN, o servidor de cima e o que foi negado.

    Duas sub-abas porque sao duas perguntas: 'Dados' e a ficha de como o
    resolvedor esta montado e para quem ele pergunta; 'Bloqueios' e a unica
    coisa que este servico registra evento a evento.

    'Bloqueios' so EXIBE: mexer na lista de regras e assunto de outra tela,
    e misturar as duas confundia -- a tabela mostra tentativas que
    aconteceram, e uma regra recem-criada nao produz linha ali ate alguem
    consultar aquele nome.

    O que esta tela NUNCA vai mostrar: quem consultou o que. O resolvedor
    nao registra consulta, por decisao de arquitetura -- so a NEGADA deixa
    rastro, porque negar e acao. Quem responde 'o que a rede pediu' e o
    coletor, que le o DNS na entrada da LAN, e essa e a leitura que se
    cruza com esta.
    """

    def monta(self):
        self.abas = QTabWidget()

        aba_dados = QWidget()
        dentro = QVBoxLayout(aba_dados)
        dentro.setContentsMargins(0, 6, 0, 0)
        self.ficha_local = tabela_chave_valor(T("texto.este_resolvedor"))
        dentro.addWidget(self.ficha_local, 1)
        self.ficha_acima = tabela_chave_valor(T("texto.servidor_de_cima"))
        dentro.addWidget(self.ficha_acima, 1)
        self.abas.addTab(aba_dados, T("aba.dados"))

        aba_bloqueios = QWidget()
        dentro = QVBoxLayout(aba_bloqueios)
        dentro.setContentsMargins(0, 6, 0, 0)
        linha = QHBoxLayout()
        linha.addWidget(QLabel(T("texto.filtrar")))
        self.filtro = QLineEdit()
        self.filtro.setPlaceholderText(T("dica.cliente_ou_nome"))
        self.filtro.textChanged.connect(self._aplica_filtro)
        linha.addWidget(self.filtro)
        dentro.addLayout(linha)
        dentro.addWidget(QLabel(
            T("texto.consultas_negadas_somadas_por")))
        # Colunas na ordem inversa da natural: a REGRA vem primeiro e leva a
        # sobra da largura, porque e o campo que cresce (padrao com curinga)
        # e o que explica POR QUE aquele nome foi negado. Data e cliente sao
        # de largura fixa e ficam no fim.
        #
        # Uma linha por (regra, nome, cliente), com o total: negacao repete
        # muito, e a lista crua era rolagem sem informacao.
        self.bloqueios = tabela(
            [T("coluna.regra"), T("coluna.nome"), T("coluna.cliente"), T("coluna.total"), T("coluna.primeira"), T("coluna.ultima")], 5)
        self.bloqueios.sortByColumn(5, Qt.DescendingOrder)
        dentro.addWidget(self.bloqueios)
        self.abas.addTab(aba_bloqueios, T("aba.bloqueios"))

        # Terceira: quem usa DNS nesta rede. Vem do COLETOR, nao do
        # resolvedor -- ver o docstring da classe.
        aba_clientes = QWidget()
        dentro = QVBoxLayout(aba_clientes)
        dentro.setContentsMargins(0, 6, 0, 0)
        self.aviso_clientes = QLabel("")
        self.aviso_clientes.setWordWrap(True)
        dentro.addWidget(self.aviso_clientes)
        self.clientes = tabela(
            [T("coluna.cliente"), T("coluna.servidor_consultado"), T("coluna.usa_este_lojmit"), T("coluna.consultas"),
             T("coluna.primeira"), T("coluna.ultima")], 3)
        dentro.addWidget(self.clientes)
        self.abas.addTab(aba_clientes, T("aba.clientes"))

        # Quarta: as listas em si. Duas especies, e varias listas em cada --
        # a 'propria', escrita a mao, e as coladas pelo operador.
        aba_listas = QWidget()
        dentro = QVBoxLayout(aba_listas)
        dentro.setContentsMargins(0, 6, 0, 0)
        self.especies = QTabWidget()
        self.painel_negados = PainelListasDNS(
            "negados", self.painel, self.no, self.avisar, self.recarrega_listas)
        self.painel_permitidos = PainelListasDNS(
            "permitidos", self.painel, self.no, self.avisar, self.recarrega_listas)
        self.especies.addTab(self.painel_negados, T("aba.blacklists"))
        self.especies.addTab(self.painel_permitidos, T("aba.whitelists"))
        dentro.addWidget(self.especies)
        self.abas.addTab(aba_listas, T("aba.listas"))

        self.leiaute.addWidget(self.abas)
        self.recarrega_listas()

    def recarrega_listas(self):
        """Le as listas do no. Separado do resto: o comando e outro."""
        tarefa = Tarefa(self.painel.listas_dns, self.no)
        tarefa.sinais.pronto.connect(self._mostra_listas)
        tarefa.sinais.falhou.connect(lambda m: self.avisar(f"{self.no}: {m}"))
        self.pool.start(tarefa)

    @Slot(object)
    def _mostra_listas(self, dados):
        listas = dados.get("listas") or {}
        self.painel_negados.mostra(listas.get("negados") or [])
        self.painel_permitidos.mostra(listas.get("permitidos") or [])
        self.especies.setTabText(0, T("aba.contagem").format(T("aba.blacklists"), len(listas.get("negados") or [])))
        self.especies.setTabText(1, T("aba.contagem").format(T("aba.whitelists"), len(listas.get("permitidos") or [])))

    def _aplica_filtro(self, texto=""):
        texto = (texto or self.filtro.text()).strip().lower()
        escondidas = 0
        for i in range(self.bloqueios.rowCount()):
            # 1 = nome, 2 = cliente, na ordem invertida das colunas.
            casa = not texto or any(
                texto in (self.bloqueios.item(i, c).text().lower()
                          if self.bloqueios.item(i, c) else "")
                for c in (1, 2))
            self.bloqueios.setRowHidden(i, not casa)
            escondidas += not casa
        total = self.bloqueios.rowCount()
        self.abas.setTabText(1, T("aba.contagem").format(T("aba.bloqueios"), f"{total - escondidas}"
                                + (T("aba.bloqueios_de").format(total) if escondidas else "")))

    def preenche(self, dados):
        configuracao = dados.get("configuracao") or {}
        acima = dados.get("acima") or {}
        self.resumo.setText(
            T("texto.negados_excecoes").format(dados.get('ativo', '?'), dados.get('negados', 0), dados.get('permitidos', 0)))

        preenche_ficha(self.ficha_local, [
            (T("ficha.servico"), f"{dados.get('ativo', '?')} / {dados.get('habilitado', '?')}"),
            (T("ficha.escuta_em"), ", ".join(dados.get("escuta") or [])),
            (T("ficha.nomes_negados"), str(dados.get("negados", 0))),
            (T("ficha.excecoes"), str(dados.get("permitidos", 0))),
            (T("ficha.resposta_a_nome_negado"), configuracao.get("blocked_query_response")),
            (T("ficha.cache"), ("ligado, " + configuracao.get("cache_size", "?") + " entradas")
             if configuracao.get("cache") == "true" else "desligado"),
            (T("ficha.registra_consultas"), T("ficha.nao_so_as_negadas")),
        ])
        preenche_ficha(self.ficha_acima, [
            (T("ficha.servidor_em_uso"), acima.get("servidor")),
            (T("ficha.latencia_inicial"), (acima.get("latencia") + " ms")
             if acima.get("latencia") else None),
            (T("ficha.candidatos_vivos"), acima.get("servidores_vivos")),
            (T("ficha.escolha"), "fixada em " + configuracao["server_names"]
             if configuracao.get("server_names") not in (None, "[]")
             else "automatica, pela latencia"),
            (T("ficha.protocolos_aceitos"), ", ".join(
                p for p, chave in (("DNSCrypt", "dnscrypt_servers"), ("DoH", "doh_servers"))
                if configuracao.get(chave) == "true")),
            (T("ficha.exige_nao_guardar_log"), configuracao.get("require_nolog")),
            (T("ficha.exige_nao_filtrar"), configuracao.get("require_nofilter")),
            (T("ficha.exige_dnssec"), configuracao.get("require_dnssec")),
            (T("ficha.lista_de_servidores_de"), acima.get("fontes_de")),
        ])

        # Os enderecos em que este resolvedor atende: e por eles que se sabe
        # se o cliente perguntou aqui ou foi falar com um DNS de fora.
        meus = {e.rsplit(":", 1)[0] for e in (dados.get("escuta") or [])}
        linhas = dados.get("clientes") or []
        self.clientes.setSortingEnabled(False)
        self.clientes.setRowCount(len(linhas))
        fora = 0
        for i, cliente in enumerate(linhas):
            daqui = cliente.get("servidor") in meus
            fora += not daqui
            self.clientes.setItem(i, 0, celula(cliente.get("origem", "")))
            self.clientes.setItem(i, 1, celula(cliente.get("servidor", "")))
            self.clientes.setItem(i, 2, celula("sim" if daqui else "NAO"))
            self.clientes.setItem(i, 3, celula(cliente.get("total") or 0, numero=True))
            self.clientes.setItem(i, 4, celula(cliente.get("primeiro", "")))
            self.clientes.setItem(i, 5, celula(cliente.get("ultimo", "")))
            # Cliente que fala com DNS de fora escapa da lista de negacao e
            # do registro: e o que se quer enxergar de longe.
            if not daqui:
                for coluna in range(self.clientes.columnCount()):
                    item = self.clientes.item(i, coluna)
                    if item is not None:
                        item.setForeground(QBrush(QColor(190, 60, 60)))
        self.clientes.setSortingEnabled(True)
        self.abas.setTabText(2, T("aba.contagem").format(T("aba.clientes"), len(linhas)))
        self.aviso_clientes.setText(
            T("texto.contado_pelo_coletor").format(dados.get("dia", "?"))
            + (T("texto.falam_com_dns_de_fora").format(fora) if fora else ""))
        if not linhas:
            self.aviso_clientes.setText(
                T("texto.sem_contagem_por_cliente"))

        linhas = dados.get("bloqueios", [])
        self.bloqueios.setSortingEnabled(False)
        self.bloqueios.setRowCount(len(linhas))
        for i, bloqueio in enumerate(linhas):
            self.bloqueios.setItem(i, 0, celula(bloqueio.get("regra", "")))
            self.bloqueios.setItem(i, 1, celula(bloqueio.get("nome", "")))
            self.bloqueios.setItem(i, 2, celula(bloqueio.get("cliente", "")))
            self.bloqueios.setItem(i, 3, celula(bloqueio.get("total") or 0, numero=True))
            self.bloqueios.setItem(i, 4, celula(bloqueio.get("primeiro", "")))
            self.bloqueios.setItem(i, 5, celula(bloqueio.get("ultimo", "")))
        self.bloqueios.setSortingEnabled(True)
        self._aplica_filtro()


class AbaWifi(AbaPapel):
    """O radio e quem esta associado a ele."""

    def monta(self):
        self.clientes = tabela(
            [T("coluna.mac"), T("coluna.sinal_dbm"), T("coluna.conectado"), T("coluna.inativo"), T("coluna.rx_kb"), T("coluna.tx_kb")], 0)
        self.clientes.sortByColumn(0, Qt.AscendingOrder)
        self.leiaute.addWidget(QLabel(T("texto.associados_ao_radio")))
        self.leiaute.addWidget(self.clientes)

    def preenche(self, dados):
        rede = dados.get("rede") or {}
        self.resumo.setText(
            T("texto.ssid_canal_radio_em").format(dados.get('ativo', '?'), rede.get('ssid', '?'), rede.get('channel', '?'), dados.get('radio', '?'), dados.get('ponte', '-')))
        linhas = dados.get("clientes", [])
        self.clientes.setSortingEnabled(False)
        self.clientes.setRowCount(len(linhas))
        for i, cliente in enumerate(linhas):
            self.clientes.setItem(i, 0, celula(cliente.get("mac", "")))
            self.clientes.setItem(i, 1, celula(cliente.get("sinal") or ""))
            self.clientes.setItem(i, 2, celula(cliente.get("conectado", "")))
            self.clientes.setItem(i, 3, celula(cliente.get("inativo", "")))
            self.clientes.setItem(i, 4, celula((cliente.get("rx_bytes") or 0) // 1000, numero=True))
            self.clientes.setItem(i, 5, celula((cliente.get("tx_bytes") or 0) // 1000, numero=True))
        self.clientes.setSortingEnabled(True)


class DiagramaFirewall(QWidget):
    """O caminho do pacote pelas cadeias, desenhado.

    Uma coluna por cadeia, na ordem em que o kernel as consulta, e uma caixa
    por regra, na ordem em que ela e avaliada -- que e a informacao que a
    tabela nao da bem: em firewall a ORDEM decide, e a primeira regra que
    casa encerra a conversa.

    A cor diz o veredito (aceitar, barrar, mascarar) e a barra diz quanto
    aquela regra ja pegou, em escala logaritmica: com escala linear uma
    regra de trafego normal achataria todas as outras, e o que se procura
    aqui e justamente a regra que quase nunca pega.

    Contador zerado NAO apaga a regra: ela continua valendo, e ler firewall
    e ler o que esta la. O destaque -- contorno grosso e negrito -- vai para
    a regra de DROP que pegou pacote, que e a unica que diz que algo esta
    acontecendo agora: alguem tentou e foi impedido.
    """

    CORES = {
        "accept": QColor(60, 140, 70),
        "drop": QColor(190, 60, 60),
        "reject": QColor(190, 60, 60),
        "masquerade": QColor(60, 110, 180),
        "snat": QColor(60, 110, 180),
        "dnat": QColor(60, 110, 180),
        "jump": QColor(150, 110, 30),
        "goto": QColor(150, 110, 30),
    }
    COR_OUTRO = QColor(120, 120, 120)
    # A ordem em que o kernel percorre os ganchos. Cadeia de gancho
    # desconhecido vai para o fim, em vez de sumir do desenho.
    ORDEM = ("prerouting", "input", "forward", "output", "postrouting")
    LARGURA_MINIMA = 210
    FOLGA = 10

    def __init__(self):
        super().__init__()
        self.cadeias = []
        self.regras = []
        self.setMinimumHeight(200)

    def atualiza(self, cadeias, regras):
        self.cadeias = sorted(
            cadeias,
            key=lambda c: (self.ORDEM.index(c.get("gancho"))
                           if c.get("gancho") in self.ORDEM else len(self.ORDEM),
                           c.get("tabela", "")))
        self.regras = regras
        colunas = max(1, len(self.cadeias))
        maior = max((sum(1 for r in regras
                         if r.get("cadeia") == c.get("nome")
                         and r.get("tabela") == c.get("tabela"))
                     for c in self.cadeias), default=0)
        altura = self.fontMetrics().height()
        self.setMinimumWidth(colunas * self.LARGURA_MINIMA)
        # Espaco para as regras, a caixa da politica e o rodape.
        self.setMinimumHeight(int(60 + maior * (altura * 2 + 14)
                                  + (altura + 16) + altura + 24))
        self.update()

    def _regras_da(self, cadeia):
        return [r for r in self.regras
                if r.get("cadeia") == cadeia.get("nome")
                and r.get("tabela") == cadeia.get("tabela")]

    def _politica(self, pintor, metrica, x, y, largura, linha, fraco, politica):
        """A politica da cadeia, no pe da cascata, com borda tracejada.

        Tracejada de proposito: nao e uma regra, e o que sobra quando
        nenhuma casou. Desenhada sempre, inclusive em cadeia vazia, onde ela
        e a unica coisa que acontece.
        """
        cor = self.CORES.get((politica or "").lower(), self.COR_OUTRO)
        altura = linha + 8

        # Seta curta ligando a ultima regra a politica: o pacote "cai" ate aqui.
        meio = x + largura // 2
        pintor.setPen(QPen(fraco, 1, Qt.DotLine))
        pintor.drawLine(meio, y - 5, meio, y + 1)

        pintor.setPen(QPen(cor.darker(140), 1, Qt.DashLine))
        pintor.setBrush(QColor(cor.red(), cor.green(), cor.blue(), 35))
        pintor.drawRoundedRect(x, y + 2, largura, altura, 4, 4)
        pintor.setPen(fraco)
        pintor.drawText(x + 6, y + 2, largura - 12, altura, Qt.AlignLeft | Qt.AlignVCenter,
                        T("texto.nenhuma_casou"))
        pintor.setPen(cor.darker(150))
        fonte = pintor.font()
        fonte.setBold(True)
        pintor.setFont(fonte)
        pintor.drawText(x + 6, y + 2, largura - 12, altura,
                        Qt.AlignRight | Qt.AlignVCenter,
                        (politica or T("texto.sem_politica")).upper())
        fonte.setBold(False)
        pintor.setFont(fonte)

    def paintEvent(self, _evento):
        pintor = QPainter(self)
        pintor.setRenderHint(QPainter.Antialiasing)
        paleta = self.palette()
        texto_cor = paleta.color(paleta.ColorRole.WindowText)
        fraco = paleta.color(paleta.ColorRole.Mid)
        metrica = pintor.fontMetrics()
        linha = metrica.height()

        if not self.cadeias:
            pintor.setPen(fraco)
            pintor.drawText(self.rect(), Qt.AlignCenter, T("texto.sem_cadeias"))
            return

        largura_coluna = max(self.LARGURA_MINIMA,
                             (self.width() - self.FOLGA) // len(self.cadeias))
        altura_caixa = linha * 2 + 8
        # Escala logaritmica: o maior contador define o comprimento cheio.
        maior = max((r.get("pacotes") or 0 for r in self.regras), default=0)
        import math
        teto = math.log10(maior + 1) or 1

        for indice, cadeia in enumerate(self.cadeias):
            x = self.FOLGA + indice * largura_coluna
            largura = largura_coluna - self.FOLGA
            y = self.FOLGA

            # Cabecalho da cadeia: onde ela e consultada e o que acontece
            # com o pacote que chega ao fim dela sem casar com nada.
            pintor.setPen(QPen(fraco, 1))
            pintor.setBrush(paleta.color(paleta.ColorRole.AlternateBase))
            pintor.drawRoundedRect(x, y, largura, linha * 2 + 6, 4, 4)
            pintor.setPen(texto_cor)
            fonte = pintor.font()
            fonte.setBold(True)
            pintor.setFont(fonte)
            pintor.drawText(x + 6, y + 3, largura - 12, linha, Qt.AlignLeft,
                            metrica.elidedText(
                                f"{cadeia.get('tabela')} / {cadeia.get('nome')}",
                                Qt.ElideRight, largura - 12))
            fonte.setBold(False)
            pintor.setFont(fonte)
            pintor.setPen(fraco)
            pintor.drawText(x + 6, y + 3 + linha, largura - 12, linha, Qt.AlignLeft,
                            metrica.elidedText(
                                T("texto.gancho_politica").format(
                                    cadeia.get("gancho") or "-",
                                    cadeia.get("politica") or "-"),
                                Qt.ElideRight, largura - 12))
            y += linha * 2 + 6 + 8

            # Seta para a proxima cadeia: o pacote segue por elas nesta ordem.
            if indice + 1 < len(self.cadeias):
                meio = self.FOLGA + indice * largura_coluna + largura + 1
                pintor.setPen(QPen(fraco, 1))
                pintor.drawLine(meio, self.FOLGA + linha, meio + self.FOLGA - 2,
                                self.FOLGA + linha)
                pintor.drawLine(meio + self.FOLGA - 5, self.FOLGA + linha - 3,
                                meio + self.FOLGA - 2, self.FOLGA + linha)
                pintor.drawLine(meio + self.FOLGA - 5, self.FOLGA + linha + 3,
                                meio + self.FOLGA - 2, self.FOLGA + linha)

            regras = self._regras_da(cadeia)
            if not regras:
                pintor.setPen(fraco)
                pintor.drawText(x + 6, y, largura - 12, linha, Qt.AlignLeft,
                                T("texto.nenhuma_regra"))
                y += linha + 6

            for ordem, regra in enumerate(regras, start=1):
                cor = self.CORES.get(regra.get("veredito"), self.COR_OUTRO)
                pacotes = regra.get("pacotes") or 0
                # A cor e do VEREDITO, sempre cheia: verde aceita, vermelho
                # barra, azul mascara. Contador zerado nao apaga a regra da
                # vista -- ela continua valendo, e ler o firewall e ler o
                # que esta la, nao so o que se moveu hoje.
                #
                # O destaque e para BARRA E PEGOU: regra de drop com pacote
                # e a unica que conta algo acontecendo agora -- alguem
                # tentou e foi impedido. E o que se quer ver de longe.
                barrou = pacotes and regra.get("veredito") in ("drop", "reject")

                pintor.setPen(QPen(cor.darker(140), 3 if barrou else 1))
                pintor.setBrush(QColor(cor.red(), cor.green(), cor.blue(),
                                       110 if barrou else 55))
                pintor.drawRoundedRect(x, y, largura, altura_caixa, 4, 4)

                fonte = pintor.font()
                fonte.setBold(bool(barrou))
                pintor.setFont(fonte)
                pintor.setPen(texto_cor)
                pintor.drawText(
                    x + 6, y + 2, largura - 12, linha, Qt.AlignLeft,
                    metrica.elidedText(f"{ordem}. {regra.get("texto") or T("texto.sem_condicao")}",
                                       Qt.ElideRight, largura - 12))
                pintor.setPen(cor.darker(150))
                pintor.drawText(x + 6, y + 2 + linha, largura - 12, linha, Qt.AlignLeft,
                                (regra.get("veredito") or T("texto.sem_veredito")).upper())
                pintor.drawText(x + 6, y + 2 + linha, largura - 12, linha, Qt.AlignRight,
                                f"{pacotes} pac")
                fonte.setBold(False)
                pintor.setFont(fonte)

                # Barra do contador, rente a base da caixa.
                if pacotes:
                    cheio = int((largura - 12) * (math.log10(pacotes + 1) / teto))
                    pintor.setPen(Qt.NoPen)
                    pintor.setBrush(cor)
                    pintor.drawRect(x + 6, y + altura_caixa - 4, cheio, 2)
                y += altura_caixa + 6

            # O fim da cascata: o que acontece com o pacote que desceu a
            # cadeia inteira sem casar com nada. Sem isto o desenho conta
            # metade da historia -- e a metade que decide o caso comum.
            self._politica(pintor, metrica, x, y, largura, linha, fraco,
                           cadeia.get("politica"))

        pintor.setPen(fraco)
        pintor.setBrush(Qt.NoBrush)
        rodape = T("texto.rodape_cascata")
        pintor.drawText(self.FOLGA, self.height() - linha - 2,
                        self.width() - 2 * self.FOLGA, linha, Qt.AlignLeft,
                        metrica.elidedText(rodape, Qt.ElideRight,
                                           self.width() - 2 * self.FOLGA))



class DialogoFirewall(QDialog):
    """Formulario para criar tabela, cadeia ou regra no firewall de um no.

    Campos, e nao texto de regra: cada caixa vira um argumento conferido no
    agente. Escrever a regra a mao seria mais flexivel e abriria a porta que
    o conjunto fechado existe para manter fechada.
    """

    def __init__(self, especie, pai=None, tabelas=(), cadeias=()):
        super().__init__(pai)
        self.especie = especie
        self.setWindowTitle(T("janela.ghop_nova").format(especie))
        leiaute = QVBoxLayout(self)
        titulo = T("texto.nova_%s" % especie)
        ajuda = T("ajuda.nova_%s" % especie)
        leiaute.addWidget(cabecalho(titulo, ajuda))
        formulario = QFormLayout()
        self.campos = {}

        def caixa(nome, rotulo, valores=None, editavel=False, dica=""):
            if valores is None:
                widget = QLineEdit()
                widget.setPlaceholderText(dica)
            else:
                widget = QComboBox()
                widget.setEditable(editavel)
                widget.addItems(list(valores))
            self.campos[nome] = widget
            formulario.addRow(rotulo, widget)
            return widget

        caixa("familia", T("campo.familia"), ("inet", "ip", "ip6"))
        if especie == "tabela":
            caixa("nome", T("campo.nome"), dica=T("dica.ex_painel"))
        elif especie == "cadeia":
            caixa("tabela", T("campo.tabela"), tabelas or ("filter",), editavel=True)
            caixa("nome", T("campo.nome"), dica="ex.: bloqueios")
            caixa("tipo", T("campo.tipo"), ("filter", "nat", "route"))
            caixa("gancho", T("campo.gancho"), ("", "input", "forward", "output",
                                        "prerouting", "postrouting"))
            caixa("prioridade", T("campo.prioridade"), dica="0")
            caixa("politica", T("campo.politica"), ("accept", "drop"))
        else:
            caixa("tabela", T("campo.tabela"), tabelas or ("filter",), editavel=True)
            caixa("cadeia", T("campo.cadeia"), cadeias or ("input",), editavel=True)
            caixa("iifname", T("campo.entra_por"), dica="interface, ex.: br0")
            caixa("oifname", T("campo.sai_por"), dica="interface, ex.: enp1s0")
            caixa("saddr", T("campo.origem"), dica="ex.: 192.168.101.50 ou 10.0.0.0/8")
            caixa("daddr", T("campo.destino"), dica="ex.: 1.1.1.1")
            caixa("protocolo", T("campo.protocolo"), ("", "tcp", "udp", "icmp"))
            caixa("sport", T("campo.porta_de_origem"), dica="ex.: 1024-65535")
            caixa("dport", T("campo.porta_de_destino"), dica="ex.: 443 ou 80-90")
            caixa("estado", T("campo.estado"), ("", "new", "established", "related",
                                        "invalid", "established,related"))
            caixa("veredito", T("campo.o_que_fazer"), ("accept", "drop", "reject",
                                               "masquerade", "counter"))
            caixa("nota", T("campo.nota"), dica=T("dica.por_que_regra"))
        leiaute.addLayout(formulario)

        botoes = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        botoes.accepted.connect(self.accept)
        botoes.rejected.connect(self.reject)
        leiaute.addWidget(botoes)

    def valores(self):
        saida = {}
        for nome, widget in self.campos.items():
            valor = (widget.currentText() if isinstance(widget, QComboBox)
                     else widget.text()).strip()
            if valor:
                saida[nome] = valor
        return saida


class VisaoRoteamento(AbaPapel):
    """O firewall em vigor: tabelas, cadeias, regras e quanto cada uma pegou.

    Visao inteira, e nao aba dentro de 'Dados', porque e o assunto que se
    olha linha a linha. Le o ruleset do KERNEL, nao o arquivo que o gerou: o
    que vale e o que esta valendo. Regra com contador zerado e regra que
    nunca pegou nada -- pode estar certa e sobrando, ou errada e nao
    pegando o que devia.
    """

    # A serie de pacotes por cadeia. Vermelho do tema, e nao a cor de antes,
    # porque aqui a cor nao DISTINGUE nada: e uma linha so por grafico, sem
    # segunda serie com que contrastar -- e identidade visual, nao
    # significado. Nao confundir com as CORES da aba 'Rules', que sao o
    # veredito de cada regra (accept, drop, masquerade): aquelas dizem o que
    # a regra faz, e trocar qualquer uma apaga informacao.
    COR_PACOTES = QColor(178, 34, 34)


    # Tem grafico (aba Graficos), entao ganha "Ao vivo" e "Segundo plano".
    AO_VIVO = True

    tabelas_conhecidas = ()
    cadeias_conhecidas = ()

    def cria(self, especie):
        dialogo = DialogoFirewall(especie, self, self.tabelas_conhecidas,
                                  self.cadeias_conhecidas)
        if dialogo.exec() != QDialog.Accepted:
            return
        campos = dialogo.valores()
        resumo = ", ".join(f"{c}={v}" for c, v in campos.items())
        if QMessageBox.question(
                self, "GHop",
                T("msg.criar_em_o_ruleset_inteiro").format(especie, self.no, resumo),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self._manda(especie, campos)

    def apaga(self):
        linha = self.meus.currentRow()
        item = self.meus.item(linha, 0) if linha >= 0 else None
        alvo = item.data(PAPEL_LINHA) if item else None
        if not alvo:
            self.avisar(T("msg.selecione_na_tabela_de_baixo"))
            return
        if QMessageBox.question(
                self, "GHop",
                T("msg.apagar_de_o_ruleset_inteiro").format(alvo['especie'][:-1], alvo['id'], self.no),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self._manda("remover", {"especie": alvo["especie"], "id": alvo["id"]})

    def _manda(self, acao, campos):
        self.aviso_firewall.setText(f"{acao}...")
        tarefa = Tarefa(self.painel.firewall, self.no, acao, **campos)
        tarefa.sinais.pronto.connect(self._firewall_mudou)
        tarefa.sinais.falhou.connect(self._falhou)
        self.pool.start(tarefa)

    @Slot(object)
    def _firewall_mudou(self, dados):
        self.aviso_firewall.setText(
            T("texto.tabela_s_cadeia_s").format(dados.get('acao'), dados.get('tabelas'), dados.get('cadeias'), dados.get('regras')))
        # Uma mudanca no firewall muda TODAS as telas desta visao: as tabelas
        # de Dados, o desenho e o proximo ponto dos graficos. Por isso se
        # recarrega a visao inteira, e nao so esta aba.
        self.recarrega()

    def monta(self):
        # Duas maneiras de olhar a mesma coisa: 'Dados' resume em tabela, e
        # 'Rules' mostra o ruleset como o nft o imprime. O resumo e melhor
        # para achar; o texto e melhor quando o resumo nao explica -- ordem
        # das regras, sintaxe exata, o que veio de fragmento.
        self.abas = QTabWidget()

        aba_dados = QWidget()
        dentro = QVBoxLayout(aba_dados)
        dentro.setContentsMargins(0, 6, 0, 0)
        self.cadeias = tabela(
            [T("coluna.familia"), T("coluna.tabela"), T("coluna.cadeia"), T("coluna.gancho"), T("coluna.prioridade"), T("coluna.politica")], 0)
        self.cadeias.sortByColumn(1, Qt.AscendingOrder)
        dentro.addWidget(QLabel(T("texto.cadeias")))
        dentro.addWidget(self.cadeias, 1)
        self.regras = tabela(
            [T("coluna.tabela"), T("coluna.cadeia"), T("coluna.regra"), T("coluna.pacotes"), T("coluna.bytes")], 3)
        dentro.addWidget(QLabel(T("texto.regras_com_o_que")))
        dentro.addWidget(self.regras, 3)
        self.abas.addTab(aba_dados, T("aba.dados"))

        # 'Graficos': quanto passa por cada cadeia, nos mesmos 10 minutos que
        # o agente ja amostra. A tabela diz o total desde que a regra existe;
        # aqui se ve o AGORA, que e o que responde "esta acontecendo algo?".
        rolagem_graficos = QScrollArea()
        rolagem_graficos.setWidgetResizable(True)
        caixa = QWidget()
        self.graficos_leiaute = QVBoxLayout(caixa)
        self.graficos_leiaute.setContentsMargins(0, 6, 0, 0)
        self.graficos_cadeia = {}
        rolagem_graficos.setWidget(caixa)
        self.abas.addTab(rolagem_graficos, T("aba.graficos"))

        # 'Rules' e o desenho: o caminho do pacote e a ordem das regras, que
        # e o que a tabela nao mostra bem. Vai dentro de uma area rolavel
        # porque cresce com o numero de regras.
        aba_desenho = QWidget()
        dentro = QVBoxLayout(aba_desenho)
        dentro.setContentsMargins(0, 6, 0, 0)
        acoes = QHBoxLayout()
        for especie in ("tabela", "cadeia", "regra"):
            rotulo = T("botao.nova_%s" % especie)
            botao = QPushButton(rotulo)
            botao.clicked.connect(lambda _=False, e=especie: self.cria(e))
            acoes.addWidget(botao)
        self.botao_tirar = QPushButton(T("botao.apagar_a_selecionada"))
        self.botao_tirar.clicked.connect(self.apaga)
        acoes.addWidget(self.botao_tirar)
        acoes.addStretch()
        self.aviso_firewall = QLabel("")
        self.aviso_firewall.setStyleSheet("color: palette(mid);")
        acoes.addWidget(self.aviso_firewall)
        dentro.addLayout(acoes)

        rolagem = QScrollArea()
        rolagem.setWidgetResizable(True)
        self.diagrama = DiagramaFirewall()
        rolagem.setWidget(self.diagrama)
        dentro.addWidget(rolagem, 3)

        # O que o PAINEL escreveu, separado do resto: as regras base e os
        # fragmentos dos outros papeis nao se apagam daqui, e misturar as
        # duas coisas numa lista so faria parecer que se apagam.
        dentro.addWidget(QLabel(T("texto.escrito_pelo_painel_so")))
        self.meus = tabela([T("coluna.o_que"), T("coluna.onde"), T("coluna.detalhe"), T("coluna.id")], 0)
        dentro.addWidget(self.meus, 1)
        self.abas.addTab(aba_desenho, T("aba.rules"))

        aba_texto = QWidget()
        dentro = QVBoxLayout(aba_texto)
        dentro.setContentsMargins(0, 6, 0, 0)
        self.texto = QPlainTextEdit()
        self.texto.setReadOnly(True)
        self.texto.setLineWrapMode(QPlainTextEdit.NoWrap)
        fonte = QFont("monospace")
        fonte.setStyleHint(QFont.Monospace)
        self.texto.setFont(fonte)
        dentro.addWidget(self.texto)
        self.abas.addTab(aba_texto, T("aba.raw"))

        self.leiaute.addWidget(self.abas)

    def preenche(self, dados):
        self.resumo.setText(
            T("texto.wan_lan_encaminhamento_fragmentos").format(dados.get('ativo', '?'), dados.get('wan') or '?', dados.get('lan') or '?', 'ligado' if dados.get('encaminha') else 'DESLIGADO', ', '.join(dados.get('fragmentos') or []) or 'nenhum'))

        linhas = dados.get("cadeias", [])
        self.cadeias.setSortingEnabled(False)
        self.cadeias.setRowCount(len(linhas))
        for i, cadeia in enumerate(linhas):
            self.cadeias.setItem(i, 0, celula(cadeia.get("familia", "")))
            self.cadeias.setItem(i, 1, celula(cadeia.get("tabela", "")))
            self.cadeias.setItem(i, 2, celula(cadeia.get("nome", "")))
            self.cadeias.setItem(i, 3, celula(cadeia.get("gancho", "")))
            self.cadeias.setItem(i, 4, celula(cadeia.get("prioridade") or 0, numero=True))
            self.cadeias.setItem(i, 5, celula(cadeia.get("politica", "")))
        self.cadeias.setSortingEnabled(True)

        linhas = dados.get("regras", [])
        self.regras.setSortingEnabled(False)
        self.regras.setRowCount(len(linhas))
        for i, regra in enumerate(linhas):
            self.regras.setItem(i, 0, celula(regra.get("tabela", "")))
            self.regras.setItem(i, 1, celula(regra.get("cadeia", "")))
            self.regras.setItem(i, 2, celula(regra.get("texto", "")))
            self.regras.setItem(i, 3, celula(regra.get("pacotes") or 0, numero=True))
            self.regras.setItem(i, 4, celula(regra.get("bytes") or 0, numero=True))
            # Regra que nunca pegou nada fica em cinza: e o que se procura
            # quando algo "devia estar bloqueado" e nao esta.
            if not regra.get("pacotes"):
                for coluna in range(self.regras.columnCount()):
                    item = self.regras.item(i, coluna)
                    if item is not None:
                        item.setForeground(QBrush(QColor(140, 140, 140)))
        self.regras.setSortingEnabled(True)

        # Trocar o texto perde a rolagem; guardar e devolver mantem o lugar
        # em que se estava lendo quando a tela se atualiza.
        onde = self.texto.verticalScrollBar().value()
        self.texto.setPlainText(dados.get("texto") or T("texto.sem_ruleset"))
        self.texto.verticalScrollBar().setValue(onde)
        self.abas.setTabText(0, T("aba.dados_regras").format(len(linhas)))
        self.diagrama.atualiza(dados.get("cadeias") or [], linhas)

        series = dados.get("series") or {}
        agora = float(dados.get("agora") or time.time())
        janela = int(dados.get("janela") or 600)
        for nome in sorted(series):
            if nome not in self.graficos_cadeia:
                if self.graficos_cadeia:
                    risco = QFrame()
                    risco.setFrameShape(QFrame.HLine)
                    risco.setFrameShadow(QFrame.Sunken)
                    self.graficos_leiaute.addWidget(risco)
                grafico = GraficoTrafego(
                    nome, series=[("pacotes", self.COR_PACOTES, 1)],
                    formata=lambda v: f"{v:,.0f} pac/s".replace(",", "."))
                self.graficos_cadeia[nome] = grafico
                self.graficos_leiaute.addWidget(grafico)
            self.graficos_cadeia[nome].atualiza(series[nome], agora, janela)
        self.abas.setTabText(1, T("aba.contagem").format(T("aba.graficos"), len(series)))
        if not series:
            self.abas.setTabText(1, T("aba.graficos_amostrando"))

        # O que o painel escreveu, para poder apagar depois.
        painel = dados.get("painel") or {}
        self.tabelas_conhecidas = sorted(
            {c.get("tabela") for c in (dados.get("cadeias") or []) if c.get("tabela")})
        self.cadeias_conhecidas = sorted(
            {c.get("nome") for c in (dados.get("cadeias") or []) if c.get("nome")})
        entradas = []
        for tabela_ in painel.get("tabelas") or []:
            entradas.append(("tabela", f'{tabela_["familia"]} {tabela_["nome"]}', "",
                             f'{tabela_["familia"]}/{tabela_["nome"]}'))
        for cadeia in painel.get("cadeias") or []:
            detalhe = (T("texto.cadeia_detalhe").format(
                           cadeia.get("tipo"), cadeia.get("gancho"),
                           cadeia.get("prioridade"), cadeia.get("politica"))
                       if cadeia.get("gancho") else T("texto.sem_gancho"))
            entradas.append(("cadeia", f'{cadeia["tabela"]}/{cadeia["nome"]}', detalhe,
                             f'{cadeia["familia"]}/{cadeia["tabela"]}/{cadeia["nome"]}'))
        for regra in painel.get("regras") or []:
            resumo = " ".join(
                f"{campo} {regra[campo]}" for campo in
                ("iifname", "oifname", "saddr", "daddr", "protocolo", "sport",
                 "dport", "estado") if regra.get(campo))
            entradas.append(("regra", f'{regra["tabela"]}/{regra["cadeia"]}',
                             f'{resumo} -> {regra.get("veredito")}'
                             + (f'  ({regra["nota"]})' if regra.get("nota") else ""),
                             regra["id"]))
        self.meus.setSortingEnabled(False)
        self.meus.setRowCount(len(entradas))
        for i, (especie, onde, detalhe, chave) in enumerate(entradas):
            item = celula(especie)
            item.setData(PAPEL_LINHA, {"especie": especie + "s", "id": chave})
            self.meus.setItem(i, 0, item)
            self.meus.setItem(i, 1, celula(onde))
            self.meus.setItem(i, 2, celula(detalhe))
            self.meus.setItem(i, 3, celula(chave))
        self.meus.setSortingEnabled(True)
        self.aviso_firewall.setText(
            T("texto.itens_escritos").format(len(entradas)) if entradas
            else T("texto.nada_escrito"))


class DialogoRegraFiltro(QDialog):
    """Uma regra do filtro: tipo, valor, acao e a nota de por que ela existe.

    Campos separados, nunca texto de regra: e o mesmo principio do comando
    'firewall'. O que o operador digita e um NOME; o resto sai de lista
    fechada, aqui e de novo no agente.
    """

    def __init__(self, pai=None):
        super().__init__(pai)
        self.setWindowTitle(T("janela.regra_filtro"))
        self.resize(520, 0)
        leiaute = QVBoxLayout(self)
        leiaute.addWidget(cabecalho(
            T("texto.nova_regra_do_filtro"),
            T("texto.compara_o_nome_que")))

        formulario = QFormLayout()
        self.acao = QComboBox()
        self.acao.addItem(T("opcao.bloquear_nao_sai"), "bloquear")
        self.acao.addItem(T("opcao.permitir_excecao"), "permitir")
        formulario.addRow("Acao:", self.acao)
        self.tipo = QComboBox()
        for chave in ("sufixo", "exato", "prefixo", "contem"):
            self.tipo.addItem(T("opcao.casa_%s" % chave), chave)
        formulario.addRow(T("campo.casa_por"), self.tipo)
        self.valor = QLineEdit()
        self.valor.setPlaceholderText(T("dica.exemplo_com"))
        formulario.addRow(T("campo.nome"), self.valor)
        self.nota = QLineEdit()
        self.nota.setPlaceholderText(T("dica.por_que_esta_regra"))
        formulario.addRow("Nota:", self.nota)
        leiaute.addLayout(formulario)

        aviso = QLabel(
            T("texto.a_ordem_importa_a"))
        aviso.setWordWrap(True)
        aviso.setStyleSheet("color: palette(mid);")
        leiaute.addWidget(aviso)

        botoes = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        botoes.accepted.connect(self.accept)
        botoes.rejected.connect(self.reject)
        leiaute.addWidget(botoes)

    def regra(self):
        return {
            "tipo": self.tipo.currentData(),
            "valor": self.valor.text().strip(),
            "acao": self.acao.currentData(),
            "nota": self.nota.text().strip(),
        }


class VisaoFiltro(AbaPapel):
    """O filtro de camada de aplicacao: o que a LAN pode alcancar por nome.

    Tres sub-abas, e a divisao nao e arrumacao: 'Regras' e do PAINEL (o que
    o operador escreveu, no disco dele), 'Servico' e do NO (o que esta de
    fato em vigor la), e 'Bloqueios' e o que aconteceu. As duas primeiras
    podem DIVERGIR -- regra escrita aqui so vale depois de enviada --, e a
    tela diz isso em vermelho em vez de deixar o operador supor.

    O que esta tela nunca vai mostrar: o que passou. O filtro so registra o
    que negou; quem responde 'a rede pediu o que' e o coletor.
    """

    def monta(self):
        self.abas = QTabWidget()

        # ---- Regras: a area de configuracao propriamente dita.
        aba_regras = QWidget()
        dentro = QVBoxLayout(aba_regras)
        dentro.setContentsMargins(0, 6, 0, 0)

        linha = QHBoxLayout()
        linha.addWidget(QLabel(T("texto.politica_padrao")))
        self.politica = QComboBox()
        self.politica.addItem(T("opcao.permitir_so_bloqueia"), "permitir")
        self.politica.addItem(T("opcao.bloquear_lista_branca"),
                              "bloquear")
        self.politica.activated.connect(self._muda_politica)
        linha.addWidget(self.politica, 1)
        dentro.addLayout(linha)

        self.regras = tabela([T("coluna.texto"), T("coluna.acao"), T("coluna.casa_por"), T("coluna.nome"), T("coluna.nota")], 0)
        self.regras.setSortingEnabled(False)   # ordem e semantica, nao arrumacao
        self.regras.sortByColumn(0, Qt.AscendingOrder)
        dentro.addWidget(self.regras, 1)

        botoes = QHBoxLayout()
        for texto, funcao in (("Acrescentar", self._acrescenta),
                              ("Remover", self._remove),
                              ("Subir", lambda: self._move(-1)),
                              ("Descer", lambda: self._move(1))):
            botao = QPushButton(texto)
            botao.clicked.connect(funcao)
            botoes.addWidget(botao)
        botoes.addStretch()
        self.botao_enviar = QPushButton(T("botao.enviar_ao_no"))
        self.botao_enviar.clicked.connect(self._envia)
        botoes.addWidget(self.botao_enviar)
        dentro.addLayout(botoes)

        # Responder "e se?" sem esperar alguem tropecar na regra. E local: le
        # as regras do painel, nao fala com o no.
        teste = QHBoxLayout()
        teste.addWidget(QLabel(T("texto.testar_um_nome")))
        self.teste = QLineEdit()
        self.teste.setPlaceholderText(T("dica.www_exemplo_com"))
        self.teste.textChanged.connect(self._testa)
        teste.addWidget(self.teste, 1)
        self.resultado_teste = QLabel("")
        teste.addWidget(self.resultado_teste, 1)
        dentro.addLayout(teste)

        self.divergencia = QLabel("")
        self.divergencia.setWordWrap(True)
        dentro.addWidget(self.divergencia)
        self.abas.addTab(aba_regras, T("aba.regras"))

        # ---- Servico: o que esta em vigor NO NO.
        aba_servico = QWidget()
        dentro = QVBoxLayout(aba_servico)
        dentro.setContentsMargins(0, 6, 0, 0)
        self.ficha = tabela_chave_valor(T("texto.filtro_nesta_maquina"))
        dentro.addWidget(self.ficha, 1)
        self.ficha_contagem = tabela_chave_valor(T("texto.conexoes_desde"))
        dentro.addWidget(self.ficha_contagem, 1)
        self.abas.addTab(aba_servico, T("aba.servico"))

        # ---- Bloqueios: o unico registro evento a evento deste papel.
        aba_bloqueios = QWidget()
        dentro = QVBoxLayout(aba_bloqueios)
        dentro.setContentsMargins(0, 6, 0, 0)
        dentro.addWidget(QLabel(
            T("texto.conexoes_negadas_somadas_por")))
        self.bloqueios = tabela(
            [T("coluna.regra"), T("coluna.nome"), T("coluna.cliente"), T("coluna.porta"), T("coluna.total"), T("coluna.primeira"), T("coluna.ultima")], 6)
        self.bloqueios.sortByColumn(6, Qt.DescendingOrder)
        dentro.addWidget(self.bloqueios)
        self.abas.addTab(aba_bloqueios, T("aba.bloqueios"))

        self.leiaute.addWidget(self.abas)
        self.mostra_regras()

    # ------------------------------------------------- regras (lado painel)

    def mostra_regras(self):
        """Le do disco do painel. Nao fala com no nenhum: e instantaneo."""
        try:
            dados = self.painel.regras_filtro.tudo()
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        indice = self.politica.findData(dados["politica"])
        if indice >= 0:
            self.politica.setCurrentIndex(indice)
        self.regras.setRowCount(len(dados["regras"]))
        for i, regra in enumerate(dados["regras"]):
            self.regras.setItem(i, 0, celula(i + 1, numero=True))
            self.regras.setItem(i, 1, celula(regra.get("acao", "")))
            self.regras.setItem(i, 2, celula(regra.get("tipo", "")))
            self.regras.setItem(i, 3, celula(regra.get("valor", "")))
            self.regras.setItem(i, 4, celula(regra.get("nota", "")))
            if regra.get("acao") == "bloquear":
                for coluna in range(self.regras.columnCount()):
                    item = self.regras.item(i, coluna)
                    if item is not None:
                        item.setForeground(QBrush(QColor(190, 60, 60)))
        self.abas.setTabText(0, T("aba.contagem").format(T("aba.regras"), len(dados["regras"])))
        self._testa()
        self._confere_divergencia()

    def _linha_escolhida(self):
        linhas = {i.row() for i in self.regras.selectedIndexes()}
        if len(linhas) != 1:
            self.avisar(T("msg.escolha_uma_regra_na_tabela"))
            return None
        return linhas.pop()

    def _acrescenta(self):
        dialogo = DialogoRegraFiltro(self)
        if dialogo.exec() != QDialog.Accepted:
            return
        regra = dialogo.regra()
        try:
            # Excecao entra ACIMA das outras por padrao: uma regra
            # 'permitir' colocada no fim, embaixo do bloqueio que ela abre,
            # nao faz nada -- e o erro que se comete na primeira vez.
            posicao = 0 if regra["acao"] == "permitir" else None
            self.painel.regras_filtro.adiciona(
                regra["tipo"], regra["valor"], regra["acao"], regra["nota"], posicao)
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.mostra_regras()

    def _remove(self):
        linha = self._linha_escolhida()
        if linha is None:
            return
        try:
            self.painel.regras_filtro.remove(linha)
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.mostra_regras()

    def _move(self, passo):
        linha = self._linha_escolhida()
        if linha is None:
            return
        try:
            self.painel.regras_filtro.move(linha, linha + passo)
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.mostra_regras()
        self.regras.selectRow(max(0, min(linha + passo, self.regras.rowCount() - 1)))

    def _muda_politica(self):
        politica = self.politica.currentData()
        if politica == "bloquear" and QMessageBox.question(
                self, "GHop",
                T("msg.politica_bloquear_e_lista_branca"),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            self.mostra_regras()
            return
        try:
            self.painel.regras_filtro.define_politica(politica)
        except ErroGHop as falha:
            self.avisar(str(falha))
        self.mostra_regras()

    def _testa(self, *_):
        nome = self.teste.text().strip()
        if not nome:
            self.resultado_teste.setText("")
            return
        try:
            acao, regra = self.painel.regras_filtro.decide(nome)
        except ErroGHop as falha:
            self.resultado_teste.setText(str(falha))
            return
        cor = "#be3c3c" if acao == "bloquear" else "#2e7d32"
        self.resultado_teste.setText(
            T("texto.por").format(cor, acao, regra))

    def _envia(self):
        if QMessageBox.question(
                self, "GHop",
                T("msg.as_regras_deste_painel_passam").format(self.no),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        self.botao_enviar.setEnabled(False)
        self.estado.setText(T("texto.enviando"))
        tarefa = Tarefa(self.painel.sincroniza_filtro, self.no)
        tarefa.sinais.pronto.connect(self._enviou)
        tarefa.sinais.falhou.connect(self._falhou_enviar)
        self.pool.start(tarefa)

    @Slot(object)
    def _enviou(self, resultado):
        self.botao_enviar.setEnabled(True)
        aceitos, falhas = resultado
        if falhas:
            self.avisar(f"{self.no}: {'; '.join(falhas.values())}")
        else:
            self.estado.setText(T("texto.regra_s_enviadas").format(aceitos.get(self.no, 0)))
        self.recarrega()

    @Slot(str)
    def _falhou_enviar(self, mensagem):
        self.botao_enviar.setEnabled(True)
        self.estado.setText(T("texto.falhou"))
        self.avisar(f"{self.no}: {mensagem}")

    def _confere_divergencia(self, do_no=None):
        """Diz, em vermelho, quando o painel e o no discordam.

        Sem isto o operador escreve uma regra, ve a tabela mudar e sai
        achando que a maquina mudou junto -- e ela so muda no 'Enviar'.
        """
        if do_no is None:
            do_no = getattr(self, "_ultimo_do_no", None)
        if do_no is None:
            self.divergencia.setText("")
            return
        self._ultimo_do_no = do_no
        try:
            daqui = self.painel.regras_filtro.tudo()
        except ErroGHop:
            return
        iguais = (daqui["politica"] == do_no.get("politica") and
                  [(r.get("tipo"), r.get("valor"), r.get("acao"))
                   for r in daqui["regras"]] ==
                  [(r.get("tipo"), r.get("valor"), r.get("acao"))
                   for r in do_no.get("regras") or []])
        if iguais:
            self.divergencia.setStyleSheet("color: palette(mid);")
            self.divergencia.setText(T("texto.em_vigor_em_iguais").format(self.no))
        else:
            self.divergencia.setStyleSheet("color: #be3c3c;")
            self.divergencia.setText(
                T("texto.estas_regras_ainda_nao").format(self.no, len(do_no.get('regras') or []), do_no.get('politica')))

    # ---------------------------------------------------- lado do no

    def preenche(self, dados):
        contagem = dados.get("contadores") or {}
        ativo = dados.get("ativo", "?")
        redirecionando = dados.get("redirecionando")
        # 'active' sozinho mente quando o redirecionamento nao esta no
        # firewall: o servico esta de pe e nao ve trafego nenhum. A linha de
        # resumo e a que fica sempre a vista, entao o aviso tem de estar
        # nela, e nao so na ficha da aba Servico.
        self.resumo.setText(
            T("texto.regras_em_vigor").format(
                ativo, len(dados.get("regras") or []), contagem.get("bloqueadas", 0))
            if redirecionando else
            T("texto.nao_filtra").format(ativo))

        preenche_ficha(self.ficha, [
            (T("ficha.servico"), f"{ativo} / {dados.get('habilitado', '?')}"),
            (T("ficha.interface_filtrada"), dados.get("interface")),
            (T("ficha.politica_em_vigor"), dados.get("politica")),
            (T("ficha.regras_em_vigor"), str(len(dados.get("regras") or []))),
            # Servico de pe sem o redirecionamento no firewall nao ve nada.
            # Sem esta linha a tela diria 'ativo' e o operador acharia que
            # esta filtrando.
            (T("ficha.redirecionamento_no_firewall"),
             T("texto.sim") if redirecionando else T("texto.nao_recebe_trafego")),
            (T("ficha.le"), T("ficha.sni_do_clienthello_tls")),
            (T("ficha.descriptografa"), T("ficha.nao_e_nao_ha")),
            (T("ficha.registra"), T("ficha.so_o_que_foi")),
        ])
        preenche_ficha(self.ficha_contagem, [
            (T("ficha.desde"), contagem.get("desde")),
            (T("ficha.conexoes_vistas"), contagem.get("conexoes")),
            (T("ficha.permitidas"), contagem.get("permitidas")),
            (T("ficha.bloqueadas"), contagem.get("bloqueadas")),
            # O tamanho do buraco, a vista: sem nome nao ha o que casar.
            (T("ficha.sem_nome_legivel_passaram"), contagem.get("sem_nome")),
        ])

        linhas = dados.get("bloqueios") or []
        self.bloqueios.setSortingEnabled(False)
        self.bloqueios.setRowCount(len(linhas))
        for i, bloqueio in enumerate(linhas):
            self.bloqueios.setItem(i, 0, celula(bloqueio.get("regra", "")))
            self.bloqueios.setItem(i, 1, celula(bloqueio.get("nome", "")))
            self.bloqueios.setItem(i, 2, celula(bloqueio.get("cliente", "")))
            self.bloqueios.setItem(i, 3, celula(bloqueio.get("porta", "")))
            self.bloqueios.setItem(i, 4, celula(bloqueio.get("total") or 0, numero=True))
            self.bloqueios.setItem(i, 5, celula(bloqueio.get("primeiro", "")))
            self.bloqueios.setItem(i, 6, celula(bloqueio.get("ultimo", "")))
        self.bloqueios.setSortingEnabled(True)
        self.abas.setTabText(2, T("aba.contagem").format(T("aba.bloqueios"), len(linhas)))

        self._confere_divergencia(dados)


ABAS_DE_PAPEL = {"wifi": AbaWifi}

# Papeis que rendem uma VISAO inteira, no mesmo nivel de 'Dados'.
VISOES_DE_PAPEL = {"nftables": VisaoRoteamento, "dns": VisaoDNS,
                   "dhcp": VisaoDHCP, "filtro": VisaoFiltro}


def tamanho_legivel(bytes_):
    """'1,4 GB', '512 MB'. Base 1000, que e como fabricante e df falam."""
    valor = float(bytes_ or 0)
    for unidade in ("B", "kB", "MB", "GB", "TB"):
        if valor < 1000 or unidade == "TB":
            texto = f"{valor:.0f}" if unidade == "B" else f"{valor:.1f}".rstrip("0").rstrip(".")
            return f"{texto} {unidade}".replace(".", ",")
        valor /= 1000
    return ""


class BarrasNucleos(QWidget):
    """Uma barra por nucleo, com o uso de agora.

    Trinta nucleos viram trinta linhas ilegiveis num grafico; em barra cabem
    todos e da para ver de relance se a carga esta espalhada ou empilhada em
    um so -- que e a pergunta que se faz olhando processador.
    """

    def __init__(self):
        super().__init__()
        self.valores = []
        self.setMinimumHeight(60)

    def atualiza(self, valores):
        self.valores = valores
        altura = self.fontMetrics().height()
        colunas = 2 if len(valores) > 8 else 1
        linhas = (len(valores) + colunas - 1) // colunas
        self.setMinimumHeight(max(40, linhas * (altura + 4) + 8))
        self.setToolTip(T("ajuda.uso_de_cada_nucleo"))
        self.update()

    def paintEvent(self, _evento):
        if not self.valores:
            return
        pintor = QPainter(self)
        pintor.setRenderHint(QPainter.Antialiasing)
        paleta = self.palette()
        metrica = pintor.fontMetrics()
        altura_linha = metrica.height()
        texto_cor = paleta.color(paleta.ColorRole.WindowText)

        colunas = 2 if len(self.valores) > 8 else 1
        por_coluna = (len(self.valores) + colunas - 1) // colunas
        largura_coluna = self.width() // colunas
        rotulo_largura = metrica.horizontalAdvance("cpu99") + 6
        numero_largura = metrica.horizontalAdvance("100%") + 6

        for indice, (nome, valor) in enumerate(self.valores):
            coluna, linha = divmod(indice, por_coluna)
            x = coluna * largura_coluna
            y = 4 + linha * (altura_linha + 4)
            pintor.setPen(texto_cor)
            pintor.drawText(x, y, rotulo_largura, altura_linha,
                            Qt.AlignLeft | Qt.AlignVCenter, nome)
            trilho = QRect(x + rotulo_largura, y + 2,
                           max(10, largura_coluna - rotulo_largura - numero_largura - 10),
                           altura_linha - 4)
            pintor.setPen(Qt.NoPen)
            pintor.setBrush(paleta.color(paleta.ColorRole.AlternateBase))
            pintor.drawRoundedRect(trilho, 2, 2)
            # Verde ate 60, ambar ate 85, vermelho acima: o mesmo semaforo
            # que se usa para olhar carga sem precisar ler o numero.
            cor = (QColor(60, 140, 70) if valor < 60 else
                   QColor(200, 150, 40) if valor < 85 else QColor(190, 60, 60))
            pintor.setBrush(cor)
            cheio = QRect(trilho)
            cheio.setWidth(int(trilho.width() * min(100.0, valor) / 100.0))
            pintor.drawRoundedRect(cheio, 2, 2)
            pintor.setPen(texto_cor)
            pintor.drawText(trilho.right() + 4, y, numero_largura, altura_linha,
                            Qt.AlignRight | Qt.AlignVCenter, f"{valor:.0f}%")


class VisaoMaquina(QWidget):
    """O que a maquina E: processador, memoria, disco e versoes.

    Primeira aba de propósito. Papel parado, coleta vazia e agente lento tem
    explicacao aqui com frequencia -- disco cheio, memoria no fim, carga alta
    -- e olhar isso antes evita procurar defeito no lugar errado.
    """

    def __init__(self, painel, no, avisar):
        super().__init__()
        self.painel, self.no, self.avisar = painel, no, avisar
        self.pool = QThreadPool.globalInstance()

        leiaute = QVBoxLayout(self)
        controles = QHBoxLayout()
        self.botao = QPushButton(T("botao.atualizar"))
        self.botao.clicked.connect(self.recarrega)
        controles.addWidget(self.botao)
        self.ao_vivo = QCheckBox(T("opcao.ao_vivo", s=5))
        self.ao_vivo.setChecked(True)
        controles.addWidget(self.ao_vivo)
        self.fundo = botao_segundo_plano()
        self.fundo.toggled.connect(self._ajusta_relogio)
        controles.addWidget(self.fundo)
        controles.addStretch()
        self.estado = QLabel("")
        self.estado.setStyleSheet("color: palette(mid);")
        controles.addWidget(self.estado)
        leiaute.addLayout(controles)

        self.identificacao = QLabel("")
        self.identificacao.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.identificacao.setWordWrap(True)
        leiaute.addWidget(self.identificacao)

        rolagem = QScrollArea()
        rolagem.setWidgetResizable(True)
        dentro = QWidget()
        pilha = QVBoxLayout(dentro)
        pilha.setContentsMargins(0, 0, 0, 0)

        self.cpu = GraficoTrafego(
            T("texto.processador_somado"),
            series=[("uso", QColor(150, 80, 160), 1)],
            formata=lambda v: f"{v:.0f}%")
        pilha.addWidget(self.cpu)
        pilha.addWidget(QLabel(T("texto.por_nucleo_agora")))
        self.nucleos = BarrasNucleos()
        pilha.addWidget(self.nucleos)

        self.memoria = GraficoTrafego(
            "Memoria",
            series=[("RAM", QColor(40, 120, 200), 1), ("swap", QColor(210, 120, 30), 2)],
            formata=lambda v: f"{v:.0f}%")
        pilha.addWidget(self.memoria)
        self.memoria_texto = QLabel("")
        pilha.addWidget(self.memoria_texto)

        pilha.addWidget(QLabel(T("texto.discos")))
        self.discos = tabela(
            [T("coluna.ponto"), T("coluna.dispositivo"), T("coluna.tipo"), T("coluna.total"), T("coluna.usado"), T("coluna.livre"), T("coluna.uso")], 0)
        self.discos.sortByColumn(0, Qt.AscendingOrder)
        self.discos.setMinimumHeight(120)
        pilha.addWidget(self.discos)
        rolagem.setWidget(dentro)
        leiaute.addWidget(rolagem, 1)

        self.relogio = QTimer(self)
        self.relogio.setInterval(5000)
        self.relogio.timeout.connect(self.recarrega)
        self.ao_vivo.toggled.connect(self._ajusta_relogio)

    def _ajusta_relogio(self, *_):
        # Para COMECAR basta estar na aba da frente: no instante do
        # showEvent a regiao visivel ainda nao foi calculada, e exigir
        # a_vista() aqui deixaria o relogio parado para sempre. Quem
        # confere de verdade e cada tique, que para se ninguem estiver
        # olhando.
        if self.ao_vivo.isChecked() and (self.isVisible() or self.fundo.isChecked()):
            self.relogio.start()
        else:
            self.relogio.stop()

    def showEvent(self, evento):
        super().showEvent(evento)
        self._ajusta_relogio()

    def hideEvent(self, evento):
        super().hideEvent(evento)
        if not self.fundo.isChecked():
            self.relogio.stop()

    def recarrega(self):
        if self.sender() is self.relogio and not (
                a_vista(self) or self.fundo.isChecked()):
            self.relogio.stop()
            return
        self.botao.setEnabled(False)
        tarefa = Tarefa(self.painel.sistema, self.no)
        tarefa.sinais.pronto.connect(self.preenche)
        tarefa.sinais.falhou.connect(self.deu_errado)
        self.pool.start(tarefa)

    @staticmethod
    def _ligada_ha(segundos):
        dias, resto = divmod(int(segundos or 0), 86400)
        horas, resto = divmod(resto, 3600)
        minutos = resto // 60
        if dias:
            return f"{dias}d {horas}h {minutos}min"
        return f"{horas}h {minutos}min" if horas else f"{minutos}min"

    @Slot(object)
    def preenche(self, dados):
        self.botao.setEnabled(True)
        self.estado.setText(T("texto.em").format(dados.get('quando')))
        basico = dados.get("basico") or {}
        carga = basico.get("carga") or []
        self.identificacao.setText(
            T("texto.nbsp_nbsp_kernel_nbsp").format(basico.get('maquina', '?'), basico.get('sistema', '?'), basico.get('kernel', '?'), basico.get('arquitetura', '?'), basico.get('processador', 'processador desconhecido'), basico.get('nucleos', '?'), ', '.join(str(c) for c in carga) if carga else '?', self._ligada_ha(basico.get('ligada_ha'))))

        agora = float(dados.get("agora") or time.time())
        janela = int(dados.get("janela") or 600)
        nomes = dados.get("processadores") or []
        serie = dados.get("serie_cpu") or []
        # A serie traz total e cada nucleo; o grafico mostra o total, e as
        # barras mostram os nucleos. Duas perguntas diferentes.
        self.cpu.atualiza([[p[0], p[1]] for p in serie] if serie else [], agora, janela)
        if serie and len(nomes) > 1:
            self.nucleos.atualiza(
                [(nome, serie[-1][i + 1]) for i, nome in enumerate(nomes) if nome != "total"])

        self.memoria.atualiza(dados.get("serie_memoria") or [], agora, janela)
        memoria = dados.get("memoria") or {}
        swap_total = memoria.get("swap_total") or 0
        self.memoria_texto.setText(
            f"RAM {tamanho_legivel(memoria.get('ram_usada'))} de "
            f"{tamanho_legivel(memoria.get('ram_total'))}"
            + (f"   -   swap {tamanho_legivel(memoria.get('swap_usada'))} de "
               f"{tamanho_legivel(swap_total)}" if swap_total else
               T("texto.sem_swap")))

        linhas = dados.get("discos") or []
        self.discos.setSortingEnabled(False)
        self.discos.setRowCount(len(linhas))
        for i, disco in enumerate(linhas):
            self.discos.setItem(i, 0, celula(disco.get("ponto", "")))
            self.discos.setItem(i, 1, celula(disco.get("dispositivo", "")))
            self.discos.setItem(i, 2, celula(disco.get("tipo", "")))
            self.discos.setItem(i, 3, celula(tamanho_legivel(disco.get("total"))))
            self.discos.setItem(i, 4, celula(tamanho_legivel(disco.get("usado"))))
            self.discos.setItem(i, 5, celula(tamanho_legivel(disco.get("livre"))))
            percentual = disco.get("percentual") or 0
            item = celula(f"{percentual:.0f}")
            item.setData(Qt.DisplayRole, percentual)
            self.discos.setItem(i, 6, item)
            # Disco quase cheio e o defeito que derruba coleta e servico sem
            # dar erro que se pareca com disco cheio.
            if percentual >= 90:
                cor = QBrush(QColor(190, 40, 40))
            elif percentual >= 75:
                cor = QBrush(QColor(200, 150, 40))
            else:
                cor = None
            if cor is not None:
                for coluna in range(self.discos.columnCount()):
                    celula_item = self.discos.item(i, coluna)
                    if celula_item is not None:
                        celula_item.setForeground(cor)
        self.discos.setSortingEnabled(True)

    @Slot(str)
    def deu_errado(self, mensagem):
        self.botao.setEnabled(True)
        self.estado.setText(T("texto.falhou"))
        self.relogio.stop()
        self.avisar(f"{self.no}: {mensagem}")


class VisaoServicos(QWidget):
    """Os papeis do GHop nesta maquina, e os botoes que os mudam.

    E a UNICA tela do painel que muda a maquina do outro lado. Por isso:
    cada acao pede confirmacao dizendo o que ela causa, o pedido volta na
    hora (a acao roda destacada la) e o rodape mostra a saida do instalador
    enquanto ela anda. Nada acontece por passar o mouse ou trocar de aba.
    """

    INTERVALO_ACAO = 3000

    def __init__(self, painel, no, avisar):
        super().__init__()
        self.painel, self.no, self.avisar = painel, no, avisar
        self.pool = QThreadPool.globalInstance()

        leiaute = QVBoxLayout(self)
        controles = QHBoxLayout()
        self.botao = QPushButton(T("botao.atualizar"))
        self.botao.clicked.connect(self.recarrega)
        controles.addWidget(self.botao)
        controles.addStretch()
        self.estado = QLabel("")
        self.estado.setStyleSheet("color: palette(mid);")
        controles.addWidget(self.estado)
        leiaute.addLayout(controles)

        self.papeis = tabela([T("coluna.papel"), T("coluna.unidade"), T("coluna.estado"), T("coluna.no_boot"), T("coluna.origem")], 0)
        self.papeis.sortByColumn(0, Qt.AscendingOrder)
        self.papeis.itemSelectionChanged.connect(self._ajusta_botoes)
        leiaute.addWidget(self.papeis, 2)

        acoes = QHBoxLayout()
        self.botoes = {}
        for chave, definicao in nucleo.ACOES_PAPEL.items():
            botao = QPushButton(definicao["rotulo"])
            botao.setToolTip(definicao["aviso"])
            botao.setEnabled(False)
            botao.clicked.connect(lambda _=False, c=chave: self.pede(c))
            acoes.addWidget(botao)
            self.botoes[chave] = botao
        acoes.addStretch()
        leiaute.addLayout(acoes)

        leiaute.addWidget(QLabel(T("texto.ultima_acao")))
        self.saida = QPlainTextEdit()
        self.saida.setReadOnly(True)
        self.saida.setMaximumBlockCount(500)
        leiaute.addWidget(self.saida, 1)

        # Enquanto uma acao anda, o painel pergunta como ela vai. Para quando
        # ela termina: nada aqui fica consultando sozinho para sempre.
        self.relogio = QTimer(self)
        self.relogio.setInterval(self.INTERVALO_ACAO)
        self.relogio.timeout.connect(self.acompanha)

    def _papel_escolhido(self):
        linha = self.papeis.currentRow()
        if linha < 0:
            return None
        item = self.papeis.item(linha, 0)
        return item.data(PAPEL_LINHA) if item else None

    def _ajusta_botoes(self):
        papel = self._papel_escolhido()
        gerenciavel = bool(papel) and papel.get("chave") in nucleo.PAPEIS_GERENCIAVEIS
        instalado = bool(papel) and papel.get("instalado")
        ativo = bool(papel) and papel.get("ativo") == "active"
        # Servico que ja estava na maquina nao se desinstala daqui: o
        # instalador desfaz a partir da copia que ele mesmo guardou, e sem
        # essa copia nao ha o que restaurar. O agente recusa de qualquer
        # jeito; aqui o botao so nao mente. Iniciar e parar continuam
        # valendo, e sao reversiveis tambem no alheio: o script cai no
        # systemctl puro quando nao acha marca nossa (ver dhcp.sh).
        alheio = bool(papel) and papel.get("origem") == "sistema"
        self.botoes["instalar"].setEnabled(gerenciavel)
        self.botoes["iniciar"].setEnabled(gerenciavel and instalado and not ativo)
        self.botoes["parar"].setEnabled(gerenciavel and ativo)
        self.botoes["desinstalar"].setEnabled(gerenciavel and instalado and not alheio)

    def recarrega(self):
        self.botao.setEnabled(False)
        self.estado.setText(T("texto.consultando"))
        tarefa = Tarefa(self.painel.papeis, self.no)
        tarefa.sinais.pronto.connect(self.preenche)
        tarefa.sinais.falhou.connect(self.deu_errado)
        self.pool.start(tarefa)
        self.acompanha()

    @Slot(object)
    def preenche(self, dados):
        self.botao.setEnabled(True)
        self.estado.setText(T("texto.em").format(dados.get('quando')))
        # A tabela mostra TODOS os papeis gerenciaveis, nao so os instalados:
        # sem isso nao haveria onde clicar para instalar o que falta.
        presentes = {p["chave"]: p for p in dados.get("papeis", [])}
        chaves = list(dict.fromkeys(
            list(presentes) + list(nucleo.PAPEIS_GERENCIAVEIS)))
        self.papeis.setSortingEnabled(False)
        self.papeis.setRowCount(len(chaves))
        for i, chave in enumerate(chaves):
            papel = dict(presentes.get(chave) or {"chave": chave, "rotulo": chave})
            papel["instalado"] = chave in presentes
            principal = celula(papel.get("rotulo", chave))
            principal.setData(PAPEL_LINHA, papel)
            self.papeis.setItem(i, 0, principal)
            self.papeis.setItem(i, 1, celula(papel.get("unidade", "")))
            # Papel sem unidade nao esta parado: nao tem servico para estar.
            # O lojmIt e um sysctl, e mostrar "?" ali fazia parecer avaria.
            if papel["instalado"] and not papel.get("ativo"):
                estado = "?" if papel.get("unidade") else T("texto.sem_servico_proprio")
            else:
                estado = papel.get("ativo") or T("texto.nao_instalado")
            self.papeis.setItem(i, 2, celula(estado))
            self.papeis.setItem(i, 3, celula(papel.get("habilitado", "")))
            # De onde o servico veio. 'ja estava aqui' quer dizer que nao
            # fomos nos que instalamos -- e o que explica o botao Desinstalar
            # desligado. O texto sai do nucleo: a linha de comando mostra a
            # mesma coluna.
            self.papeis.setItem(i, 4, celula(
                nucleo.ORIGENS_PAPEL.get(papel.get("origem", ""), "")))
            apagado = not papel["instalado"] or (
                papel.get("ativo") != "active" and papel.get("unidade"))
            if apagado:
                for coluna in range(self.papeis.columnCount()):
                    item = self.papeis.item(i, coluna)
                    if item is not None:
                        item.setForeground(QBrush(QColor(140, 140, 140)))
        self.papeis.setSortingEnabled(True)
        self._ajusta_botoes()

    def pede(self, acao):
        papel = self._papel_escolhido()
        if not papel:
            return
        definicao = nucleo.ACOES_PAPEL[acao]
        resposta = QMessageBox.question(
            self, "GHop",
            T("msg.o_papel_em_isto_muda").format(definicao['rotulo'], papel.get('rotulo'), self.no, definicao['aviso']),
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if resposta != QMessageBox.Yes:
            return
        self.saida.setPlainText(
            T("msg.pedindo_acao").format(acao, papel["chave"], self.no))
        tarefa = Tarefa(self.painel.papel, self.no, papel["chave"], acao)
        tarefa.sinais.pronto.connect(self.comecou)
        tarefa.sinais.falhou.connect(self.deu_errado)
        self.pool.start(tarefa)

    @Slot(object)
    def comecou(self, dados):
        self.saida.appendPlainText(
            f"{dados.get('acao')} de {dados.get('papel')} iniciada em {dados.get('quando')}")
        if not self.relogio.isActive():
            self.relogio.start()

    def acompanha(self):
        # A acao continua rodando na maquina de la; o que para aqui e a
        # pergunta. Ao voltar para a aba, retoma-se de onde estiver.
        if self.sender() is self.relogio and not a_vista(self):
            self.relogio.stop()
            return
        tarefa = Tarefa(self.painel.acao, self.no)
        tarefa.sinais.pronto.connect(self.mostra_acao)
        tarefa.sinais.falhou.connect(self.acao_falhou)
        self.pool.start(tarefa)

    @Slot(object)
    def mostra_acao(self, dados):
        # Sem 'andando' o relogio para logo abaixo; com ele, so segue se a
        # aba estiver a vista.
        ultima = dados.get("ultima") or {}
        cabeca = (f"{ultima.get('acao', '?')} de {ultima.get('papel', '?')}, "
                  f"pedida em {ultima.get('quando', '?')}: "
                  f"{'andando' if dados.get('andando') else dados.get('resultado') or 'terminada'}")
        self.saida.setPlainText(cabeca + "\n\n" + (dados.get("saida") or ""))
        self.saida.verticalScrollBar().setValue(
            self.saida.verticalScrollBar().maximum())
        if dados.get("andando") and a_vista(self) and not self.relogio.isActive():
            self.relogio.start()
        if not dados.get("andando"):
            self.relogio.stop()
            # Terminou: a lista de papeis mudou, entao vale reler.
            tarefa = Tarefa(self.painel.papeis, self.no)
            tarefa.sinais.pronto.connect(self.preenche)
            tarefa.sinais.falhou.connect(self.deu_errado)
            self.pool.start(tarefa)

    @Slot(str)
    def acao_falhou(self, mensagem):
        # Perder o acompanhamento nao e erro de tela: a maquina pode ter
        # ficado sem rede exatamente por causa da acao pedida.
        self.relogio.stop()
        self.saida.appendPlainText(T("msg.sem_resposta_de").format(self.no, mensagem))

    def showEvent(self, evento):
        super().showEvent(evento)
        # Voltou a ser vista: um pedido para saber se a acao terminou
        # enquanto se olhava outra coisa.
        if self.saida.toPlainText().strip():
            self.acompanha()

    def hideEvent(self, evento):
        super().hideEvent(evento)
        self.relogio.stop()

    @Slot(str)
    def deu_errado(self, mensagem):
        self.botao.setEnabled(True)
        self.estado.setText(T("texto.falhou"))
        self.avisar(f"{self.no}: {mensagem}")


class VisaoDados(QWidget):
    """A maquina em si: o que ela e, nao o que ela faz.

    Abas por assunto. Hoje so 'Rede', com as interfaces como o agente as ve
    agora; o desenho e para receber outras (discos, processos, o que for),
    cada uma alimentada pelo seu comando de leitura. Nada aqui e historico:
    e o retrato de quando se clicou em Atualizar.
    """

    def __init__(self, painel, no, avisar):
        super().__init__()
        self.painel, self.no, self.avisar = painel, no, avisar
        self.pool = QThreadPool.globalInstance()

        leiaute = QVBoxLayout(self)
        controles = QHBoxLayout()
        self.botao = QPushButton(T("botao.atualizar"))
        self.botao.clicked.connect(self.recarrega)
        controles.addWidget(self.botao)
        controles.addStretch()
        self.estado = QLabel("")
        controles.addWidget(self.estado)
        leiaute.addLayout(controles)

        self.abas = QTabWidget()
        self.abas.addTab(self._aba_trafego(), T("aba.trafego"))
        self.abas.addTab(self._aba_rede(), T("aba.rede"))
        self.abas.addTab(self._aba_rotas(), T("aba.rotas"))
        # As abas de papel (hoje so Wi-Fi) sao acrescentadas depois, so nos
        # nos que tiverem aquele papel -- e o agente que diz quais sao. O que
        # rende tela inteira (DHCP, DNS, Roteamento) nao entra aqui: vai ao
        # lado de 'Dados', por VISOES_DE_PAPEL.
        self.abas_papel = {}
        leiaute.addWidget(self.abas)
        # Tres consultas por Atualizar, uma por aba; o botao volta quando
        # todas responderem, e cada uma preenche a sua.
        self.pendentes = 0

        # O grafico de trafego e a unica coisa do painel que se atualiza
        # sozinha, e so enquanto esta a vista: e um "agora" que envelhece em
        # segundos. Consulta o agente, nunca servico de fora, entao nao fere
        # o "nada consulta sozinho" -- mas a caixa desliga quando se quer.
        self.relogio = QTimer(self)
        self.relogio.setInterval(5000)
        self.relogio.timeout.connect(self.recarrega_trafego)
        self.abas.currentChanged.connect(self._ajusta_relogio)
        self.ao_vivo.toggled.connect(self._ajusta_relogio)

    def _aba_trafego(self):
        aba = QWidget()
        leiaute = QVBoxLayout(aba)
        leiaute.setContentsMargins(0, 6, 0, 0)
        linha = QHBoxLayout()
        self.ao_vivo = QCheckBox(T("opcao.ao_vivo_aba", s=5))
        self.ao_vivo.setChecked(True)
        linha.addWidget(self.ao_vivo)
        self.fundo = botao_segundo_plano()
        self.fundo.toggled.connect(self._ajusta_relogio)
        linha.addWidget(self.fundo)
        linha.addStretch()
        self.trafego_estado = QLabel("")
        self.trafego_estado.setStyleSheet("color: palette(mid);")
        linha.addWidget(self.trafego_estado)
        leiaute.addLayout(linha)
        self.graficos_caixa = QWidget()
        self.graficos_leiaute = QVBoxLayout(self.graficos_caixa)
        self.graficos_leiaute.setContentsMargins(0, 0, 0, 0)
        self.graficos = {}
        leiaute.addWidget(self.graficos_caixa, 1)
        return aba

    def _ajusta_relogio(self, *_):
        # Comeca pela aba da frente (ver a nota em VisaoMaquina); parar e
        # tarefa do tique, que sabe se a janela esta mesmo a vista.
        mostrando = (self.abas.currentIndex() == 0 and self.isVisible()) \
            or self.fundo.isChecked()
        if mostrando and self.ao_vivo.isChecked():
            if not self.relogio.isActive():
                self.relogio.start()
        else:
            self.relogio.stop()

    def showEvent(self, evento):
        super().showEvent(evento)
        self._ajusta_relogio()

    def hideEvent(self, evento):
        super().hideEvent(evento)
        if not self.fundo.isChecked():
            self.relogio.stop()

    def recarrega_trafego(self):
        # Conferido de novo a cada tique: a janela pode ter sido coberta
        # depois de o relogio comecar, e ai a proxima pergunta nao sai.
        if self.sender() is self.relogio and not self.fundo.isChecked() and not (
                a_vista(self) and self.abas.currentIndex() == 0):
            self.relogio.stop()
            return
        tarefa = Tarefa(self.painel.trafego, self.no)
        tarefa.sinais.pronto.connect(self.preenche_trafego)
        tarefa.sinais.falhou.connect(self.trafego_falhou)
        self.pool.start(tarefa)

    @Slot(object)
    def preenche_trafego(self, dados):
        series = dados.get("interfaces") or {}
        agora = float(dados.get("agora") or time.time())
        janela = int(dados.get("janela") or 600)
        for nome in sorted(series):
            if nome not in self.graficos:
                # Risco entre um grafico e o proximo: empilhados sem nada
                # entre eles, a linha de baixo de um parece do outro.
                if self.graficos:
                    risco = QFrame()
                    risco.setFrameShape(QFrame.HLine)
                    risco.setFrameShadow(QFrame.Sunken)
                    self.graficos_leiaute.addWidget(risco)
                grafico = GraficoTrafego(nome)
                self.graficos[nome] = grafico
                self.graficos_leiaute.addWidget(grafico)
            self.graficos[nome].atualiza(series[nome], agora, janela)
        # Interface que sumiu do agente fica no grafico, congelada e marcada.
        for nome, grafico in self.graficos.items():
            if nome not in series:
                grafico.setToolTip(T("ajuda.nao_esta_mais_no").format(nome))
        pontos = sum(len(p) for p in series.values())
        self.trafego_estado.setText(
            T("texto.interfaces_amostra").format(
                len(series), dados.get("intervalo"), dados.get("quando"))
            if pontos else T("texto.agente_sem_amostras"))
        if self.pendentes:
            self._respondeu()

    @Slot(str)
    def trafego_falhou(self, mensagem):
        self.trafego_estado.setText(T("texto.falhou"))
        self.relogio.stop()
        self.avisar(f"{self.no}: {mensagem}")
        if self.pendentes:
            self._respondeu()

    def _aba_rotas(self):
        aba = QWidget()
        leiaute = QVBoxLayout(aba)
        leiaute.setContentsMargins(0, 6, 0, 0)
        self.rotas = tabela(
            [T("coluna.destino"), T("coluna.via"), T("coluna.por"), T("coluna.origem"), T("coluna.protocolo"), T("coluna.escopo"),
             T("coluna.metrica"), T("coluna.tabela")], 0)
        self.rotas.sortByColumn(7, Qt.AscendingOrder)
        leiaute.addWidget(self.rotas, 3)
        # As regras de politica sao o que um dia vai dizer "isto vai por
        # VPN". Hoje sao as tres de fabrica; ficam a vista mesmo assim.
        leiaute.addWidget(QLabel(T("texto.regras_de_politica_ip")))
        # A tabela vem primeiro porque e o que a regra RESOLVE; a prioridade
        # e so a ordem em que sao consultadas, e cabe no tamanho do numero.
        self.regras = tabela([T("coluna.tabela"), T("coluna.prioridade"), T("coluna.de"), T("coluna.para"), T("coluna.marca"), T("coluna.entrada")], 1)
        cabeca = self.regras.horizontalHeader()
        cabeca.setSectionResizeMode(QHeaderView.ResizeToContents)
        # A sobra fica com a ultima coluna, em vez de inchar a primeira.
        cabeca.setStretchLastSection(True)
        self.regras.sortByColumn(1, Qt.AscendingOrder)
        leiaute.addWidget(self.regras, 1)
        return aba

    def _aba_rede(self):
        aba = QWidget()
        leiaute = QVBoxLayout(aba)
        leiaute.setContentsMargins(0, 6, 0, 0)
        self.rota = QLabel("")
        self.rota.setTextInteractionFlags(Qt.TextSelectableByMouse)
        leiaute.addWidget(self.rota)
        self.interfaces = tabela(
            [T("coluna.interface"), T("coluna.tipo"), T("coluna.estado"), T("coluna.mac"), T("coluna.enderecos"), T("coluna.detalhe"),
             T("coluna.mtu"), T("coluna.rx_mb"), T("coluna.tx_mb")], 0)
        # Interfaces se leem em ordem de nome, nao de contagem.
        self.interfaces.sortByColumn(0, Qt.AscendingOrder)
        leiaute.addWidget(self.interfaces)
        return aba

    def recarrega(self):
        self.botao.setEnabled(False)
        self.estado.setText(T("texto.consultando"))
        self.pendentes = 4
        for funcao, preenche in ((self.painel.interfaces, self.preenche),
                                 (self.painel.rotas, self.preenche_rotas),
                                 (self.painel.papeis, self.preenche_papeis)):
            tarefa = Tarefa(funcao, self.no)
            tarefa.sinais.pronto.connect(preenche)
            tarefa.sinais.falhou.connect(self.deu_errado)
            self.pool.start(tarefa)
        self.recarrega_trafego()

    @Slot(object)
    def preenche_papeis(self, dados):
        """Cria uma aba por papel do GHop que exista naquele no.

        Papel que sumir do agente NAO tira a aba: some sem aviso e o
        operador acha que nunca existiu. A aba fica e, ao atualizar, diz o
        que houve.
        """
        self._respondeu()
        for papel in dados.get("papeis", []):
            chave = papel.get("chave")
            # Quem manda no destino e nucleo.PAPEIS['visao']; este dicionario
            # so diz COM QUE classe desenhar. Sem consultar 'visao' aqui, um
            # papel listado nos dois dicionarios apareceria duas vezes, e a
            # chave 'visao' nao teria leitor nenhum.
            construtor = None if papel.get("visao") else ABAS_DE_PAPEL.get(chave)
            if construtor is None or chave in self.abas_papel:
                continue
            funcao = getattr(self.painel, papel["comando"])
            aba = construtor(self.painel, self.no, self.avisar, funcao)
            aba.setToolTip(papel.get("descricao", ""))
            self.abas_papel[chave] = aba
            self.abas.addTab(aba, papel.get("rotulo", chave))
            aba.recarrega()

    def _respondeu(self):
        self.pendentes = max(0, self.pendentes - 1)
        if self.pendentes == 0:
            self.botao.setEnabled(True)

    @Slot(object)
    def preenche_rotas(self, dados):
        self._respondeu()
        linhas = dados.get("rotas", [])
        self.rotas.setSortingEnabled(False)
        self.rotas.setRowCount(len(linhas))
        for i, rota in enumerate(linhas):
            self.rotas.setItem(i, 0, celula(rota.get("destino") or ""))
            self.rotas.setItem(i, 1, celula(rota.get("via") or ""))
            self.rotas.setItem(i, 2, celula(rota.get("por") or ""))
            self.rotas.setItem(i, 3, celula(rota.get("origem") or ""))
            self.rotas.setItem(i, 4, celula(rota.get("protocolo") or ""))
            self.rotas.setItem(i, 5, celula(rota.get("escopo") or ""))
            self.rotas.setItem(i, 6, celula(rota.get("metrica") or 0, numero=True))
            self.rotas.setItem(i, 7, celula(rota.get("tabela") or ""))
            # A rota padrao e a que se procura primeiro: em negrito.
            if rota.get("destino") == "default":
                for coluna in range(self.rotas.columnCount()):
                    item = self.rotas.item(i, coluna)
                    if item is not None:
                        fonte = item.font()
                        fonte.setBold(True)
                        item.setFont(fonte)
        self.rotas.setSortingEnabled(True)

        regras = dados.get("regras", [])
        self.regras.setSortingEnabled(False)
        self.regras.setRowCount(len(regras))
        for i, regra in enumerate(regras):
            self.regras.setItem(i, 0, celula(regra.get("tabela") or ""))
            self.regras.setItem(i, 1, celula(regra.get("prioridade") or 0, numero=True))
            self.regras.setItem(i, 2, celula(regra.get("de") or ""))
            self.regras.setItem(i, 3, celula(regra.get("para") or ""))
            self.regras.setItem(i, 4, celula(regra.get("marca") or ""))
            self.regras.setItem(i, 5, celula(regra.get("entrada") or ""))
        self.regras.setSortingEnabled(True)
        self.abas.setTabText(2, T("aba.contagem").format(T("aba.rotas"), len(linhas)))

    @staticmethod
    def _detalhe(interface):
        partes = []
        if interface.get("membros"):
            partes.append("bridge: " + " ".join(interface["membros"]))
        elif interface.get("bridge"):
            partes.append("em " + interface["bridge"])
        sem_fio = interface.get("sem_fio") or {}
        if sem_fio.get("type"):
            texto = sem_fio["type"]
            if sem_fio.get("ssid"):
                texto += f" '{sem_fio['ssid']}'"
            if sem_fio.get("canal"):
                texto += f" canal {sem_fio['canal']}"
            if "clientes" in sem_fio:
                texto += f", {sem_fio['clientes']} cliente(s)"
            partes.append(texto)
        return "; ".join(partes)

    @Slot(object)
    def preenche(self, dados):
        self._respondeu()
        rota = dados.get("rota_padrao") or {}
        self.rota.setText(
            f"Rota padrao: via {rota.get('via')} por {rota.get('por')}" if rota
            else T("texto.sem_rota_padrao"))

        linhas = dados.get("interfaces", [])
        self.interfaces.setSortingEnabled(False)
        self.interfaces.setRowCount(len(linhas))
        for i, interface in enumerate(linhas):
            principal = celula(interface["nome"])
            principal.setData(PAPEL_LINHA, interface)
            self.interfaces.setItem(i, 0, principal)
            self.interfaces.setItem(i, 1, celula(interface.get("tipo", "")))
            self.interfaces.setItem(i, 2, celula(interface.get("estado", "")))
            self.interfaces.setItem(i, 3, celula(interface.get("mac", "")))
            self.interfaces.setItem(i, 4, celula(", ".join(interface.get("enderecos") or [])))
            self.interfaces.setItem(i, 5, celula(self._detalhe(interface)))
            self.interfaces.setItem(i, 6, celula(interface.get("mtu") or 0, numero=True))
            self.interfaces.setItem(i, 7, celula((interface.get("rx_bytes") or 0) // 1_000_000, numero=True))
            self.interfaces.setItem(i, 8, celula((interface.get("tx_bytes") or 0) // 1_000_000, numero=True))
            # Interface fora do ar em cinza: o que importa e o que esta vivo.
            if interface.get("estado") not in ("up", "unknown"):
                for coluna in range(self.interfaces.columnCount()):
                    item = self.interfaces.item(i, coluna)
                    if item is not None:
                        item.setForeground(QBrush(QColor(140, 140, 140)))
        self.interfaces.setSortingEnabled(True)
        self.abas.setTabText(1, T("aba.contagem").format(T("aba.rede"), len(linhas)))
        self.estado.setText(T("texto.em").format(dados.get('quando')))

    @Slot(str)
    def deu_errado(self, mensagem):
        self._respondeu()
        self.estado.setText(T("texto.falhou"))
        self.avisar(f"{self.no}: {mensagem}")


class DesenhoTopologia(QWidget):
    """A vizinhanca do no, desenhada a mao: internet, o no, seus segmentos.

    QPainter puro pelo mesmo motivo do GraficoTrafego: e caixa, linha e
    texto. O desenho e SEMPRE o mesmo eixo -- internet em cima, os aparelhos
    embaixo --, porque a pergunta que ele responde e "por onde isto sai" e
    "quem esta pendurado aqui", nao "como fica bonito".

    A cor de cada aparelho e a LEITURA do cruzamento das fontes, nao um
    enfeite: cinza e quem tem concessao e nao falou, laranja e quem fala sem
    concessao nossa -- o unico caso da tela que aponta um aparelho que
    ninguem cadastrou. Sem legenda, cor vira ruido; ela e desenhada junto.
    """

    COR_VIVO = QColor(60, 110, 180)
    COR_CALADO = QColor(140, 140, 140)
    COR_ESTRANHO = QColor(200, 130, 30)
    COR_SAIDA = QColor(60, 140, 70)

    LARGURA_CHIP = 150
    ALTURA_CHIP = 40
    FOLGA = 10

    def __init__(self):
        super().__init__()
        self.dados = {}
        self.no = ""
        # Tooltip por chip: o desenho cabe pouco texto, e o resto (MAC
        # inteiro, todas as fontes) tem de estar ao alcance sem ir a tabela.
        self.setMouseTracking(True)
        self._chips = []
        self.setMinimumHeight(160)

    def atualiza(self, no, dados):
        self.no, self.dados = no, dados
        # A altura vem do conteudo: com trinta aparelhos o desenho cresce e
        # quem rola e a QScrollArea de fora. Widget de altura fixa mostraria
        # meia rede.
        _, altura = self._planta(max(self.width(), 400), QFontMetrics(self.font()))
        self.setMinimumHeight(max(160, altura))
        self.update()

    def _cor(self, host):
        if host.get("saida"):
            return self.COR_SAIDA
        fontes = set(host.get("fontes") or ())
        if "vizinho" not in fontes:
            return self.COR_CALADO
        if "dhcp" not in fontes:
            return self.COR_ESTRANHO
        return self.COR_VIVO

    def _nome_de(self, host):
        """Como chamar um aparelho na caixa, do mais util para o menos.

        Nome do DHCP primeiro (foi o aparelho que se apresentou), depois o
        fabricante pelo OUI -- 'Amazon Technologies' diz mais do que
        '24:46:c8:...' -- e o MAC como ultimo recurso. Sem a base de OUI
        instalada a do meio simplesmente nao entra, e a tela continua
        inteira.
        """
        marca = nucleo.fabricante(host.get("mac", ""))
        # 'MAC aleatorio' e explicacao, nao nome -- como titulo da caixa ele
        # apagaria o unico identificador que sobrou (o proprio MAC). Vai para
        # o tooltip, onde e leitura e nao etiqueta.
        if marca == nucleo.MAC_ALEATORIO:
            marca = ""
        return host.get("nome") or marca or host.get("mac") or "?"

    def _segmentos(self):
        """Os segmentos a desenhar, em ordem, com os hosts de cada um.

        Um segmento e uma interface com endereco (a loopback nao conta) OU
        uma interface onde ha aparelho. A segunda metade importa: cliente de
        Wi-Fi aparece pelo radio, que e membro da bridge e nao tem endereco
        proprio -- sem ela, ele sumiria do desenho.
        """
        interfaces = {i["nome"]: i for i in self.dados.get("interfaces") or []}
        por_interface = {}
        for host in self.dados.get("hosts") or []:
            # A saida ja e desenhada no tronco, acima do no: repeti-la aqui
            # dentro do segmento dela fazia o mesmo aparelho aparecer duas
            # vezes na mesma arvore.
            if host.get("saida"):
                continue
            por_interface.setdefault(host.get("interface") or "", []).append(host)

        nomes = [nome for nome, i in interfaces.items()
                 if i.get("tipo") != "loopback" and i.get("enderecos")]
        nomes += [nome for nome in por_interface if nome and nome not in nomes]

        segmentos = []
        for nome in nomes:
            interface = interfaces.get(nome, {})
            detalhe = ", ".join(interface.get("enderecos") or [])
            if interface.get("membros"):
                detalhe += f"  [bridge: {' '.join(interface['membros'])}]"
            elif interface.get("bridge"):
                detalhe += f"  [em {interface['bridge']}]"
            segmentos.append((nome, detalhe.strip(), por_interface.get(nome, [])))
        # Aparelho sem interface conhecida nao pode simplesmente sumir.
        if por_interface.get(""):
            segmentos.append((T("texto.sem_segmento"), "", por_interface[""]))
        return segmentos

    def _planta(self, largura, metrica):
        """Onde cada coisa fica, e que traco liga o que. Devolve (itens, altura).

        E uma ARVORE, e nao um grafo qualquer, porque e isso que o dado
        permite afirmar: o no ve a internet acima, os segmentos dele e quem
        esta em cada segmento. Aparelho falando com aparelho na mesma LAN
        NAO passa por ele -- um switch entrega o quadro direto --, entao
        traco entre dois hosts seria invencao. Cada aresta aqui corresponde
        a uma ligacao que alguma das quatro leituras viu.

        Uma so funcao decide o desenho e o paintEvent apenas pinta o que ela
        disse: assim a altura que a barra de rolagem usa nao pode discordar
        do que aparece.
        """
        linha = metrica.height()
        alto_chip = linha * 2 + 10
        itens = []
        meio = largura // 2
        y = self.FOLGA

        itens.append(("legenda", self.FOLGA, y, largura))
        y += linha + self.FOLGA

        def caixa(x, topo, larg, titulo, subtitulo, host, tracejado=False):
            itens.append(("chip", x, topo, larg, alto_chip, titulo, subtitulo,
                          host, tracejado))

        def desce(x, de, ate):
            """Aresta vertical. O tronco da arvore."""
            if ate > de:
                itens.append(("aresta", x, de, x, ate))

        def cotovelo(x1, y1, x2, y2):
            """Aresta em L: desce, anda, desce. Diagonal em diagrama de rede
            confunde com 'ligacao direta'; o angulo reto le como caminho."""
            meio_y = (y1 + y2) // 2
            itens.append(("aresta", x1, y1, x1, meio_y))
            itens.append(("aresta", x1, meio_y, x2, meio_y))
            itens.append(("aresta", x2, meio_y, x2, y2))

        # --- o tronco: internet -> saida -> este no ------------------------
        rota = self.dados.get("rota_padrao") or {}
        larg_internet = 130
        caixa(meio - larg_internet // 2, y, larg_internet, "internet", "",
              None, tracejado=True)
        base_internet = y + alto_chip
        y = base_internet + self.FOLGA * 2

        saida = next((h for h in self.dados.get("hosts") or [] if h.get("saida")), None)
        if saida:
            # O roteador de cima e um host de verdade (esta na tabela ARP),
            # entao entra como caixa clicavel, nao como rotulo solto.
            larg_saida = 190
            desce(meio, base_internet, y)
            caixa(meio - larg_saida // 2, y, larg_saida,
                  self._nome_de(saida) or T("texto.roteador_de_cima"),
                  (saida.get("ips") or ["-"])[0], saida)
            base = y + alto_chip
            y = base + self.FOLGA * 2
        else:
            base = base_internet
            if rota.get("via"):
                itens.append(("nota", meio + 10, y - self.FOLGA,
                              f"via {rota['via']} por {rota.get('por', '?')}"))

        larg_no = min(280, largura - 2 * self.FOLGA)
        x_no = meio - larg_no // 2
        desce(meio, base, y)
        caixa(x_no, y, larg_no, self.no,
              f"{len(self.dados.get('hosts') or [])} na rede", None)
        base_no = y + alto_chip
        y = base_no + self.FOLGA * 2

        # --- os galhos: um por segmento ------------------------------------
        #
        # Os segmentos sao IRMAOS -- todos filhos do no --, e o desenho tem de
        # dizer isso. Empilhados no mesmo eixo central, a linha que desce ate
        # cada um atravessa o anterior, e a arvore le como CORRENTE
        # ('gateway -> enp1s0 -> br0'), que e outra topologia e errada. Por
        # isso trilho indentado, como arvore de diretorio: um prumo vertical
        # a esquerda e cada filho pendurado nele por um traco horizontal.
        segmentos = self._segmentos()
        if not segmentos:
            return itens, y + self.FOLGA

        # O trilho nasce DENTRO da caixa do no, logo abaixo da borda
        # esquerda dela, e desce reto. Antes ele saia do centro, corria ate a
        # margem e so entao descia -- e essa perna horizontal desgrudava os
        # segmentos do dono: olhando a tela nao dava para dizer que enp1s0 e
        # br0 sao do 'gateway' e nao de outra coisa.
        trilho = x_no + 14
        recuo = trilho + 20
        curva = base_no
        ultimo = curva
        for nome, detalhe, hosts in segmentos:
            larg_segmento = min(420, largura - recuo - self.FOLGA)
            centro_vertical = y + alto_chip // 2
            # O traco do trilho ate a caixa: e ele que diz "filho de".
            itens.append(("aresta", trilho, centro_vertical, recuo, centro_vertical))
            ultimo = centro_vertical
            caixa(recuo, y, larg_segmento, nome, detalhe or T("texto.sem_endereco"), None)
            base_segmento = y + alto_chip
            y = base_segmento + self.FOLGA

            if not hosts:
                itens.append(("nota", recuo + 18, y, T("texto.ninguem_visto")))
                y += linha + self.FOLGA * 2
                continue

            # Os hosts sao filhos DESTE segmento: penduram do trilho proprio
            # dele, mais indentado ainda. Assim a profundidade na tela e a
            # profundidade na arvore, e nao sobra duvida de quem pertence a
            # quem.
            trilho_host = recuo + 16
            recuo_host = trilho_host + 18
            cabem_host = max(1, (largura - recuo_host - self.FOLGA)
                             // (self.LARGURA_CHIP + self.FOLGA))
            desce(trilho_host, base_segmento, base_segmento + self.FOLGA)
            ultimo_host = base_segmento
            for fila in range((len(hosts) + cabem_host - 1) // cabem_host):
                da_fila = hosts[fila * cabem_host:(fila + 1) * cabem_host]
                topo = y + self.FOLGA
                centro_fila = topo + alto_chip // 2
                itens.append(("aresta", trilho_host, centro_fila,
                              recuo_host, centro_fila))
                ultimo_host = centro_fila
                for posicao, host in enumerate(da_fila):
                    x = recuo_host + posicao * (self.LARGURA_CHIP + self.FOLGA)
                    if posicao:
                        # Dentro da fileira, um traco liga um ao outro na
                        # altura do meio: sao a mesma ninhada.
                        itens.append(("aresta", x - self.FOLGA, centro_fila,
                                      x, centro_fila))
                    caixa(x, topo, self.LARGURA_CHIP, self._nome_de(host),
                          (host.get("ips") or ["-"])[0], host)
                y = topo + alto_chip
            desce(trilho_host, base_segmento, ultimo_host)
            y += self.FOLGA * 2

        # O prumo so desce ate o ULTIMO filho: passar disso sugere que ainda
        # vem alguma coisa.
        desce(trilho, curva, ultimo)
        return itens, y + self.FOLGA

    def paintEvent(self, _evento):
        pintor = QPainter(self)
        pintor.setRenderHint(QPainter.Antialiasing)
        paleta = self.palette()
        texto_cor = paleta.color(paleta.ColorRole.WindowText)
        fraco = paleta.color(paleta.ColorRole.Mid)
        fonte = pintor.font()
        fonte.setPointSize(max(7, fonte.pointSize() - 1))
        pintor.setFont(fonte)
        metrica = pintor.fontMetrics()
        linha = metrica.height()

        itens, _ = self._planta(self.width(), metrica)
        self._chips = []
        # As arestas primeiro, para as caixas cobrirem as pontas: linha que
        # entra por baixo do retangulo nao deixa cauda a vista.
        pintor.setPen(QPen(fraco, 1))
        for item in itens:
            if item[0] == "aresta":
                pintor.drawLine(item[1], item[2], item[3], item[4])

        for item in itens:
            especie = item[0]
            if especie == "legenda":
                _, x, y, _largura = item
                for cor, rotulo in ((self.COR_VIVO, "falou agora"),
                                    (self.COR_CALADO, T("texto.so_concessao")),
                                    (self.COR_ESTRANHO, T("texto.sem_concessao")),
                                    (self.COR_SAIDA, "saida")):
                    pintor.setPen(QPen(cor, 1))
                    pintor.setBrush(QColor(cor.red(), cor.green(), cor.blue(), 60))
                    pintor.drawRect(x, y + 3, 9, 9)
                    x += 14
                    pintor.setPen(fraco)
                    pintor.drawText(x, y, metrica.horizontalAdvance(rotulo) + 4, linha,
                                    Qt.AlignLeft | Qt.AlignVCenter, rotulo)
                    x += metrica.horizontalAdvance(rotulo) + 16
            elif especie == "nota":
                _, x, y, rotulo = item
                pintor.setPen(fraco)
                pintor.drawText(x, y, self.width() - x, linha,
                                Qt.AlignLeft | Qt.AlignVCenter, rotulo)
            elif especie == "chip":
                _, x, y, largura, altura, titulo, subtitulo, host, tracejado = item
                cor = self._cor(host) if host else fraco
                pintor.setPen(QPen(cor.darker(140), 1,
                                   Qt.DashLine if tracejado else Qt.SolidLine))
                # Duas passadas: o fundo da janela OPACO primeiro, o tom da
                # cor por cima. Com um so, translucido, o tronco da arvore
                # aparece atravessando a caixa por dentro.
                pintor.setBrush(paleta.color(paleta.ColorRole.Window))
                pintor.drawRoundedRect(x, y, largura, altura, 4, 4)
                pintor.setBrush(QColor(cor.red(), cor.green(), cor.blue(), 45))
                pintor.drawRoundedRect(x, y, largura, altura, 4, 4)
                pintor.setPen(texto_cor)
                pintor.drawText(x + 6, y + 3, largura - 12, linha,
                                Qt.AlignLeft | Qt.AlignVCenter,
                                metrica.elidedText(titulo, Qt.ElideRight, largura - 12))
                if subtitulo:
                    pintor.setPen(fraco)
                    pintor.drawText(x + 6, y + altura - linha - 3, largura - 12, linha,
                                    Qt.AlignLeft | Qt.AlignVCenter,
                                    metrica.elidedText(subtitulo, Qt.ElideRight,
                                                       largura - 12))
                if host is not None:
                    self._chips.append((QRect(x, y, largura, altura), host))

    def mouseMoveEvent(self, evento):
        """O chip cabe pouco texto; o resto sai aqui."""
        posicao = evento.position().toPoint()
        for area, host in self._chips:
            if area.contains(posicao):
                fontes = "+".join(host.get("fontes") or []) or "-"
                leitura = nucleo.leitura_das_fontes(host.get("fontes") or [])
                partes = [f"MAC: {host.get("mac") or T("texto.sem_mac")}",
                          f"IP: {', '.join(host.get('ips') or []) or '-'}",
                          T("texto.visto_por").format(fontes)]
                marca = nucleo.fabricante(host.get("mac", ""))
                if marca:
                    partes.insert(1, f"fabricante: {marca}")
                if host.get("nome"):
                    partes.insert(0, host["nome"])
                if leitura:
                    partes.append(leitura)
                if host.get("no"):
                    partes.append(T("texto.endereco_bate").format(host["no"]))
                self.setToolTip("\n".join(partes))
                return
        self.setToolTip("")


CONSTRUTORES = {"maquina": VisaoMaquina, "servicos": VisaoServicos, "dados": VisaoDados, "saida": VisaoSaida}


class AreaMDI(QMdiArea):
    """A area de fundo do MDI, com a marca d'agua do emblema.

    Pintada DEPOIS do fundo e ANTES das subjanelas -- elas sao widgets
    filhos, entao se pintam por cima sozinhas e a marca nunca cobre
    conteudo.

    A imagem escalada e guardada por tamanho: reescalar 1191x670 a cada
    paintEvent, com o MDI redesenhando a cada janela arrastada, e trabalho
    a toa e aparece como arrasto lento.
    """

    def __init__(self):
        super().__init__()
        self.marca = QPixmap(estilo.ARQ_FUNDO)
        self._escalada = None

    def paintEvent(self, evento):
        super().paintEvent(evento)
        if self.marca.isNull() or estilo.OPACIDADE_FUNDO <= 0:
            return
        area = self.viewport().size() if self.viewport() else self.size()
        if self._escalada is None or self._escalada.size() != area:
            # KeepAspectRatioByExpanding: cobre a area inteira e sobra fora
            # da tela, em vez de deixar faixa vazia nas laterais.
            self._escalada = self.marca.scaled(
                area, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
        pintor = QPainter(self.viewport() or self)
        pintor.setOpacity(estilo.OPACIDADE_FUNDO)
        pintor.drawPixmap(
            (area.width() - self._escalada.width()) // 2,
            (area.height() - self._escalada.height()) // 2,
            self._escalada)


# --------------------------------------------------------------- subjanela

class JanelaNo(QWidget):
    """A subjanela de um no: uma aba por visao do tipo dele."""

    def __init__(self, painel, no, tipo, avisar):
        super().__init__()
        self.no = no
        leiaute = QVBoxLayout(self)

        rotulo_tipo = nucleo.TIPOS.get(tipo, {}).get("rotulo", tipo)
        leiaute.addWidget(cabecalho(
            T("texto.no").format(no), T("texto.ghop_agente").format(rotulo_tipo, no)))

        visoes = nucleo.visoes_de(tipo)
        if not visoes:
            leiaute.addWidget(QLabel(
                T("texto.tipo_nao_tem_visao").format(tipo)))
            return

        self.painel, self.avisar = painel, avisar
        self.abas = QTabWidget()
        # Cada visao consulta o agente ao ser mostrada pela primeira vez, e
        # so entao: abrir um no nao dispara todas de uma vez, e trocar de
        # aba nao reconsulta o que ja esta na tela -- para isso ha Atualizar.
        self.carregadas = set()
        self.chaves = []
        for visao in visoes:
            construtor = CONSTRUTORES.get(visao["chave"])
            if construtor and nucleo.comando_existe(visao["comando"]):
                widget = construtor(painel, no, avisar)
            else:
                widget = VisaoIndisponivel(visao)
            self.abas.addTab(widget, visao["rotulo"])
            self.chaves.append(visao["chave"])
        self.abas.currentChanged.connect(self._mostrou)
        leiaute.addWidget(self.abas)

        # Visao que so existe em no que tem o papel (hoje: Roteamento, do
        # ghop-nftables). Vem do agente, entao entra depois -- e no lugar
        # que nucleo.PAPEIS mandar, nao no fim.
        tarefa = Tarefa(painel.papeis, no)
        tarefa.sinais.pronto.connect(self._papeis_chegaram)
        tarefa.sinais.falhou.connect(lambda m: avisar(f"{no}: {m}"))
        QThreadPool.globalInstance().start(tarefa)

    @Slot(object)
    def _papeis_chegaram(self, dados):
        for papel in dados.get("papeis", []):
            chave = papel.get("chave")
            construtor = VISOES_DE_PAPEL.get(chave) if papel.get("visao") else None
            if construtor is None or chave in self.chaves:
                continue
            funcao = getattr(self.painel, papel["comando"])
            widget = construtor(self.painel, self.no, self.avisar, funcao)
            widget.setToolTip(papel.get("descricao", ""))
            # 'antes' e uma lista de candidatos em ordem de preferencia: o no
            # do tipo webserver nao tem 'saida', e sem o segundo candidato
            # ('servico') as visoes de papel iam todas para o fim da fileira,
            # depois da analise -- que e o oposto da ordem pretendida.
            antes = papel.get("antes") or ()
            if isinstance(antes, str):
                antes = (antes,)
            onde = next((self.chaves.index(c) for c in antes if c in self.chaves),
                        self.abas.count())
            self.abas.insertTab(onde, widget, papel.get("rotulo", chave))
            self.chaves.insert(onde, chave)
            # Inserir no meio desloca o que ja tinha carregado.
            self.carregadas = {i + 1 if i >= onde else i for i in self.carregadas}

    def _mostrou(self, indice):
        widget = self.abas.widget(indice)
        if widget is None or indice in self.carregadas:
            return
        if hasattr(widget, "recarrega"):
            self.carregadas.add(indice)
            widget.recarrega()

    def carrega(self):
        self._mostrou(self.abas.currentIndex())


# -------------------------------------------------------------- cadastrar

class DialogoNo(QDialog):
    def __init__(self, pai=None):
        super().__init__(pai)
        self.setWindowTitle(T("janela.cadastrar_no"))
        leiaute = QVBoxLayout(self)
        leiaute.addWidget(cabecalho(
            T("texto.cadastrar_no"), T("texto.uma_maquina_observada_o")))
        formulario = QFormLayout()
        leiaute.addLayout(formulario)

        self.nome = QLineEdit()
        self.nome.setPlaceholderText(T("dica.lojmit"))
        self.endereco = QLineEdit()
        self.endereco.setPlaceholderText(T("dica.192_168_101_1"))
        self.tipo = QComboBox()
        for chave in sorted(nucleo.TIPOS):
            self.tipo.addItem(nucleo.TIPOS[chave]["rotulo"], chave)

        formulario.addRow(T("campo.nome_do_no"), self.nome)
        formulario.addRow(T("campo.endereco"), self.endereco)
        formulario.addRow("Tipo:", self.tipo)

        aviso = QLabel(T("texto.o_cadastro_confere_o"))
        aviso.setStyleSheet("color: palette(mid);")
        formulario.addRow(aviso)

        botoes = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        botoes.accepted.connect(self.accept)
        botoes.rejected.connect(self.reject)
        formulario.addRow(botoes)

    def valores(self):
        return (self.nome.text().strip(), self.endereco.text().strip(),
                self.tipo.currentData())


# ----------------------------------------------------------------- detalhe

class AbaColetado(QWidget):
    """O que o proprio GHop viu. E pouco, e e pouco de proposito.

    O coletor SO sumariza -- contadores, sem registro de evento individual.
    Nao existe historico, nem quem acessou, nem cada vez. Dizer isso na tela
    e melhor que deixar o operador procurando uma aba que nunca vai existir.
    """

    def __init__(self, especie, linha):
        super().__init__()
        leiaute = QVBoxLayout(self)
        # Aberto pelo inventario nao houve leitura de no: o inventario guarda
        # a sua decisao, nao contador. Melhor dizer isso do que mostrar campo
        # em branco e deixar parecer que o numero e zero.
        tem_leitura = "total" in linha
        fatos = QFormLayout()
        if tem_leitura:
            fatos.addRow("Total de pedidos:", QLabel(str(linha.get("total", ""))))
            if especie == "ips":
                fatos.addRow("Porta:", QLabel(str(linha.get("porta", ""))))
            fatos.addRow("Primeiro:", QLabel(str(linha.get("primeiro", ""))))
            fatos.addRow("Ultimo:", QLabel(str(linha.get("ultimo", ""))))
        else:
            sem = QLabel(T("texto.aberto_pelo_inventario_nao"))
            sem.setWordWrap(True)
            fatos.addRow(sem)

        classe = linha.get("classe")
        if classe == "negra":
            estado = (f"<span style='color:#be2828'><b>blacklist</b></span>"
                      f" ({linha.get('regra')})")
        elif classe == "branca":
            estado = f"<span style='color:#888'>whitelist</span> ({linha.get('regra')})"
        else:
            estado = T("texto.ainda_sem_nome")
        fatos.addRow(T("campo.classificacao"), QLabel(estado))
        leiaute.addLayout(fatos)

        aviso = QLabel(
            T("texto.so_contadores") if tem_leitura
            else T("texto.so_contadores_pelo_no"))
        aviso.setWordWrap(True)
        aviso.setStyleSheet("color: palette(mid);")
        leiaute.addWidget(aviso)
        leiaute.addStretch()


class AbaServico(QWidget):
    """Uma consulta a um servico de FORA, com cache e controle de gasto.

    NAO consulta ao abrir, e isso e o ponto. Perguntar e uma acao ATIVA e
    atribuivel: conta ao servidor -- e a quem estiver no caminho -- que
    alguem investiga aquele nome. Abrir uma tela nao pode disparar isso.

    A consulta sai do PAINEL, nunca do agente. Dar ao agente um comando que
    faz pedido de saida o transformaria em proxy da rede observada.

    Servico pago acrescenta uma segunda razao para o cache: credito. No plano
    gratuito do IPQualityScore sao 35 consultas por dia. Aqui o cache deixa de
    ser conveniencia e vira orcamento -- por isso o botao diz o que vai
    gastar, a tela mostra o consumo, e reconsultar pede confirmacao.
    """

    def __init__(self, servico, especie, valor, avisar):
        super().__init__()
        self.servico, self.especie, self.valor = servico, especie, valor
        self.avisar = avisar
        self.definicao = nucleo.SERVICOS[servico]
        self.custa = self.definicao.get("custa", False)
        self.pool = QThreadPool.globalInstance()
        self.bruto = None
        self.mudou_cadastro = False

        leiaute = QVBoxLayout(self)

        linha_topo = QHBoxLayout()
        # O texto do botao ja diz o custo: e a ultima coisa que o operador
        # le antes de gastar, e um "Consultar" mudo esconde justamente isso.
        self.botao = QPushButton(self.texto_do_botao(ja_tem=False))
        self.botao.clicked.connect(lambda: self.pede(forcar=False))
        linha_topo.addWidget(self.botao)
        # So faz sentido depois de haver texto: sem consulta nao ha o que
        # extrair, e um botao habilitado que nao faz nada e promessa falsa.
        self.botao_elementos = QPushButton(T("botao.elementos_para_o_inventario"))
        self.botao_elementos.setEnabled(False)
        self.botao_elementos.setToolTip(
            T("ajuda.lista_os_dominios_e"))
        self.botao_elementos.clicked.connect(self.abre_elementos)
        linha_topo.addWidget(self.botao_elementos)
        linha_topo.addStretch()
        self.estado = QLabel(T("texto.nao_consultado"))
        self.estado.setStyleSheet("color: palette(mid);")
        linha_topo.addWidget(self.estado)
        leiaute.addLayout(linha_topo)

        aviso = QLabel(self.definicao["descricao"].get(especie, ""))
        aviso.setWordWrap(True)
        aviso.setStyleSheet("color: palette(mid);")
        leiaute.addWidget(aviso)

        self.orcamento = QLabel("")
        self.orcamento.setWordWrap(True)
        leiaute.addWidget(self.orcamento)

        self.saida = QPlainTextEdit()
        self.saida.setReadOnly(True)
        fonte = QFont("monospace")
        fonte.setStyleHint(QFont.Monospace)
        self.saida.setFont(fonte)
        leiaute.addWidget(self.saida)

        self.atualiza_orcamento()
        # Se ja foi consultado antes, mostra agora -- sem tocar na rede e sem
        # gastar credito. Ver o que se sabe nao pode custar uma pergunta nova.
        guardado = nucleo.CacheConsultas(servico).obtem(especie, valor)
        if guardado is not None:
            self.mostra_registro(dict(guardado, do_cache=True))
        else:
            self.saida.setPlaceholderText(
                T("dica.clique_em_consultar_para").format(self.definicao['nome']))

    # -- orcamento

    def atualiza_orcamento(self):
        if not self.custa:
            self.orcamento.hide()
            return
        limite = self.definicao.get("limite") or {}
        uso = nucleo.UsoServico(self.servico).resumo()
        dia, mes = uso["dia"], uso["mes"]
        teto_dia, teto_mes = limite.get("dia"), limite.get("mes")
        apertado = teto_dia and dia >= teto_dia * 0.8
        cor = "#be2828" if apertado else "palette(mid)"
        self.orcamento.setStyleSheet(f"color: {cor};")
        self.orcamento.setText(
            T("texto.servico_pago_consumo_contado").format(dia, teto_dia, mes, teto_mes))

    def texto_do_botao(self, ja_tem):
        if not self.custa:
            return T("botao.consultar_de_novo_curto") if ja_tem else T("botao.consultar_curto")
        return (T("botao.consultar_de_novo") if ja_tem
                else T("botao.consultar"))

    # -- consulta

    def pede(self, forcar):
        if self.custa:
            limite = (self.definicao.get("limite") or {}).get("dia")
            uso = nucleo.UsoServico(self.servico).resumo()
            aviso = ""
            if limite and uso["dia"] >= limite:
                aviso = T("msg.atencao_limite").format(uso["dia"], limite)
            resposta = QMessageBox.question(
                self, self.definicao["nome"],
                T("msg.consultar_no_gasta_1_credito").format(self.valor, self.definicao['nome'], uso['dia'], limite, aviso),
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if resposta != QMessageBox.Yes:
                return

        self.botao.setEnabled(False)
        self.estado.setText(T("texto.consultando"))
        tarefa = Tarefa(nucleo.consulta_servico, self.servico, self.especie,
                        self.valor, forcar)
        tarefa.sinais.pronto.connect(self.mostra)
        tarefa.sinais.falhou.connect(self.deu_errado)
        self.pool.start(tarefa)

    @Slot(object)
    def mostra(self, registro):
        self.botao.setEnabled(True)
        self.mostra_registro(registro)
        self.atualiza_orcamento()

    def mostra_registro(self, registro):
        self.bruto = registro.get("bruto")
        self.botao_elementos.setEnabled(True)

        # Depois de haver resposta, consultar passa a ser pergunta nova de
        # proposito: e assim que se descobre que algo mudou -- e, num servico
        # pago, e assim que se gasta.
        self.botao.setText(self.texto_do_botao(ja_tem=True))
        try:
            self.botao.clicked.disconnect()
        except (TypeError, RuntimeError):
            pass
        self.botao.clicked.connect(lambda: self.pede(forcar=True))

        quando = registro.get("consultado_em", "")
        consultado = registro.get("respondeu_por") or self.valor
        if registro.get("do_cache"):
            self.estado.setText(T("texto.do_cache_consultado_em").format(quando))
        else:
            self.estado.setText(T("texto.consultado_agora").format(quando))

        linhas = []
        if registro.get("do_cache"):
            linhas.append(T("texto.guardado_em").format(quando))
            if self.custa:
                linhas.append(T("texto.nenhum_credito"))
            linhas.append("")
        if consultado != self.valor:
            # RDAP responde pelo dominio registrado, nao pelo host. Sem dizer
            # isso, o operador leria os dados do pai achando que sao do filho.
            linhas.append(T("texto.servico_nao_conhece").format(self.valor))
            linhas.append(T("texto.abaixo_resposta").format(consultado))
            linhas.append("")
        for rotulo, valor in registro.get("resumo") or []:
            linhas.append(f"{rotulo:<24} {valor}")
        linhas.append("")
        linhas.append(T("texto.resposta_completa"))
        linhas.append(json.dumps(registro.get("bruto"), ensure_ascii=False, indent=2))
        self.saida.setPlainText("\n".join(linhas))

    def abre_elementos(self):
        """Extrai do TEXTO da resposta, e nao da estrutura de cada servico.

        Cada um devolve um formato diferente; varrer o texto pega nameserver,
        bloco e dominio de contato em todos eles sem um parser por servico.
        """
        texto = self.saida.toPlainText()
        if not texto.strip():
            self.avisar(T("msg.consulte_antes_nao_ha_texto"))
            return
        achados = nucleo.extrai_entidades(texto)
        if not achados["dominios"] and not achados["ips"]:
            self.avisar(T("msg.nao_achei_dominio_nem_ip"))
            return
        dialogo = DialogoElementos(self.valor, achados, self)
        dialogo.exec()
        self.mudou_cadastro = self.mudou_cadastro or dialogo.mudou

    @Slot(str)
    def deu_errado(self, mensagem):
        self.botao.setEnabled(True)
        self.estado.setText(T("texto.falhou"))
        self.saida.setPlainText(mensagem)
        self.atualiza_orcamento()


class DialogoElementos(QDialog):
    """Entidades encontradas no texto de uma consulta whois/RDAP.

    O whois e onde aparecem os vizinhos de um item: os nameservers do
    dominio, o bloco de onde o endereco veio, o dominio do contato de abuso.
    Sao coisas que so existem depois de consultar, e que se perderiam se
    tivessem de ser copiadas na mao.

    A lista e generosa de proposito -- oferecer um candidato a mais custa um
    olhar, esconder um nameserver custa a pista. Nada e adicionado sozinho:
    voce marca o que quer, e as duas respostas (adicionar e dispensar) ficam
    gravadas, como em qualquer decisao de cadastro.
    """

    def __init__(self, origem, achados, pai=None):
        super().__init__(pai)
        self.setWindowTitle(T("janela.elementos_encontrados_em").format(origem))
        self.resize(720, 560)
        self.cadastro = nucleo.Cadastro()
        self.mudou = False
        leiaute = QVBoxLayout(self)
        leiaute.addWidget(cabecalho(
            T("texto.elementos_para_o_inventario"),
            T("texto.extraidos_do_texto_da").format(origem)))

        self.tabela = QTableWidget(0, 4)
        self.tabela.setHorizontalHeaderLabels(["", "Especie", "Valor", "Situacao"])
        self.tabela.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tabela.setSelectionBehavior(QTableWidget.SelectRows)
        self.tabela.setAlternatingRowColors(True)
        self.tabela.verticalHeader().setVisible(False)
        colunas_widget = self.tabela.horizontalHeader()
        colunas_widget.setSectionResizeMode(QHeaderView.ResizeToContents)
        colunas_widget.setSectionResizeMode(2, QHeaderView.Stretch)
        leiaute.addWidget(self.tabela)

        self.linhas = []
        for especie in ("dominios", "ips"):
            for valor in achados.get(especie, []):
                self.linhas.append((especie, valor))
        self.preenche()

        acoes = QHBoxLayout()
        marcar = QPushButton(T("botao.marcar_os_novos"))
        marcar.setToolTip(T("ajuda.marca_so_o_que"))
        marcar.clicked.connect(self.marca_novos)
        acoes.addWidget(marcar)
        acoes.addStretch()
        for rotulo, decisao in ((T("botao.adicionar_marcados"), "cadastrado"),
                                (T("botao.dispensar_marcados"), "dispensado")):
            botao = QPushButton(rotulo)
            botao.clicked.connect(lambda _=False, alvo=decisao: self.decide(alvo))
            acoes.addWidget(botao)
        fechar = QPushButton(T("botao.fechar"))
        fechar.clicked.connect(self.accept)
        acoes.addWidget(fechar)
        leiaute.addLayout(acoes)

    def preenche(self):
        self.tabela.setRowCount(len(self.linhas))
        for i, (especie, valor) in enumerate(self.linhas):
            marca = QTableWidgetItem()
            marca.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            marca.setCheckState(Qt.Unchecked)
            self.tabela.setItem(i, 0, marca)
            self.tabela.setItem(i, 1, QTableWidgetItem(
                "dominio" if especie == "dominios" else "IP"))
            self.tabela.setItem(i, 2, QTableWidgetItem(valor))

            registro = self.cadastro.obtem(especie, valor)
            situacao = registro["decisao"] if registro else "novo"
            item = QTableWidgetItem(situacao)
            if registro:
                item.setForeground(QBrush(QColor(140, 140, 140)))
            self.tabela.setItem(i, 3, item)

    def marca_novos(self):
        for i in range(self.tabela.rowCount()):
            novo = self.tabela.item(i, 3).text() == "novo"
            self.tabela.item(i, 0).setCheckState(
                Qt.Checked if novo else Qt.Unchecked)

    def marcados(self):
        return [self.linhas[i] for i in range(self.tabela.rowCount())
                if self.tabela.item(i, 0).checkState() == Qt.Checked]

    def decide(self, decisao):
        escolhidos = self.marcados()
        if not escolhidos:
            QMessageBox.information(self, "Elementos",
                                    T("msg.nada_marcado_marque_as_linhas"))
            return
        for especie, valor in escolhidos:
            try:
                self.cadastro.registra(especie, valor, decisao)
            except ErroGHop as falha:
                QMessageBox.warning(self, "Elementos", f"{valor}: {falha}")
                continue
            self.mudou = True
        self.preenche()


class AbaCadastro(QWidget):
    """A pergunta "eu ja olhei isto?" -- item a item, no inventario geral."""

    def __init__(self, especie, valor, no, avisar, ao_mudar):
        super().__init__()
        self.especie, self.valor, self.no = especie, valor, no
        self.avisar, self.ao_mudar = avisar, ao_mudar
        self.cadastro = nucleo.Cadastro()

        leiaute = QVBoxLayout(self)
        self.estado = QLabel()
        self.estado.setWordWrap(True)
        leiaute.addWidget(self.estado)

        leiaute.addWidget(QLabel(T("texto.nota")))
        self.nota = QLineEdit()
        self.nota.setPlaceholderText(T("dica.o_que_voce_descobriu"))
        leiaute.addWidget(self.nota)

        acoes = QHBoxLayout()
        botao_add = QPushButton(T("botao.adicionar_ao_inventario"))
        botao_add.clicked.connect(lambda: self.decide("cadastrado"))
        acoes.addWidget(botao_add)
        botao_disp = QPushButton(T("botao.dispensar"))
        botao_disp.setToolTip(
            T("ajuda.grava_que_voce_olhou"))
        botao_disp.clicked.connect(lambda: self.decide("dispensado"))
        acoes.addWidget(botao_disp)
        self.botao_esquece = QPushButton(T("botao.esquecer"))
        self.botao_esquece.setToolTip(T("ajuda.apaga_a_decisao_volta"))
        self.botao_esquece.clicked.connect(self.esquece)
        acoes.addWidget(self.botao_esquece)
        acoes.addStretch()
        leiaute.addLayout(acoes)

        explicacao = QLabel(
            T("texto.o_inventario_e_geral"))
        explicacao.setWordWrap(True)
        explicacao.setStyleSheet("color: palette(mid);")
        leiaute.addWidget(explicacao)
        leiaute.addStretch()
        self.mostra()

    def mostra(self):
        """Estado atual no inventario. Nada aqui e automatico: se nao aparece
        decisao, e porque o operador ainda nao deu nenhuma."""
        try:
            registro = self.cadastro.obtem(self.especie, self.valor)
        except ErroGHop as falha:
            self.estado.setText(str(falha))
            return
        self.botao_esquece.setEnabled(registro is not None)
        if registro is None:
            self.estado.setText(
                T("texto.nao_cadastrado_nada_entra"))
            self.nota.setText("")
            return
        decisao = registro.get("decisao", "?")
        cor = "#2a7d2a" if decisao == "cadastrado" else "#888"
        nos = ", ".join(registro.get("nos") or []) or "-"
        self.estado.setText(
            T("texto.desde_nbsp_nbsp_visto").format(cor, decisao, registro.get('primeiro',''), nos))
        self.nota.setText(registro.get("nota", ""))

    def decide(self, decisao):
        try:
            self.cadastro.registra(self.especie, self.valor, decisao,
                                   self.nota.text().strip(), self.no)
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.ao_mudar()
        self.mostra()

    def esquece(self):
        try:
            self.cadastro.esquece(self.especie, self.valor)
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.ao_mudar()
        self.mostra()


class AbaClassificar(QWidget):
    """A pergunta "isto e esperado ou ruim?" -- regra para as listas."""

    def __init__(self, especie, valor, avisar, ao_mudar, ao_concluir):
        super().__init__()
        self.especie, self.valor = especie, valor
        self.avisar, self.ao_mudar, self.ao_concluir = avisar, ao_mudar, ao_concluir
        self.listas = nucleo.Listas()

        leiaute = QVBoxLayout(self)
        formulario = QFormLayout()
        self.tipo = QComboBox()
        self.tipo.addItems(nucleo.TIPOS_DOMINIO if especie == "dominios"
                           else nucleo.TIPOS_IP)
        self.tipo.currentTextChanged.connect(self.sugere)
        formulario.addRow("Tipo:", self.tipo)
        self.regra = QLineEdit()
        formulario.addRow(T("texto.regra"), self.regra)
        self.nota = QLineEdit()
        self.nota.setPlaceholderText(T("dica.por_que_esta_sendo"))
        formulario.addRow("Nota:", self.nota)
        leiaute.addLayout(formulario)
        self.sugere()

        acoes = QHBoxLayout()
        for rotulo, lista in ((T("botao.para_whitelist"), "branca"),
                              (T("botao.para_blacklist"), "negra")):
            botao = QPushButton(rotulo)
            botao.clicked.connect(lambda _=False, alvo=lista: self.classifica(alvo))
            acoes.addWidget(botao)
        acoes.addStretch()
        leiaute.addLayout(acoes)

        explicacao = QLabel(
            T("texto.regra_vale_para_todos"))
        explicacao.setWordWrap(True)
        explicacao.setStyleSheet("color: palette(mid);")
        leiaute.addWidget(explicacao)
        leiaute.addStretch()

    def sugere(self):
        self.regra.setText(
            nucleo.sugestao_regra(self.especie, self.valor, self.tipo.currentText()))

    def classifica(self, lista):
        regra = self.regra.text().strip()
        if not regra:
            self.avisar(T("msg.a_regra_esta_vazia"))
            return
        try:
            self.listas.adiciona(lista, self.especie, self.tipo.currentText(),
                                 regra, self.nota.text().strip())
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.ao_mudar()
        QMessageBox.information(
            self, "Classificar",
            T("msg.entrou_na_lista_a_classificacao").format(regra, lista))
        self.ao_concluir()


class AbaServicos(QWidget):
    """Consultas a fontes de FORA do GHop, cada uma na sua sub-aba.

    Separadas do resto por natureza, e nao por arrumacao: tudo aqui dentro
    sai para a rede e e atribuivel ao operador, enquanto 'Coletado',
    'Cadastro' e 'Classificar' sao locais e mudos. Ter os servicos num lugar
    so deixa claro onde e que a maquina fala com estranhos.

    Hoje ha um servico (whois/RDAP). O nivel de abas existe para os proximos
    entrarem sem remexer no dialogo.
    """

    def __init__(self, especie, valor, avisar):
        super().__init__()
        leiaute = QVBoxLayout(self)
        leiaute.setContentsMargins(0, 0, 0, 0)

        self.abas = QTabWidget()
        # Uma aba por servico que atende esta especie, lida do registro do
        # nucleo. Acrescentar servico e mexer la, nao aqui.
        self.servicos = {}
        for nome, definicao in nucleo.SERVICOS.items():
            if especie not in definicao["especies"]:
                continue
            aba = AbaServico(nome, especie, valor, avisar)
            self.servicos[nome] = aba
            rotulo = definicao["rotulo"].get(especie, definicao["nome"])
            if definicao.get("custa"):
                rotulo += " ($)"
            self.abas.addTab(aba, rotulo)
        leiaute.addWidget(self.abas)

    def mudou_cadastro(self):
        """Se alguma aba de servico acrescentou entidade ao inventario."""
        return any(aba.mudou_cadastro for aba in self.servicos.values())


class JanelaDetalhe(QDialog):
    """O que se sabe de um dominio ou IP, e o que fazer a respeito.

    Dois niveis de aba. No primeiro, as quatro coisas que se faz com um item:
    ver o que o GHop coletou, decidir se entra no inventario, classificar
    para as listas, e consultar fontes de fora. No segundo, dentro de
    'Servico', um servico por aba.

    A divisao nao e so arrumacao: 'Servico' e o unico lugar que sai para a
    rede. Coletado, Cadastro e Classificar sao locais e nao contam a ninguem
    o que voce esta olhando.
    """

    def __init__(self, especie, linha, no=None, pai=None):
        super().__init__(pai)
        self.especie = especie
        self.linha = linha
        self.no = no
        self.mudou = False

        self.valor = linha["dominio"] if especie == "dominios" else linha["ip"]
        # Nome unico: a especie na frente distingue as duas telas, que sao
        # parecidas por dentro, e a origem diz de onde este item veio.
        especie_nome = T("especie.dominio_singular") if especie == "dominios" else "IP"
        self.setWindowTitle(f"{especie_nome}: {self.valor}")
        self.resize(820, 660)
        leiaute = QVBoxLayout(self)
        origem = T("texto.visto_no_no").format(no) if no else T("texto.aberto_pelo_inventario")
        leiaute.addWidget(cabecalho(f"{especie_nome}: {self.valor}", origem))

        self.abas = QTabWidget()
        self.abas.addTab(AbaColetado(especie, linha), T("aba.coletado"))
        self.aba_cadastro = AbaCadastro(
            especie, self.valor, no, self.avisar, self.marca_mudanca)
        self.abas.addTab(self.aba_cadastro, T("aba.cadastro"))
        self.aba_classificar = AbaClassificar(
            especie, self.valor, self.avisar, self.marca_mudanca, self.accept)
        self.abas.addTab(self.aba_classificar, T("aba.classificar"))
        self.aba_servicos = AbaServicos(especie, self.valor, self.avisar)
        self.abas.addTab(self.aba_servicos, T("aba.servico"))
        leiaute.addWidget(self.abas)

        rodape = QHBoxLayout()
        rodape.addStretch()
        fechar = QPushButton(T("botao.fechar"))
        fechar.clicked.connect(self.accept)
        rodape.addWidget(fechar)
        leiaute.addLayout(rodape)

    def avisar(self, mensagem):
        QMessageBox.warning(self, self.valor, mensagem)

    def marca_mudanca(self):
        self.mudou = True

    def accept(self):
        # Elementos adicionados pela aba de servico tambem contam como
        # mudanca: quem chamou precisa recarregar a lista depois.
        servicos = getattr(self, "aba_servicos", None)
        if servicos is not None and servicos.mudou_cadastro():
            self.mudou = True
        super().accept()


# --------------------------------------------------------------- inventario

class TabelaInventario(QWidget):
    """O inventario de uma especie: tudo o que ja foi decidido.

    Mostra tambem o que foi DISPENSADO, e nao so o que foi cadastrado: a
    decisao de nao adicionar e informacao, e some-la aqui faria o operador
    reabrir a mesma discussao meses depois sem lembrar que ja tinha decidido.
    """

    def __init__(self, cadastro, especie, avisar):
        super().__init__()
        self.cadastro, self.especie, self.avisar = cadastro, especie, avisar
        self.valores = []
        leiaute = QVBoxLayout(self)

        topo = QHBoxLayout()
        topo.addWidget(QLabel(T("texto.filtrar")))
        self.filtro = QLineEdit()
        self.filtro.setPlaceholderText(T("dica.parte_do_valor_ou"))
        self.filtro.textChanged.connect(self.recarrega)
        topo.addWidget(self.filtro)
        self.contagem = QLabel("")
        self.contagem.setStyleSheet("color: palette(mid);")
        topo.addWidget(self.contagem)
        leiaute.addLayout(topo)

        self.tabela = QTableWidget(0, 6)
        self.tabela.setHorizontalHeaderLabels(
            ["Valor", "Decisao", "Nota", "Primeiro", "Ultimo", "Nos"])
        self.tabela.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tabela.setSelectionBehavior(QTableWidget.SelectRows)
        self.tabela.setAlternatingRowColors(True)
        self.tabela.verticalHeader().setVisible(False)
        self.tabela.setSortingEnabled(True)
        colunas_widget = self.tabela.horizontalHeader()
        colunas_widget.setSectionResizeMode(QHeaderView.ResizeToContents)
        colunas_widget.setSectionResizeMode(0, QHeaderView.Stretch)
        colunas_widget.setSectionResizeMode(2, QHeaderView.Stretch)
        # Ordem explicita: sem isto a tabela reordena sozinha ao ser
        # preenchida e a linha sob o cursor muda de significado.
        self.tabela.sortByColumn(0, Qt.AscendingOrder)
        self.tabela.itemSelectionChanged.connect(self.mostra_selecionado)
        self.tabela.itemDoubleClicked.connect(self.abre_detalhe)
        leiaute.addWidget(self.tabela)

        rodape = QHBoxLayout()
        rodape.addWidget(QLabel(T("texto.nota")))
        self.nota = QLineEdit()
        rodape.addWidget(self.nota, 3)
        botao_nota = QPushButton(T("botao.salvar_nota"))
        botao_nota.clicked.connect(self.salva_nota)
        rodape.addWidget(botao_nota)
        botao_esq = QPushButton(T("botao.esquecer"))
        botao_esq.setToolTip(T("ajuda.apaga_a_decisao_volta"))
        botao_esq.clicked.connect(self.esquece)
        rodape.addWidget(botao_esq)
        leiaute.addLayout(rodape)

        self.recarrega()

    def selecionado(self):
        linha = self.tabela.currentRow()
        if linha < 0:
            return None
        item = self.tabela.item(linha, 0)
        return item.text() if item else None

    def recarrega(self):
        try:
            tudo = self.cadastro.tudo()[self.especie]
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        procura = self.filtro.text().strip().lower()
        itens = [
            (valor, registro) for valor, registro in sorted(tudo.items())
            if not procura or procura in valor.lower()
            or procura in (registro.get("nota") or "").lower()
        ]
        self.tabela.setSortingEnabled(False)
        self.tabela.setRowCount(len(itens))
        for i, (valor, registro) in enumerate(itens):
            decisao = registro.get("decisao", "")
            colunas = [valor, decisao, registro.get("nota", ""),
                       registro.get("primeiro", ""), registro.get("ultimo", ""),
                       ", ".join(registro.get("nos") or [])]
            for coluna, texto in enumerate(colunas):
                item = QTableWidgetItem(texto)
                if decisao == "dispensado":
                    item.setForeground(QBrush(QColor(140, 140, 140)))
                self.tabela.setItem(i, coluna, item)
        self.tabela.setSortingEnabled(True)
        self.contagem.setText(T("texto.de").format(len(itens), len(tudo)))

    def mostra_selecionado(self):
        linha = self.tabela.currentRow()
        item = self.tabela.item(linha, 2) if linha >= 0 else None
        self.nota.setText(item.text() if item else "")

    def abre_detalhe(self, item):
        """Duplo clique abre o mesmo dialogo da analise de saida.

        A especie vem desta tabela, entao dominio abre dialogo de dominio e IP
        abre dialogo de IP -- com whois num caso e alocacao de bloco no outro.

        A diferenca e que aqui NAO ha leitura de no: o inventario guarda a sua
        decisao, nao contador. O dialogo monta so com o que existe, e a aba
        'Coletado' diz que os numeros nao vieram desta abertura.
        """
        linha_tabela = item.row()
        celula_valor = self.tabela.item(linha_tabela, 0)
        if celula_valor is None:
            return
        valor = celula_valor.text()
        chave = "dominio" if self.especie == "dominios" else "ip"
        linha = {chave: valor}
        # Classificacao pelas listas continua valendo: e regra, nao depende de
        # ter vindo de uma leitura de no.
        try:
            linha["classe"], linha["regra"] = nucleo.Listas().classifica_valor(
                self.especie, valor)
        except ErroGHop:
            linha["classe"], linha["regra"] = "", ""

        dialogo = JanelaDetalhe(self.especie, linha, None, self)
        dialogo.exec()
        if dialogo.mudou:
            self.recarrega()

    def salva_nota(self):
        valor = self.selecionado()
        if not valor:
            self.avisar(T("msg.escolha_uma_linha"))
            return
        registro = self.cadastro.obtem(self.especie, valor)
        if not registro:
            self.avisar(T("msg.nao_esta_mais_no_cadastro").format(valor))
            return
        try:
            # Mantem a decisao: aqui se edita a nota, nao se muda de ideia.
            self.cadastro.registra(self.especie, valor, registro["decisao"],
                                   self.nota.text().strip())
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.recarrega()

    def esquece(self):
        valor = self.selecionado()
        if not valor:
            self.avisar(T("msg.escolha_uma_linha"))
            return
        try:
            self.cadastro.esquece(self.especie, valor)
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.recarrega()


ROTULO_ESPECIE = {"dominios": T("especie.dominios"), "ips": T("especie.ips")}
# Como a especie aparece no meio de uma frase ("Inventario de ..."): 'IPs'
# nao vira minuscula, e sigla em caixa baixa fica com cara de erro.
ROTULO_NA_FRASE = {"dominios": T("especie.dominios.frase"), "ips": T("especie.ips.frase")}


class PainelInventario(QWidget):
    """O inventario de uma especie: dominios OU IPs.

    Widget, nao dialogo: vive dentro do MDI, ao lado das janelas de no. E o
    que faz sentido para o trabalho -- olhar o resumo de um no e o inventario
    ao mesmo tempo, sem que uma janela modal trave a outra. Dialogo modal so
    para o que e decisao pontual (detalhe, listas).

    Uma especie por janela, escolhida no menu: olhar nome e olhar endereco
    pedem cabeca diferente, e assim as duas ficam lado a lado.

    E o inventario GERAL: nao pertence a no nenhum. A mesma entidade vista em
    duas maquinas e uma linha so -- juntar as visoes e tarefa do painel.
    """

    def __init__(self, especie, avisar):
        super().__init__()
        self.especie = especie
        self.avisar = avisar
        self.cadastro = nucleo.Cadastro()
        leiaute = QVBoxLayout(self)
        leiaute.addWidget(cabecalho(
            T("janela.inventario", especie=ROTULO_NA_FRASE.get(especie, especie)),
            T("texto.geral_uma_entidade_so")))

        explicacao = QLabel(
            T("texto.entidades_que_voce_ja"))
        explicacao.setWordWrap(True)
        explicacao.setStyleSheet("color: palette(mid);")
        leiaute.addWidget(explicacao)

        self.tabela_inventario = TabelaInventario(self.cadastro, especie, avisar)
        leiaute.addWidget(self.tabela_inventario)

    def carrega(self):
        self.tabela_inventario.recarrega()


class PainelTopologiaRede(QWidget):
    """Os aparelhos vistos nas redes dos nos, numa lista so.

    Mora no menu Inventario junto de dominios e IPs, mas tem UMA diferenca
    que a tela precisa dizer, e diz: as outras duas leem `cadastro.json` do
    disco -- decisao sua, sem rede, sem senha --, e esta PERGUNTA aos nos.
    E leitura do que esta la agora, nao inventario guardado. Nada aqui e
    gravado, e nao ha decisao a tomar.

    Uma linha por aparelho e nao por (no, aparelho): quando houver um segundo
    no, o mesmo celular visto nos dois vira uma linha com dois nos, que e a
    unica coisa que esta tela responde e a do no sozinho nao responde. Com um
    no so isso nao existe ainda, entao as colunas de no ficam ESCONDIDAS --
    coluna que repete o mesmo valor em toda linha nao informa, atrapalha.
    """

    def __init__(self, painel, avisar):
        super().__init__()
        self.painel, self.avisar = painel, avisar
        self.pool = QThreadPool.globalInstance()
        leiaute = QVBoxLayout(self)
        leiaute.addWidget(cabecalho(
            T("menu.topologia"),
            T("texto.quem_esta_nas_redes")))

        explicacao = QLabel(
            T("texto.cruzamento_de_quatro_leituras"))
        explicacao.setWordWrap(True)
        explicacao.setStyleSheet("color: palette(mid);")
        leiaute.addWidget(explicacao)

        linha = QHBoxLayout()
        self.botao = QPushButton(T("botao.atualizar"))
        self.botao.clicked.connect(self.carrega)
        linha.addWidget(self.botao)
        self.resumo = QLabel("")
        linha.addWidget(self.resumo)
        linha.addStretch()
        self.estado = QLabel("")
        self.estado.setStyleSheet("color: palette(mid);")
        linha.addWidget(self.estado)
        leiaute.addLayout(linha)

        # Um desenho por no, empilhados: sao redes que nao se tocam, e um
        # traco so entre elas seria invencao. Com um no, e um desenho.
        self.desenhos = QWidget()
        self.pilha = QVBoxLayout(self.desenhos)
        self.pilha.setContentsMargins(0, 0, 0, 0)
        self.rolagem = QScrollArea()
        self.rolagem.setWidget(self.desenhos)
        self.rolagem.setWidgetResizable(True)
        self.rolagem.setFrameShape(QFrame.NoFrame)
        leiaute.addWidget(self.rolagem, 1)


    def _redesenha(self, por_no):
        """Refaz a pilha de desenhos. Nó que sumiu do cadastro sai junto."""
        while self.pilha.count():
            velho = self.pilha.takeAt(0).widget()
            if velho is not None:
                velho.deleteLater()
        for nome, dados in sorted(por_no.items()):
            desenho = DesenhoTopologia()
            desenho.atualiza(nome, dados)
            self.pilha.addWidget(desenho)
        self.pilha.addStretch()

    def carrega(self):
        self.botao.setEnabled(False)
        self.estado.setText(T("texto.perguntando_aos_nos"))
        # Quatro comandos POR NO, em serie: e a chamada mais cara do painel, e
        # por isso ela nunca sai da thread de UI.
        tarefa = Tarefa(self.painel.topologia_geral)
        tarefa.sinais.pronto.connect(self._chegou)
        tarefa.sinais.falhou.connect(self._falhou)
        self.pool.start(tarefa)

    @Slot(object)
    def _chegou(self, resposta):
        linhas, por_no, falhas = resposta
        self._redesenha(por_no)
        self.botao.setEnabled(True)
        self.estado.setText("")
        varios = len({no for linha in linhas for no in linha["nos"]}) > 1
        resumo = f"{len(linhas)} aparelho(s)"
        if varios:
            juntos = sum(1 for linha in linhas if len(linha["nos"]) > 1)
            resumo += T("texto.em_mais_de_um_no").format(juntos)
        if falhas:
            resumo += T("texto.sem_resposta_sufixo") + ", ".join(sorted(falhas))
        self.resumo.setText(resumo)
        for no, erro in sorted(falhas.items()):
            self.avisar(f"{no}: {erro}")

    @Slot(str)
    def _falhou(self, mensagem):
        self.botao.setEnabled(True)
        self.estado.setText(T("texto.falhou"))
        self.avisar(mensagem)


# ------------------------------------------------------------------ listas

class EditorRegras(QWidget):
    """Uma lista (branca ou negra) de uma especie (dominios ou ips).

    Arquivo local, sem rede: nao precisa de thread nem de senha.
    """

    def __init__(self, listas, lista, especie, avisar):
        super().__init__()
        self.listas, self.lista, self.especie = listas, lista, especie
        self.avisar = avisar
        leiaute = QVBoxLayout(self)

        self.tabela = QTableWidget(0, 3)
        self.tabela.setHorizontalHeaderLabels(["Tipo", "Valor", "Nota"])
        self.tabela.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tabela.setSelectionBehavior(QTableWidget.SelectRows)
        self.tabela.setAlternatingRowColors(True)
        self.tabela.verticalHeader().setVisible(False)
        colunas_widget = self.tabela.horizontalHeader()
        colunas_widget.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        colunas_widget.setSectionResizeMode(1, QHeaderView.Stretch)
        colunas_widget.setSectionResizeMode(2, QHeaderView.Stretch)
        leiaute.addWidget(self.tabela)

        entrada = QHBoxLayout()
        self.tipo = QComboBox()
        tipos = (nucleo.TIPOS_DOMINIO if especie == "dominios" else nucleo.TIPOS_IP)
        self.tipo.addItems(tipos)
        self.tipo.setToolTip(
            T("ajuda.sufixo_casa_o_dominio"))
        entrada.addWidget(self.tipo)
        self.valor = QLineEdit()
        self.valor.setPlaceholderText(
            T("dica.exemplo_com_br") if especie == "dominios" else "203.0.113.0/24")
        self.valor.returnPressed.connect(self.adiciona)
        entrada.addWidget(self.valor, 2)
        self.nota = QLineEdit()
        self.nota.setPlaceholderText(T("dica.nota_opcional_por_que"))
        entrada.addWidget(self.nota, 2)
        botao_add = QPushButton(T("botao.acrescentar"))
        botao_add.clicked.connect(self.adiciona)
        entrada.addWidget(botao_add)
        botao_rem = QPushButton(T("botao.remover"))
        botao_rem.clicked.connect(self.remove)
        entrada.addWidget(botao_rem)
        leiaute.addLayout(entrada)

        self.recarrega()

    def recarrega(self):
        try:
            regras = self.listas.regras(self.lista, self.especie)
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.tabela.setRowCount(len(regras))
        for i, regra in enumerate(regras):
            self.tabela.setItem(i, 0, QTableWidgetItem(regra.get("tipo", "")))
            self.tabela.setItem(i, 1, QTableWidgetItem(regra.get("valor", "")))
            self.tabela.setItem(i, 2, QTableWidgetItem(regra.get("nota", "")))

    def adiciona(self):
        valor = self.valor.text().strip()
        if not valor:
            self.avisar(T("msg.informe_o_valor_da_regra"))
            return
        try:
            self.listas.adiciona(self.lista, self.especie,
                                 self.tipo.currentText(), valor,
                                 self.nota.text().strip())
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.valor.clear()
        self.nota.clear()
        self.recarrega()

    def remove(self):
        linha = self.tabela.currentRow()
        if linha < 0:
            self.avisar(T("msg.escolha_uma_regra_na_tabela"))
            return
        try:
            self.listas.remove(self.lista, self.especie, linha)
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.recarrega()


class DialogoListas(QDialog):
    """Branca e negra, dominios e IPs, num lugar so.

    Fecha e o que estiver aberto recarrega: a classificacao acontece na
    leitura, entao mudar uma regra tem de mudar a tela na hora -- inclusive
    para o que ja estava coletado ha dias.
    """

    def __init__(self, pai=None):
        super().__init__(pai)
        self.setWindowTitle(T("janela.listas"))
        self.resize(760, 520)
        self.listas = nucleo.Listas()
        leiaute = QVBoxLayout(self)
        leiaute.addWidget(cabecalho(
            T("texto.listas_do_painel"), T("texto.regras_que_classificam_na")))

        explicacao = QLabel(
            T("texto.tudo_continua_sendo_coletado"))
        explicacao.setWordWrap(True)
        explicacao.setStyleSheet("color: palette(mid);")
        leiaute.addWidget(explicacao)

        abas = QTabWidget()
        for lista, rotulo in (("branca", "Whitelist"), ("negra", "Blacklist")):
            internas = QTabWidget()
            for especie, nome in (("dominios", T("especie.dominios")), ("ips", T("especie.ips"))):
                internas.addTab(
                    EditorRegras(self.listas, lista, especie, self.avisar), nome)
            abas.addTab(internas, rotulo)
        leiaute.addWidget(abas)

        botoes = QDialogButtonBox(QDialogButtonBox.Close)
        botoes.rejected.connect(self.accept)
        leiaute.addWidget(botoes)

    def avisar(self, mensagem):
        QMessageBox.warning(self, T("aba.listas"), mensagem)


# ------------------------------------------------------------------ janela

class Janela(QMainWindow):
    def __init__(self, painel):
        super().__init__()
        self.painel = painel
        self.pool = QThreadPool.globalInstance()
        # Subjanelas do MDI, separadas por natureza: 'abertas' sao nos (e
        # recarregam quando uma regra muda), 'inventarios' sao um por especie.
        self.abertas = {}
        self.inventarios = {}
        self.topologia_rede = {}
        self.setWindowTitle(T("janela.ghop_painel").format(painel.nome))
        self.resize(1100, 700)

        self.mdi = AreaMDI()
        self.mdi.setViewMode(QMdiArea.SubWindowView)
        self.setCentralWidget(self.mdi)

        lateral = QWidget()
        coluna = QVBoxLayout(lateral)
        coluna.setContentsMargins(8, 8, 8, 8)
        titulo = QLabel(T("texto.nos"))
        fonte = titulo.font()
        fonte.setBold(True)
        titulo.setFont(fonte)
        coluna.addWidget(titulo)

        self.lista = QListWidget()
        self.lista.itemActivated.connect(self.abre_item)
        self.lista.setMinimumWidth(230)
        coluna.addWidget(self.lista)

        dica = QLabel(T("texto.duplo_clique_abre_o"))
        dica.setStyleSheet("color: palette(mid);")
        coluna.addWidget(dica)

        linha = QHBoxLayout()
        adicionar = QPushButton(T("botao.adicionar"))
        adicionar.clicked.connect(self.adiciona)
        remover = QPushButton(T("botao.remover"))
        remover.clicked.connect(self.remove)
        linha.addWidget(adicionar)
        linha.addWidget(remover)
        coluna.addLayout(linha)

        doca = QDockWidget(T("texto.nos"), self)
        doca.setWidget(lateral)
        doca.setFeatures(QDockWidget.DockWidgetMovable)
        self.addDockWidget(Qt.LeftDockWidgetArea, doca)

        inventario_menu = self.menuBar().addMenu(T("menu.inventario"))
        for especie, atalho in (("dominios", "Ctrl+D"), ("ips", "Ctrl+I")):
            acao = QAction(ROTULO_ESPECIE[especie], self)
            acao.setShortcut(atalho)
            acao.triggered.connect(
                lambda _=False, alvo=especie: self.abre_inventario(alvo))
            inventario_menu.addAction(acao)
        # Separada das duas de cima porque e de outra natureza: aquelas leem
        # o disco, esta pergunta aos nos.
        inventario_menu.addSeparator()
        acao_topologia = QAction(T("menu.topologia"), self)
        acao_topologia.setShortcut("Ctrl+T")
        acao_topologia.triggered.connect(self.abre_topologia)
        inventario_menu.addAction(acao_topologia)

        listas_menu = self.menuBar().addMenu(T("menu.listas"))
        acao_listas = QAction(T("menu.editar_listas"), self)
        acao_listas.setShortcut("Ctrl+L")
        acao_listas.triggered.connect(self.edita_listas)
        listas_menu.addAction(acao_listas)

        janelas = self.menuBar().addMenu(T("menu.janelas"))
        for rotulo, acao in (("Lado a lado", self.mdi.tileSubWindows),
                             ("Cascata", self.mdi.cascadeSubWindows),
                             ("Fechar todas", self.mdi.closeAllSubWindows)):
            item = QAction(rotulo, self)
            item.triggered.connect(acao)
            janelas.addAction(item)

        self.statusBar().showMessage(f"identidade: {painel.nome}")
        self.recarrega_lista()

    # -- lista

    def subjanela_viva(self, registro, chave):
        """A subjanela ainda existente para esta chave, ou None.

        Nao da para confiar no sinal 'destroyed' para limpar o registro: ele e
        diferido, e entre fechar a janela e o sinal chegar o registro apontaria
        para um objeto C++ ja destruido -- reusar aquilo derruba a aplicacao.
        Perguntar ao MDI quem esta vivo e sempre verdade, agora.

        Compara por identidade de proposito: 'in' e '==' tocam o objeto
        destruido e levantam RuntimeError.
        """
        sub = registro.get(chave)
        if sub is None:
            return None
        for viva in self.mdi.subWindowList():
            if viva is sub:
                return sub
        registro.pop(chave, None)
        return None

    def recarrega_lista(self):
        try:
            nos = self.painel.nos()
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        self.lista.clear()
        for nome in sorted(nos):
            registro = nos[nome]
            tipo = registro.get("tipo", nucleo.TIPO_PADRAO)
            rotulo = nucleo.TIPOS.get(tipo, {}).get("rotulo", tipo)
            item = QListWidgetItem(
                f"{nome}\n{rotulo} - {registro['endereco']}:{registro['porta']}")
            item.setData(PAPEL_NO, nome)
            self.lista.addItem(item)
        if not nos:
            self.statusBar().showMessage(
                T("msg.nenhum_no_cadastrado"), 8000)

    def avisar(self, mensagem):
        self.statusBar().showMessage(mensagem, 10000)
        QMessageBox.warning(self, "GHop", mensagem)

    # -- acoes

    def abre_item(self, item):
        no = item.data(PAPEL_NO)
        sub = self.subjanela_viva(self.abertas, no)
        if sub is not None:
            self.mdi.setActiveSubWindow(sub)
            return
        try:
            tipo = self.painel.tipo_de(no)
        except ErroGHop as falha:
            self.avisar(str(falha))
            return

        conteudo = JanelaNo(self.painel, no, tipo, self.avisar)
        sub = QMdiSubWindow()
        sub.setWidget(conteudo)
        sub.setAttribute(Qt.WA_DeleteOnClose)
        sub.setWindowTitle(no)
        sub.resize(920, 560)
        self.mdi.addSubWindow(sub)
        self.abertas[no] = sub
        sub.show()
        conteudo.carrega()

    def abre_inventario(self, especie):
        """Abre o inventario como subjanela do MDI, uma por especie."""
        sub = self.subjanela_viva(self.inventarios, especie)
        if sub is not None:
            self.mdi.setActiveSubWindow(sub)
            # Ja aberto: pode ter mudado por decisao tomada noutra janela.
            sub.widget().carrega()
            return

        conteudo = PainelInventario(especie, self.avisar)
        sub = QMdiSubWindow()
        sub.setWidget(conteudo)
        sub.setAttribute(Qt.WA_DeleteOnClose)
        sub.setWindowTitle(
            T("janela.inventario", especie=ROTULO_NA_FRASE.get(especie, especie)))
        sub.resize(900, 520)
        self.mdi.addSubWindow(sub)
        self.inventarios[especie] = sub
        sub.show()

    def abre_topologia(self):
        """Abre a topologia da rede como subjanela do MDI. Uma so."""
        sub = self.subjanela_viva(self.topologia_rede, "rede")
        if sub is not None:
            self.mdi.setActiveSubWindow(sub)
            sub.widget().carrega()
            return

        conteudo = PainelTopologiaRede(self.painel, self.avisar)
        sub = QMdiSubWindow()
        sub.setWidget(conteudo)
        sub.setAttribute(Qt.WA_DeleteOnClose)
        sub.setWindowTitle(T("menu.topologia"))
        sub.resize(1000, 520)
        self.mdi.addSubWindow(sub)
        self.topologia_rede["rede"] = sub
        sub.show()
        conteudo.carrega()

    def edita_listas(self):
        DialogoListas(self).exec()
        # A classificacao acontece na leitura: mexer numa regra tem de mudar o
        # que esta na tela agora, inclusive para o que foi coletado ha dias.
        # Sem isto o operador acrescenta regra e nao ve efeito nenhum.
        for no in list(self.abertas):
            sub = self.subjanela_viva(self.abertas, no)
            if sub is not None and sub.widget() is not None:
                sub.widget().carrega()
        self.statusBar().showMessage(T("msg.listas_atualizadas"), 6000)

    def adiciona(self):
        dialogo = DialogoNo(self)
        if dialogo.exec() != QDialog.Accepted:
            return
        nome, endereco, tipo = dialogo.valores()
        if not nome or not endereco:
            self.avisar(T("msg.informe_nome_e_endereco"))
            return
        self.statusBar().showMessage(T("msg.conferindo_quem_atende").format(endereco))
        tarefa = Tarefa(self.painel.adiciona_no, nome, endereco, tipo)
        tarefa.sinais.pronto.connect(lambda _: self.cadastrou(nome))
        tarefa.sinais.falhou.connect(self.avisar)
        self.pool.start(tarefa)

    def cadastrou(self, nome):
        self.statusBar().showMessage(T("msg.no_cadastrado").format(nome), 6000)
        self.recarrega_lista()

    def remove(self):
        item = self.lista.currentItem()
        if item is None:
            self.avisar(T("msg.escolha_um_no_na_lista"))
            return
        no = item.data(PAPEL_NO)
        resposta = QMessageBox.question(
            self, "Remover no",
            T("msg.remover_do_cadastro_o_agente").format(no))
        if resposta != QMessageBox.Yes:
            return
        try:
            self.painel.remove_no(no)
        except ErroGHop as falha:
            self.avisar(str(falha))
            return
        morta = self.subjanela_viva(self.abertas, no)
        if morta is not None:
            morta.close()
            self.abertas.pop(no, None)
        self.recarrega_lista()


DIR_RECURSOS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recursos")
# Tamanhos rendericados do icone.svg. Varios, e nao um so grande, porque quem
# escolhe e o gerenciador de janelas: ele pega o mais proximo do que precisa
# (16 na barra de tarefas, 48 no alt-tab) e uma reducao de 256 para 16 feita na
# hora borra o desenho. Sem isto o painel aparece com o cubo generico do X, que
# e o que o WM mostra para quem nao declarou icone nenhum.
TAMANHOS_ICONE = (16, 24, 32, 48, 64, 128, 256)


def icone_do_painel():
    """O icone do aplicativo, montado dos PNG de recursos/. Pode vir vazio."""
    icone = QIcon()
    for tamanho in TAMANHOS_ICONE:
        caminho = os.path.join(DIR_RECURSOS, "icone-%d.png" % tamanho)
        if os.path.exists(caminho):
            icone.addFile(caminho, QSize(tamanho, tamanho))
    if icone.isNull():
        # Sem PNG, tenta o SVG; sem nada, devolve vazio e o Qt usa o padrao.
        svg = os.path.join(DIR_RECURSOS, "icone.svg")
        if os.path.exists(svg):
            icone = QIcon(svg)
    return icone


def main():
    aplicacao = QApplication(sys.argv)
    aplicacao.setApplicationName("GHop")
    # Antes de qualquer janela: o icone e propriedade da aplicacao, e janela
    # criada antes disto nasce com o icone velho.
    aplicacao.setWindowIcon(icone_do_painel())
    # Antes de qualquer widget existir: paleta trocada depois deixa para tras
    # widget ja criado com a cor antiga. GHOP_TEMA=sistema pula.
    estilo.aplica_tema(aplicacao)

    senha = os.environ.get("GHOP_PAINEL_SENHA")
    nome = os.environ.get("GHOP_PAINEL")
    if senha is None:
        senha, ok = QInputDialog.getText(
            None, "GHop", T("texto.senha_chave_painel"), QLineEdit.Password)
        if not ok:
            return 0
    try:
        painel = Painel(nome_painel=nome, senha=senha)
    except ErroGHop as falha:
        QMessageBox.critical(None, "GHop", str(falha))
        return 1

    def abre_janela():
        janela = Janela(painel)
        # showMaximized() sozinho nao basta: ele pede a maximizacao ao
        # gerenciador de janelas, e o do Qubes nao anuncia
        # _NET_WM_STATE_MAXIMIZED -- o pedido cai no vazio e a janela nasce do
        # tamanho do resize(). Ocupar a area disponivel na mao funciona com WM
        # cooperativo ou sem ele.
        #
        # QUAL monitor e' do Qubes, nao nosso: a janela usa a area da tela em
        # que ela JA esta. Ja houve aqui uma escolha de tela por variavel de
        # ambiente e, depois, pelo ponteiro; as duas eram uma resposta a mais
        # do que a pergunta, e a do gerenciador de janelas ja estava certa.
        janela.setGeometry(janela.screen().availableGeometry())
        janela.showMaximized()
        # A janela e criada aqui dentro, entao alguem tem de segurar a
        # referencia: solta, ela e coletada assim que esta funcao retorna.
        aplicacao.janela_ghop = janela

    # A splash e opcional em dois sentidos: pode ser pulada por variavel de
    # ambiente (script, teste) e pode simplesmente nao estar no disco. Nos
    # dois casos a janela abre direto -- enfeite que falta nao impede o
    # painel de subir.
    if os.environ.get("GHOP_SEM_SPLASH", "").strip():
        abre_janela()
        return aplicacao.exec()
    try:
        from splash import TelaSplash
    except ImportError:
        abre_janela()
        return aplicacao.exec()
    aplicacao.splash_ghop = TelaSplash()
    aplicacao.splash_ghop.concluido.connect(abre_janela)
    aplicacao.splash_ghop.iniciar()
    return aplicacao.exec()


if __name__ == "__main__":
    sys.exit(main())
