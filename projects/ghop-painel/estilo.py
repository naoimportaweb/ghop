#!/usr/bin/env python3
"""Tema da janela do GHop: o mesmo da splash, aplicado ao aplicativo inteiro.

As cores nascem do emblema da splash -- fundo quase preto e o vermelho do
simbolo -- e moram AQUI, num lugar so. A splash importa daqui em vez de
repetir os literais: duas telas com a mesma identidade nao podem divergir
porque alguem mexeu numa e esqueceu a outra. E a mesma razao de ORIGENS_PAPEL
viver no nucleo.

Tema por PALETA, nao por folha de estilo gigante. A diferenca importa: as 28
referencias a 'palette(...)' espalhadas pelo gui.py e as cores que o
QPainter le da paleta (o grafico de trafego, o desenho da topologia, a
cascata do firewall) passam a acompanhar o tema sozinhas. Folha de estilo
so para o que a paleta nao alcanca -- borda de aba, cabecalho de tabela,
barra de progresso.

O que NAO e tocado sao as cores SEMANTICAS do gui.py (accept verde, drop
vermelho, RX azul, TX laranja, o laranja do 'fala sem concessao nossa'):
elas nao sao decoracao, sao o significado da linha, e foram escolhidas para
ler em fundo claro ou escuro.

Variavel de ambiente:
  GHOP_TEMA=sistema   usa o tema do desktop, sem aplicar nada disto
"""

import os

from PySide6.QtGui import QColor, QFont, QPalette

# As quatro da splash. Mudar aqui muda a janela e a abertura juntas.
COR_FUNDO = "#0c0c0c"
COR_CAMPO = "#141414"
COR_ALTERNADA = "#1a1a1a"
COR_TEXTO = "#e8e8e8"
COR_APAGADO = "#9a9a9a"
COR_REALCE = "#d92121"
COR_BORDA = "#2a2a2a"

# A barra de titulo da subjanela do MDI fica com o vermelho VIVO do realce, e
# nao com um escurecido: tentou-se, e nao sai barato. A paleta sozinha nao a
# alcanca (com folha de estilo ativa quem desenha e o QStyleSheetStyle, que a
# ignora), e a regra 'QMdiSubWindow::title' que funciona faz o Qt desenhar a
# decoracao inteira em modo folha de estilo -- e com isso somem os botoes de
# minimizar, maximizar e FECHAR. Barra discreta nao paga o botao de fechar.

# A marca d'agua do fundo do MDI. Desenhada COBRINDO a area (escala mantendo
# proporcao, corte central) e nao centralizada: centralizada, a imagem tem
# fundo proprio e viraria um retangulo com borda no meio da tela, que le como
# painel e nao como marca d'agua.
#
# A opacidade e o unico parafuso, e o limite dela nao e gosto: acima de ~0.25
# ela comeca a disputar contraste com o texto das janelas, e o fundo do MDI
# existe para ser fundo. Zero desliga sem tirar o arquivo.
ARQ_FUNDO = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "recursos", "fundo.jpg")
OPACIDADE_FUNDO = 0.32

# A splash e monoespacada, e a janela do GHop e quase toda endereco, MAC e
# porta -- coluna alinhada ajuda a ler. Prosa em mono cansa mais; se um dia
# incomodar, e esta linha.
FONTE_MONO = True


def _paleta():
    paleta = QPalette()
    fundo, campo = QColor(COR_FUNDO), QColor(COR_CAMPO)
    texto, apagado = QColor(COR_TEXTO), QColor(COR_APAGADO)
    realce = QColor(COR_REALCE)

    paleta.setColor(QPalette.Window, fundo)
    paleta.setColor(QPalette.WindowText, texto)
    paleta.setColor(QPalette.Base, campo)
    paleta.setColor(QPalette.AlternateBase, QColor(COR_ALTERNADA))
    paleta.setColor(QPalette.Text, texto)
    paleta.setColor(QPalette.Button, QColor(COR_ALTERNADA))
    paleta.setColor(QPalette.ButtonText, texto)
    paleta.setColor(QPalette.BrightText, QColor("#ffffff"))
    paleta.setColor(QPalette.ToolTipBase, campo)
    paleta.setColor(QPalette.ToolTipText, texto)
    paleta.setColor(QPalette.Link, realce)
    paleta.setColor(QPalette.Highlight, realce)
    paleta.setColor(QPalette.HighlightedText, QColor("#f5f5f5"))
    # 'Mid' e o que o gui.py usa para texto apagado ("color: palette(mid)") e
    # o que os QPainter leem como cor de grade. Sem ele o texto secundario
    # some no fundo escuro.
    paleta.setColor(QPalette.Mid, apagado)
    paleta.setColor(QPalette.Dark, QColor(COR_BORDA))
    paleta.setColor(QPalette.Shadow, QColor("#000000"))

    # Desabilitado tem de LER como desabilitado sem sumir: botao que
    # desaparece parece avaria, e a tela 'Servicos' desliga botao de
    # proposito o tempo todo (Desinstalar no que nao foi o GHop que instalou).
    for papel, cor in ((QPalette.WindowText, "#6a6a6a"),
                       (QPalette.Text, "#6a6a6a"),
                       (QPalette.ButtonText, "#6a6a6a"),
                       (QPalette.Highlight, "#3a3a3a")):
        paleta.setColor(QPalette.Disabled, papel, QColor(cor))
    return paleta


FOLHA = f"""
QWidget {{ background: {COR_FUNDO}; color: {COR_TEXTO}; }}
QMdiArea {{ background: #080808; }}

QTableWidget, QTableView, QPlainTextEdit, QLineEdit, QListWidget {{
    background: {COR_CAMPO};
    alternate-background-color: {COR_ALTERNADA};
    border: 1px solid {COR_BORDA};
    gridline-color: {COR_BORDA};
    selection-background-color: {COR_REALCE};
    selection-color: #f5f5f5;
}}
QHeaderView::section {{
    background: {COR_ALTERNADA};
    color: {COR_APAGADO};
    border: 0;
    border-bottom: 1px solid {COR_REALCE};
    padding: 4px 6px;
}}

QPushButton {{
    background: {COR_ALTERNADA};
    border: 1px solid {COR_BORDA};
    padding: 4px 12px;
}}
QPushButton:hover {{ border-color: {COR_REALCE}; }}
QPushButton:pressed {{ background: {COR_REALCE}; color: #f5f5f5; }}
QPushButton:disabled {{ color: #6a6a6a; border-color: #1f1f1f; }}

QTabBar::tab {{
    background: transparent;
    color: {COR_APAGADO};
    padding: 5px 12px;
    border-bottom: 2px solid transparent;
}}
/* A aba ativa e a unica coisa vermelha em repouso: e o realce dizendo onde
   voce esta, nao enfeite espalhado. */
QTabBar::tab:selected {{ color: {COR_TEXTO}; border-bottom-color: {COR_REALCE}; }}
QTabWidget::pane {{ border: 1px solid {COR_BORDA}; }}

QMenuBar, QMenu {{ background: {COR_FUNDO}; color: {COR_TEXTO}; }}
QMenuBar::item:selected, QMenu::item:selected {{ background: {COR_REALCE}; color: #f5f5f5; }}
QStatusBar {{ color: {COR_APAGADO}; border-top: 1px solid {COR_BORDA}; }}
QDockWidget::title {{ background: {COR_ALTERNADA}; padding: 5px; }}

QProgressBar {{
    background: {COR_CAMPO};
    border: 1px solid {COR_REALCE};
    text-align: center;
}}
QProgressBar::chunk {{ background: {COR_REALCE}; }}

QScrollBar:vertical, QScrollBar:horizontal {{ background: {COR_FUNDO}; }}
QScrollBar::handle {{ background: #333333; }}
QScrollBar::handle:hover {{ background: {COR_REALCE}; }}
QCheckBox::indicator:checked {{ background: {COR_REALCE}; }}
"""


def aplica_tema(aplicacao):
    """Poe o tema da splash no aplicativo. Devolve se aplicou.

    Sai sem fazer nada com GHOP_TEMA=sistema: quem prefere o tema do desktop
    (ou depende de contraste alto do sistema) nao fica preso a esta escolha.
    """
    if os.environ.get("GHOP_TEMA", "").strip().lower() == "sistema":
        return False
    aplicacao.setStyle("Fusion")
    aplicacao.setPalette(_paleta())
    aplicacao.setStyleSheet(FOLHA)
    if FONTE_MONO:
        fonte = QFont("monospace")
        fonte.setStyleHint(QFont.Monospace)
        fonte.setPointSize(aplicacao.font().pointSize())
        aplicacao.setFont(fonte)
    return True
