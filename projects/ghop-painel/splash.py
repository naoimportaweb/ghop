#!/usr/bin/env python3
"""Splash de abertura do painel: o simbolo klingon e cinco segundos de frases.

Casca pura. Nao importa nucleo, nao le cadastro, nao toca em chave nenhuma --
se este arquivo sumir, o painel abre igual (gui.main o trata como opcional).

A barra mede o TEMPO QUE FALTA para a splash sair, e nada mais. Nao ha passo
de carga a medir aqui: abrir a chave do painel e ler o cadastro sao coisas de
milissegundos, e acontecem depois. Barra que finge medir progresso e mentira
de tela -- e neste projeto numero certo com rotulo errado ja foi decidido ser
pior do que numero nenhum. Por isso o rotulo diz 'abrindo', nao '37%'.

As frases sao tlhIngan Hol de verdade (Okrand) e ficam SO em klingon na tela.
A splash e zueira assumida, e zueira explicada perde a graca -- quem quiser
saber o que esta escrito procura, que e metade da piada. A traducao continua
no codigo, ao lado de cada frase, porque ela nao e para o usuario: e para quem
mexer aqui nao trocar uma frase por outra sem saber o que passou a dizer.

O resto do painel NAO e assim: rotulo de tela sai do recurso (textos.py) e o
padrao e ingles. A splash e a excecao, e e excecao por ser piada.

Variavel de ambiente:
  GHOP_SEM_SPLASH  qualquer valor nao vazio pula a splash (script e teste)
"""

import os
import random

from PySide6.QtCore import QElapsedTimer, Qt, QTimer, Signal
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPixmap
from PySide6.QtWidgets import QLabel, QProgressBar, QVBoxLayout, QWidget

from estilo import COR_FUNDO, COR_REALCE, COR_TEXTO

ARQ_IMAGEM = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "recursos", "splash.png")
DURACAO_MS = 5000
# Uma frase por vez, trocando ao longo dos cinco segundos.
TROCA_MS = 900

# As cores vem do estilo.py, que e o mesmo tema da janela: a abertura e o
# aplicativo nao podem divergir porque alguem mexeu numa e esqueceu a outra --
# e o vermelho do proprio simbolo, nao o verde de terminal, porque a imagem
# manda na paleta.

# tlhIngan Hol atestado (The Klingon Dictionary, Marc Okrand). O segundo item
# de cada par e a glosa, que NAO vai para a tela: fica aqui para quem mexer no
# arquivo saber o que a frase diz. Nao ha frase inventada de proposito --
# enfeite pode ser bobo, nao falso.
FRASES = [
    ("nuqneH", "o que voce quer?"),
    ("tlhIngan maH!", "somos klingon!"),
    ("Heghlu'meH QaQ jajvam", "hoje e um bom dia para morrer"),
    ("batlh bIHeghjaj", "que voce morra com honra"),
    ("lojmIt yIpoSmoH", "abra a porta"),
    ("bIjatlh 'e' yImev", "pare de falar"),
    ("Hab SoSlI' Quch!", "a testa da sua mae e lisa!"),
    ("majQa'", "bem feito"),
    ("tlhIngan Hol Dajatlh'a'?", "voce fala klingon?"),
    ("qaStaH nuq jay'?", "que diabos esta acontecendo?"),
]
# A ultima e sempre esta: e como se despede quem conseguiu.
DESPEDIDA = ("Qapla'", "sucesso")


class TelaSplash(QWidget):
    """Splash sem moldura: o simbolo, o nome, uma frase e a barra do tempo."""

    concluido = Signal()

    def __init__(self, largura=420):
        super().__init__(None, Qt.SplashScreen | Qt.FramelessWindowHint)
        self.fundo = QPixmap(ARQ_IMAGEM)
        if not self.fundo.isNull():
            self.fundo = self.fundo.scaledToWidth(largura, Qt.SmoothTransformation)
            altura = self.fundo.height() + 130
        else:
            # Sem a imagem a splash continua existindo, so mais sobria: o
            # arquivo e enfeite, e enfeite que falta nao pode impedir o
            # painel de abrir.
            altura = 260
        self.setFixedSize(largura, altura)

        leiaute = QVBoxLayout(self)
        leiaute.setContentsMargins(24, 24, 24, 20)
        leiaute.addStretch(1)

        titulo = QLabel("GHop")
        fonte = QFont("monospace")
        fonte.setStyleHint(QFont.Monospace)
        fonte.setPointSize(26)
        fonte.setBold(True)
        titulo.setFont(fonte)
        titulo.setStyleSheet(f"color:{COR_TEXTO}; background:transparent;")
        titulo.setAlignment(Qt.AlignHCenter)
        leiaute.addWidget(titulo)

        assinatura = QLabel("ghop - \"mao\" em tlhIngan Hol")
        fonte_assinatura = QFont("monospace")
        fonte_assinatura.setStyleHint(QFont.Monospace)
        fonte_assinatura.setPointSize(9)
        assinatura.setFont(fonte_assinatura)
        assinatura.setStyleSheet(f"color:{COR_REALCE}; background:transparent;")
        assinatura.setAlignment(Qt.AlignHCenter)
        leiaute.addWidget(assinatura)

        self.klingon = QLabel("")
        fonte_klingon = QFont("monospace")
        fonte_klingon.setStyleHint(QFont.Monospace)
        fonte_klingon.setPointSize(13)
        fonte_klingon.setBold(True)
        self.klingon.setFont(fonte_klingon)
        self.klingon.setStyleSheet(f"color:{COR_TEXTO}; background:transparent;")
        self.klingon.setAlignment(Qt.AlignHCenter)
        leiaute.addWidget(self.klingon)

        self.barra = QProgressBar()
        self.barra.setRange(0, 100)
        self.barra.setFixedHeight(14)
        self.barra.setFormat("abrindo")
        self.barra.setStyleSheet(
            "QProgressBar { background-color: rgba(0,0,0,180);"
            f" border: 1px solid {COR_REALCE}; color: {COR_TEXTO};"
            " text-align: center; font-family: monospace; font-size: 9px; }"
            f" QProgressBar::chunk {{ background-color: {COR_REALCE}; }}")
        leiaute.addWidget(self.barra)

        # A ordem das frases e sorteada uma vez, e nao a cada troca: sorteando
        # a cada tique a mesma frase repetia em seguida.
        self.fila = random.sample(FRASES, len(FRASES))
        self.proxima = 0
        self._troca()

        self.relogio = QElapsedTimer()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tique)
        self.trocador = QTimer(self)
        self.trocador.timeout.connect(self._troca)

    def paintEvent(self, _evento):
        pintor = QPainter(self)
        pintor.fillRect(self.rect(), QColor(COR_FUNDO))
        if not self.fundo.isNull():
            pintor.drawPixmap((self.width() - self.fundo.width()) // 2, 10, self.fundo)
        # O bloco de texto fica sobre a parte de baixo da imagem; sem esta
        # faixa escura o texto claro cai em cima do vermelho e some.
        faixa = 150
        gradiente = QLinearGradient(0, self.height() - faixa, 0, self.height())
        fundo = QColor(COR_FUNDO)
        for parada, opacidade in ((0.0, 0), (0.35, 210), (1.0, 245)):
            gradiente.setColorAt(parada, QColor(fundo.red(), fundo.green(),
                                                fundo.blue(), opacidade))
        pintor.fillRect(0, self.height() - faixa, self.width(), faixa, gradiente)
        pintor.setPen(QColor(COR_REALCE))
        pintor.drawRect(0, 0, self.width() - 1, self.height() - 1)

    def _troca(self):
        frase, _glosa = self.fila[self.proxima % len(self.fila)]
        self.proxima += 1
        self.klingon.setText(frase)

    def iniciar(self):
        self.show()
        self.relogio.start()
        self.timer.start(50)
        self.trocador.start(TROCA_MS)

    def _tique(self):
        decorrido = self.relogio.elapsed()
        self.barra.setValue(min(100, int(100 * decorrido / DURACAO_MS)))
        if decorrido >= DURACAO_MS:
            self.timer.stop()
            self.trocador.stop()
            self.barra.setValue(100)
            self.klingon.setText(DESPEDIDA[0])
            # Um respiro para o 'Qapla'' ser lido antes de a janela abrir.
            QTimer.singleShot(400, self._fecha)

    def _fecha(self):
        self.concluido.emit()
        self.close()
