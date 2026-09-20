#!/bin/bash
#
# requests.sh - instala o coletor de requisicoes do GHop (subprojeto REQUESTS).
#
# O coletor (ghop-requests.py) le a saida do tcpdump em tempo real na interface
# WAN e sumariza os IPs e dominios requisitados para fora em um banco SQLite
# por dia: /var/ghop/tmp/REQUESTS_DD_MM_YYYY
#
# Nao captura conteudo: apenas endereco de destino e nome consultado no DNS.
#
# Uso interativo:      sudo ./projects/ghop-request/requests.sh
# Uso nao interativo:  sudo WAN_IF=enp1s0 ./projects/ghop-request/requests.sh --sim

set -euo pipefail

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEM_COLETOR="$DIR_SCRIPT/ghop-requests.py"
ORIGEM_SERVICE="$DIR_SCRIPT/../../scripts/service.sh"
DIR_CONFIG=/etc/ghop
ARQ_CONFIG="$DIR_CONFIG/ghop.conf"
ARQ_COLETOR=/usr/local/sbin/ghop-requests.py
ARQ_SERVICO=/etc/systemd/system/ghop-requests.service
DIR_DADOS=/var/ghop/tmp

SEM_PERGUNTA=0
ACAO=instalar
for argumento in "$@"; do
	case "$argumento" in
	--sim) SEM_PERGUNTA=1 ;;
	ligar | desligar | estado | desinstalar | instalar) ACAO="$argumento" ;;
	*)
		echo "Erro: argumento desconhecido '$argumento'." >&2
		echo "      Uso: sudo $0 [instalar|ligar|desligar|desinstalar|estado] [--sim]" >&2
		exit 1
		;;
	esac
done
[ -t 0 ] || SEM_PERGUNTA=1

if [ "$(id -u)" -ne 0 ]; then
	echo "Erro: execute como root (sudo $0)." >&2
	exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
	echo "Erro: apt-get nao encontrado; este script e para Debian." >&2
	exit 1
fi

if [ ! -x "$ORIGEM_SERVICE" ]; then
	echo "Erro: $ORIGEM_SERVICE nao encontrado." >&2
	echo "      Copie o repositorio inteiro para esta maquina, nao so este script." >&2
	exit 1
fi

if [ ! -f "$ORIGEM_COLETOR" ]; then
	echo "Erro: $ORIGEM_COLETOR nao encontrado." >&2
	echo "      Copie o repositorio inteiro para esta maquina, nao so este script." >&2
	exit 1
fi

interfaces() {
	ls /sys/class/net | grep -v '^lo$'
}

# ---- ligar, desligar, desinstalar: o coletor como papel que se gerencia ----
#
# Os BANCOS nunca sao apagados por nenhuma destas acoes. Eles sao a
# observacao acumulada, e e a unica coisa aqui que nao se refaz reinstalando.

acao_estado() {
	echo "ghop-request (coletor)"
	printf '  %-24s %s / %s\n' "ghop-requests.service" \
		"$(systemctl is-active ghop-requests.service 2>/dev/null || true)" \
		"$(systemctl is-enabled ghop-requests.service 2>/dev/null || true)"
	if [ -f "$ARQ_SERVICO" ]; then
		printf '  %-24s %s\n' "interfaces" \
			"$(sed -n 's/^Environment=\(WAN_IF\|LAN_IF\)=/\1=/p' "$ARQ_SERVICO" | tr '\n' ' ')"
	fi
	printf '  %-24s %s\n' "bancos" "$DIR_DADOS ($(ls "$DIR_DADOS" 2>/dev/null | wc -l) arquivo(s))"
	return 0
}

acao_ligar() {
	[ -f "$ARQ_SERVICO" ] ||
		{ echo "Erro: coletor ainda nao instalado aqui. Rode: sudo $0" >&2; exit 1; }
	systemctl daemon-reload
	systemctl enable ghop-requests.service
	systemctl restart ghop-requests.service
	echo "==> coletor ligado"
	acao_estado
}

acao_desligar() {
	systemctl disable --now ghop-requests.service 2>/dev/null || true
	echo "==> coletor desligado"
	echo "    Os bancos ja gravados ficam; o que passar na rede a partir de"
	echo "    agora nao e contado por ninguem."
	acao_estado
}

acao_desinstalar() {
	systemctl disable --now ghop-requests.service 2>/dev/null || true
	rm -f "$ARQ_SERVICO" "$ARQ_COLETOR"
	systemctl daemon-reload
	echo "==> coletor desinstalado"
	echo "    Ficaram os bancos em $DIR_DADOS: sao a observacao acumulada,"
	echo "    e nenhuma reinstalacao os traz de volta."
}

case "$ACAO" in
estado) acao_estado; exit 0 ;;
ligar) acao_ligar; exit 0 ;;
desligar) acao_desligar; exit 0 ;;
desinstalar) acao_desinstalar; exit 0 ;;
esac

# Le uma chave do ghop.conf. Nao usa "source" de proposito: o arquivo define
# USER e GROUP, e carrega-lo sobrescreveria essas variaveis do proprio shell.
valor_config() {
	sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$2" | tail -n1 | tr -d "\"'"
}

perguntar() {
	local texto="$1" padrao="$2" resposta
	if [ "$SEM_PERGUNTA" -eq 1 ]; then
		echo "$padrao"
		return
	fi
	read -r -p "$texto [$padrao]: " resposta </dev/tty
	echo "${resposta:-$padrao}"
}

WAN_SUGERIDA="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
WAN_SUGERIDA="${WAN_SUGERIDA:-$(interfaces | head -n1)}"

if [ "$SEM_PERGUNTA" -eq 0 ]; then
	echo "Interfaces de rede desta maquina:"
	ip -brief addr | grep -v '^lo ' | sed 's/^/  /'
	echo
fi

WAN_IF="$(perguntar "Interface a ser observada (WAN, saida para a internet)" "${WAN_IF:-$WAN_SUGERIDA}")"

# A LAN e onde a origem ainda existe: depois do masquerade todos os clientes
# viram um endereco so. E e onde a pergunta DNS ainda esta inteira: cache,
# DNS cifrado ou VPN no lojmIt apagam o nome antes de ele chegar a WAN.
# Sem LAN o coletor le tudo na WAN e fica cego para essas tres coisas.
#
# A sugestao vem do que os outros papeis JA decidiram, e so no fim chuta a
# primeira interface que sobrar. Isso importa em instalacao remota, sem
# ninguem para conferir a pergunta: chutar por ordem alfabetica poderia
# apontar o coletor para a interface errada, calado.
# '|| true': com uma interface so o grep nao acha nada e, sem isto, o
# pipefail encerraria o script calado. Aqui LAN vazia e um caso valido.
LAN_SUGERIDA=""
if [ -f /etc/ghop/wifi/interfaces ]; then
	LAN_SUGERIDA="$(sed -n 's/^PONTE_IF=//p' /etc/ghop/wifi/interfaces)"
fi
if [ -z "$LAN_SUGERIDA" ] && [ -f /etc/ghop/dhcp/interface ]; then
	LAN_SUGERIDA="$(cat /etc/ghop/dhcp/interface)"
fi
if [ -z "$LAN_SUGERIDA" ] && [ -f /etc/ghop/dns/interface ]; then
	LAN_SUGERIDA="$(cat /etc/ghop/dns/interface)"
fi
if [ -z "$LAN_SUGERIDA" ]; then
	LAN_SUGERIDA="$(interfaces | grep -v "^${WAN_IF}$" | head -n1 || true)"
fi
LAN_IF="$(perguntar "Interface INTERNA (LAN): DNS e IPs monitorados -- vazio le DNS na WAN" "${LAN_IF:-$LAN_SUGERIDA}")"

if [ ! -e "/sys/class/net/$WAN_IF" ]; then
	echo "Erro: interface '$WAN_IF' nao existe nesta maquina." >&2
	echo "      Disponiveis: $(interfaces | tr '\n' ' ')" >&2
	exit 1
fi

if [ -n "$LAN_IF" ] && [ ! -e "/sys/class/net/$LAN_IF" ]; then
	echo "Erro: interface '$LAN_IF' nao existe nesta maquina." >&2
	exit 1
fi

if [ -n "$LAN_IF" ] && [ "$LAN_IF" = "$WAN_IF" ]; then
	echo "Erro: LAN e WAN nao podem ser a mesma interface ($WAN_IF)." >&2
	echo "      Na WAN a origem ja foi mascarada; monitorar ali nao diz quem pediu." >&2
	exit 1
fi

echo
echo "Sera aplicado nesta maquina:"
echo "  interface de saida  : $WAN_IF (conexoes TCP novas${LAN_IF:+; DNS so se nao houver LAN})"
echo "  interface interna   : ${LAN_IF:-(nenhuma; DNS lido na WAN, monitoracao de IP desligada)}"
if [ -n "$LAN_IF" ]; then
echo "                        perguntas DNS na entrada, IPs monitorados"
fi
echo "  bancos diarios      : $DIR_DADOS/REQUESTS_DD_MM_YYYY"
echo "  registra            : IP de destino e dominio consultado, apenas somados"
echo "  monitorados         : evento a evento, SO para os IPs escolhidos no painel"
echo "  nao registra        : nenhum conteudo de pacote"
echo "  pacotes             : os do papel 'agente' (ver scripts/service.sh)"
echo "  configuracao        : $ARQ_CONFIG (USER/GROUP dos servicos)"
echo "  arquivos            : $ARQ_COLETOR"
echo "                        $ARQ_SERVICO"
echo
echo "O coletor fica rodando permanentemente (ghop-requests.service)."

if [ "$SEM_PERGUNTA" -eq 0 ]; then
	read -r -p "Confirma? [s/N]: " confirmacao </dev/tty
	case "$confirmacao" in
	s | S | sim | SIM) ;;
	*)
		echo "Cancelado."
		exit 0
		;;
	esac
fi

echo
"$ORIGEM_SERVICE" agente

echo "==> Lendo $ARQ_CONFIG"
GHOP_USER="$(valor_config USER "$ARQ_CONFIG")"
GHOP_GROUP="$(valor_config GROUP "$ARQ_CONFIG")"
if [ -z "$GHOP_USER" ] || [ -z "$GHOP_GROUP" ]; then
	echo "Erro: USER ou GROUP ausentes em $ARQ_CONFIG." >&2
	exit 1
fi
if ! id "$GHOP_USER" >/dev/null 2>&1; then
	echo "Erro: usuario '$GHOP_USER' de $ARQ_CONFIG nao existe nesta maquina." >&2
	exit 1
fi
echo "    servicos rodarao como $GHOP_USER:$GHOP_GROUP"

echo "==> Criando $DIR_DADOS"
mkdir -p "$DIR_DADOS"
chmod 750 "$DIR_DADOS"

echo "==> Instalando coletor em $ARQ_COLETOR"
install -m 750 "$ORIGEM_COLETOR" "$ARQ_COLETOR"

echo "==> Escrevendo servico em $ARQ_SERVICO"
cat > "$ARQ_SERVICO" <<SERVICO
[Unit]
Description=GHop - coleta de IPs e dominios requisitados para a WAN
After=network.target

[Service]
Type=simple
User=$GHOP_USER
Group=$GHOP_GROUP
Environment=WAN_IF=$WAN_IF
Environment=LAN_IF=$LAN_IF
Environment=GHOP_DIR=$DIR_DADOS
Environment=GHOP_MONITORADOS=/var/ghop/monitorados.json
ExecStart=$ARQ_COLETOR
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICO

echo "==> Ativando ghop-requests.service"
systemctl daemon-reload
systemctl enable ghop-requests.service
systemctl restart ghop-requests.service

BANCO_HOJE="$DIR_DADOS/REQUESTS_$(date +%d_%m_%Y)"

echo
echo "==> Concluido"
printf 'interface WAN  %s\n' "$WAN_IF"
printf 'interface LAN  %s\n' "${LAN_IF:-(desligada)}"
printf 'servico        %s\n' "$(systemctl is-active ghop-requests.service)"
printf 'banco de hoje  %s\n' "$BANCO_HOJE"
echo
echo "Para consultar:"
echo "  sqlite3 $BANCO_HOJE 'SELECT dominio,total,ultimo FROM dominios ORDER BY total DESC LIMIT 20;'"
echo "  sqlite3 $BANCO_HOJE 'SELECT ip,porta,total,ultimo FROM ips ORDER BY total DESC LIMIT 20;'"
