#!/bin/bash
#
# dhcp.sh - instala e liga o ghop-dhcp nesta maquina: o servidor DHCP da LAN.
#
# Adota o isc-dhcp-server e passa a gerar o dhcpd.conf a partir do que se
# responde aqui. Antes deste papel o DHCP do lojmIt era instalado a mao,
# fora do GHop, e por isso ninguem sabia o que ele entregava sem ir ler o
# arquivo -- que e justamente o que o painel precisa mostrar.
#
# Entrega tres coisas ao cliente: endereco, roteador e resolvedor. O
# resolvedor e a decisao que importa: com o ghop-dns ligado, e esta maquina;
# sem ele, e o de cima. Trocar de um para o outro e o que faz ligar e
# desligar o ghop-dns valer para a LAN inteira.
#
# Este papel LIGA E DESLIGA sem tocar no resto. 'desligar' para o servico e
# fecha a porta; a configuracao e as concessoes ficam para o proximo 'ligar'.
# ATENCAO: com ele desligado ninguem novo recebe endereco na LAN.
#
# Uso interativo:      sudo ./projects/ghop-dhcp/dhcp.sh
# Uso nao interativo:  sudo LAN_IF=br0 ./projects/ghop-dhcp/dhcp.sh --sim
# Depois:              sudo ./projects/ghop-dhcp/dhcp.sh desligar | ligar | estado

set -euo pipefail
trap 'echo "Erro: $0 parou na linha $LINENO (comando: $BASH_COMMAND)" >&2' ERR

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEM_SERVICE="$DIR_SCRIPT/../../scripts/service.sh"
DIR_CONFIG=/etc/ghop
DIR_DHCP="$DIR_CONFIG/dhcp"
ARQ_ESTADO="$DIR_DHCP/interface"
DIR_NFT="$DIR_CONFIG/nft.d"
ARQ_NFT="$DIR_NFT/dhcp.sh"
ARQ_CONF=/etc/dhcp/dhcpd.conf
ARQ_DEFAULT=/etc/default/isc-dhcp-server
ARQ_LEASES=/var/lib/dhcp/dhcpd.leases
ARQ_WIFI=/etc/ghop/wifi/interfaces
# Quem aplica o ruleset e o papel nftables; o caminho antigo fica como
# reserva para maquina que ainda nao migrou.
REGRAS_FIREWALL=/usr/local/sbin/ghop-nftables.sh
UNIDADE_FIREWALL=ghop-nftables.service
# O script do lojmIt ANTIGO, de quando o firewall morava nele. O nome
# do arquivo continua 'gateway.sh' porque e assim que ele esta na
# maquina que ainda nao migrou -- procurar 'lojmIt.sh' aqui seria nao
# achar nada e perder o caminho de reserva.
REGRAS_LOJMIT_ANTIGO=/usr/local/sbin/gateway.sh
UNIDADE=isc-dhcp-server.service

erro() {
	echo "Erro: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || erro "execute como root (sudo $0 $*)."
command -v apt-get >/dev/null 2>&1 || erro "apt-get nao encontrado; este script e para Debian."
[ -x "$ORIGEM_SERVICE" ] || erro "$ORIGEM_SERVICE nao encontrado.
      Copie o repositorio inteiro para esta maquina, nao so este script."

SEM_PERGUNTA=0
ACAO=instalar
for argumento in "$@"; do
	case "$argumento" in
	--sim) SEM_PERGUNTA=1 ;;
	ligar | desligar | estado | desinstalar | instalar) ACAO="$argumento" ;;
	*) erro "argumento desconhecido '$argumento'. Uso: $0 [instalar|ligar|desligar|desinstalar|estado] [--sim]" ;;
	esac
done
[ -t 0 ] || SEM_PERGUNTA=1

interfaces() {
	ls /sys/class/net | grep -v '^lo$'
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

# Rede e mascara a partir do endereco da interface, sem depender de ipcalc.
rede_de() {
	python3 - "$1" <<'PYTHON'
import ipaddress, sys
rede = ipaddress.ip_interface(sys.argv[1]).network
print(rede.network_address, rede.netmask, rede.broadcast_address)
PYTHON
}

# O ghop-dns manda no que se entrega como resolvedor: e ele ou o de cima.
resolvedor_sugerido() {
	local lan_ip="$1"
	if systemctl is-active --quiet dnscrypt-proxy.service 2>/dev/null; then
		echo "$lan_ip"
		return
	fi
	sed -n 's/^nameserver[[:space:]]\+\([0-9.]\+\).*/\1/p' /etc/resolv.conf |
		grep -v '^127\.' | head -n1 || true
}

escreve_regra_firewall() {
	local lan="$1"
	mkdir -p "$DIR_NFT"
	cat > "$ARQ_NFT" <<REGRAS
# Gerado por projects/ghop-dhcp/dhcp.sh. Aplicado por $REGRAS_LOJMIT_ANTIGO.
# O DHCP responde SO na LAN. Servidor DHCP alcancavel de fora entrega
# endereco e, pior, ROTEADOR e DNS a quem nao devia -- e sequestro de rede
# em uma linha de configuracao.
nft add rule inet filter input iifname $lan udp dport 67 counter accept
nft add rule inet filter input udp dport 67 counter drop
REGRAS
	chmod 755 "$ARQ_NFT"
}

aplica_firewall() {
	if [ -x "$REGRAS_FIREWALL" ]; then
		systemctl restart "$UNIDADE_FIREWALL"
	elif [ -x "$REGRAS_LOJMIT_ANTIGO" ] && grep -q "nft.d" "$REGRAS_LOJMIT_ANTIGO"; then
		systemctl restart gateway.service
	elif nft list table inet filter >/dev/null 2>&1; then
		bash "$ARQ_NFT"
	fi
}

comando_estado() {
	echo "ghop-dhcp"
	printf '  %-24s %s / %s\n' "$UNIDADE" \
		"$(systemctl is-active "$UNIDADE" 2>/dev/null || true)" \
		"$(systemctl is-enabled "$UNIDADE" 2>/dev/null || true)"
	if [ -f "$ARQ_ESTADO" ]; then
		printf '  %-24s %s\n' "interface" "$(cat "$ARQ_ESTADO")"
	fi
	if [ -f "$ARQ_CONF" ]; then
		printf '  %-24s %s\n' "faixa" \
			"$(sed -n 's/^[[:space:]]*range[[:space:]]*//p' "$ARQ_CONF" | tr -d ';' | head -n1)"
		printf '  %-24s %s\n' "resolvedor entregue" \
			"$(sed -n 's/^[[:space:]]*option domain-name-servers[[:space:]]*//p' "$ARQ_CONF" | tr -d ';' | tail -n1)"
	fi
	if [ -f "$ARQ_LEASES" ]; then
		printf '  %-24s %s\n' "concessoes ativas" \
			"$(grep -c 'binding state active' "$ARQ_LEASES" 2>/dev/null || echo 0)"
	fi
	[ -f "$ARQ_NFT" ] && printf '  %-24s %s\n' "firewall" "$ARQ_NFT"
	return 0
}

# Este DHCP e nosso? A marca em /etc/ghop e o que diz. Numa maquina apenas
# OBSERVADA o isc-dhcp-server veio da distribuicao, e ai ligar e desligar
# nao podem tocar em configuracao nem em firewall: sao o systemctl e mais
# nada. Sem isto o painel parava um DHCP alheio e nao conseguia religa-lo.
e_nosso() {
	[ -f "$ARQ_CONF" ] && [ -f "$ARQ_ESTADO" ]
}

comando_ligar() {
	if ! e_nosso; then
		systemctl start "$UNIDADE"
		echo "==> $UNIDADE iniciado (nao e um ghop-dhcp: nada mais foi tocado)"
		comando_estado
		return 0
	fi
	escreve_regra_firewall "$(cat "$ARQ_ESTADO")"
	aplica_firewall
	systemctl daemon-reload
	systemctl enable "$UNIDADE"
	systemctl restart "$UNIDADE"
	echo "==> ghop-dhcp ligado"
	comando_estado
}

comando_desligar() {
	if ! e_nosso; then
		# So parar. 'disable' tiraria do boot um servico que nao pusemos
		# la, e isso o operador nao desfaz pelo painel.
		systemctl stop "$UNIDADE"
		echo "==> $UNIDADE parado (nao e um ghop-dhcp: continua habilitado no boot)"
		comando_estado
		return 0
	fi
	systemctl disable --now "$UNIDADE" 2>/dev/null || true
	rm -f "$ARQ_NFT"
	if [ -x "$REGRAS_FIREWALL" ]; then
		systemctl restart "$UNIDADE_FIREWALL"
	elif [ -x "$REGRAS_LOJMIT_ANTIGO" ] && grep -q "nft.d" "$REGRAS_LOJMIT_ANTIGO"; then
		systemctl restart gateway.service
	fi
	echo "==> ghop-dhcp desligado"
	echo "    Quem ja tem endereco continua com ele ate a concessao vencer;"
	echo "    quem chegar agora na LAN nao recebe nenhum."
	comando_estado
}

comando_desinstalar() {
	# As CONCESSOES ficam. Elas dizem quem esteve nesta rede e quando, e
	# isso e justamente o que o painel usa; apagar seria perder observacao.
	systemctl disable --now "$UNIDADE" 2>/dev/null || true
	if [ -f "$ARQ_CONF.anterior-ghop" ]; then
		mv "$ARQ_CONF.anterior-ghop" "$ARQ_CONF"
		echo "==> $ARQ_CONF restaurado ao que havia antes do GHop"
	elif [ -f "$ARQ_CONF" ] && grep -q "Gerado por projects/ghop-dhcp" "$ARQ_CONF"; then
		# Sem copia do anterior porque nao havia nada antes: o arquivo e
		# nosso do inicio ao fim, e o carimbo prova.
		rm -f "$ARQ_CONF"
	elif [ -f "$ARQ_CONF" ]; then
		# Nem copia nem carimbo: este arquivo nao e nosso. Apagar aqui era
		# o jeito de uma maquina observada perder o DHCP dela por causa de
		# um clique no painel.
		echo "==> $ARQ_CONF preservado: nao foi o GHop que o escreveu"
	fi
	rm -rf "$DIR_DHCP"
	rm -f "$ARQ_NFT"
	if [ -x "$REGRAS_FIREWALL" ]; then
		systemctl restart "$UNIDADE_FIREWALL"
	elif [ -x "$REGRAS_LOJMIT_ANTIGO" ] && grep -q "nft.d" "$REGRAS_LOJMIT_ANTIGO"; then
		systemctl restart gateway.service
	fi
	systemctl daemon-reload
	echo "==> ghop-dhcp desinstalado"
	echo "    Ficaram: o pacote isc-dhcp-server e $ARQ_LEASES."
	echo "    Ninguem mais recebe endereco nesta LAN."
}

case "$ACAO" in
estado) comando_estado; exit 0 ;;
ligar) comando_ligar; exit 0 ;;
desligar) comando_desligar; exit 0 ;;
desinstalar) comando_desinstalar; exit 0 ;;
esac

# ---------------------------------------------------------------- instalar

if [ "$SEM_PERGUNTA" -eq 0 ]; then
	echo "Interfaces de rede desta maquina:"
	ip -brief addr | grep -v '^lo ' | sed 's/^/  /'
	echo
fi

WAN_SUGERIDA="$(ip route show default 2>/dev/null | awk '{print $5; exit}' || true)"
# Com Wi-Fi instalado a LAN e a bridge, e e nela que o DHCP tem de escutar.
LAN_SUGERIDA=""
[ -f "$ARQ_ESTADO" ] && LAN_SUGERIDA="$(cat "$ARQ_ESTADO")"
if [ -z "$LAN_SUGERIDA" ] && [ -f "$ARQ_WIFI" ]; then
	LAN_SUGERIDA="$(sed -n 's/^PONTE_IF=//p' "$ARQ_WIFI")"
fi
if [ -z "$LAN_SUGERIDA" ]; then
	LAN_SUGERIDA="$(sed -n 's/^INTERFACESv4="\(.*\)"/\1/p' "$ARQ_DEFAULT" 2>/dev/null | awk '{print $1}')"
fi
if [ -z "$LAN_SUGERIDA" ]; then
	LAN_SUGERIDA="$(interfaces | grep -v "^${WAN_SUGERIDA}$" | head -n1 || true)"
fi

LAN_IF="$(perguntar "Interface da LAN onde o DHCP atende" "${LAN_IF:-$LAN_SUGERIDA}")"
[ -e "/sys/class/net/$LAN_IF" ] || erro "interface '$LAN_IF' nao existe. Disponiveis: $(interfaces | tr '\n' ' ')"
[ "$LAN_IF" != "$WAN_SUGERIDA" ] ||
	erro "'$LAN_IF' e a saida para a internet. Servir DHCP ali entrega roteador e DNS
      para a rede de cima -- e o erro que derruba a rede dos outros."

LAN_ADDR="$(ip -4 -o addr show dev "$LAN_IF" 2>/dev/null | awk '{print $4; exit}' || true)"
[ -n "$LAN_ADDR" ] || erro "'$LAN_IF' nao tem endereco IPv4; configure a LAN antes."
LAN_IP="${LAN_ADDR%/*}"
read -r REDE MASCARA BROADCAST <<<"$(rede_de "$LAN_ADDR")"

# Faixa: da .100 a .200 da propria rede, que deixa o comeco livre para
# endereco fixo (o lojmIt, impressora, o que for cravado a mao).
BASE="${REDE%.*}"
FAIXA_INICIO="$(perguntar "Primeiro endereco da faixa" "${GHOP_DHCP_INICIO:-$BASE.100}")"
FAIXA_FIM="$(perguntar "Ultimo endereco da faixa" "${GHOP_DHCP_FIM:-$BASE.200}")"

RESOLVEDOR="$(perguntar "Resolvedor entregue aos clientes" \
	"${GHOP_DHCP_DNS:-$(resolvedor_sugerido "$LAN_IP")}")"
[ -n "$RESOLVEDOR" ] || erro "sem resolvedor para entregar; informe um."

# 10 minutos e o padrao do pacote e e curto demais: renova o tempo todo e
# enche o arquivo de concessoes. Uma hora, com teto de quatro, e o suficiente
# para uma LAN pequena e ainda devolve endereco rapido de quem foi embora.
MINUTOS="$(perguntar "Tempo de concessao, em minutos" "${GHOP_DHCP_MINUTOS:-60}")"
[[ "$MINUTOS" =~ ^[0-9]+$ ]] && [ "$MINUTOS" -ge 1 ] || erro "tempo invalido '$MINUTOS'."
CONCESSAO=$((MINUTOS * 60))
CONCESSAO_MAX=$((CONCESSAO * 4))

echo
echo "Sera aplicado nesta maquina:"
echo "  atende em           : $LAN_IF ($LAN_IP), rede $REDE/$MASCARA"
echo "  faixa               : $FAIXA_INICIO a $FAIXA_FIM"
echo "  entrega roteador    : $LAN_IP"
echo "  entrega resolvedor  : $RESOLVEDOR$([ "$RESOLVEDOR" = "$LAN_IP" ] && echo "  (esta maquina; o ghop-dns esta ligado)")"
echo "  concessao           : $MINUTOS min (teto $((CONCESSAO_MAX / 60)) min)"
echo "  firewall            : porta 67 so por $LAN_IF, via $ARQ_NFT"
echo "  arquivos            : $ARQ_CONF (copia em $ARQ_CONF.anterior-ghop)"
echo "                        $ARQ_DEFAULT"
echo "  pacotes             : os do papel 'dhcp' (ver scripts/service.sh)"
echo "  nao apaga           : as concessoes ja dadas ($ARQ_LEASES)"
echo

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
"$ORIGEM_SERVICE" dhcp

echo "==> Configuracao em $ARQ_CONF"
if [ -f "$ARQ_CONF" ] && ! grep -q "Gerado por projects/ghop-dhcp" "$ARQ_CONF"; then
	cp -a "$ARQ_CONF" "$ARQ_CONF.anterior-ghop"
	echo "    o que havia foi guardado em $ARQ_CONF.anterior-ghop"
fi
cat > "$ARQ_CONF" <<CONF
# Gerado por projects/ghop-dhcp/dhcp.sh do GHop. Alteracoes manuais serao sobrescritas.

# Sem DNS dinamico: o GHop nao registra nome de cliente em zona nenhuma.
ddns-update-style none;

# Unico servidor DHCP desta rede: responde NAK na hora a quem chega pedindo
# renovacao de um endereco de outra rede, em vez de deixar o cliente esperar.
authoritative;

default-lease-time $CONCESSAO;
max-lease-time $CONCESSAO_MAX;

subnet $REDE netmask $MASCARA {
  range $FAIXA_INICIO $FAIXA_FIM;
  option subnet-mask $MASCARA;
  option broadcast-address $BROADCAST;
  option routers $LAN_IP;
  option domain-name-servers $RESOLVEDOR;
}
CONF
chmod 644 "$ARQ_CONF"

echo "==> Interface em $ARQ_DEFAULT"
if [ -f "$ARQ_DEFAULT" ]; then
	sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$LAN_IF\"/" "$ARQ_DEFAULT"
	grep -q "^INTERFACESv4=" "$ARQ_DEFAULT" || echo "INTERFACESv4=\"$LAN_IF\"" >> "$ARQ_DEFAULT"
else
	printf 'INTERFACESv4="%s"\nINTERFACESv6=""\n' "$LAN_IF" > "$ARQ_DEFAULT"
fi

mkdir -p "$DIR_DHCP"
chmod 755 "$DIR_DHCP"
echo "$LAN_IF" > "$ARQ_ESTADO"

# Configuracao ruim so aparece quando o servico nao sobe; conferir antes.
dhcpd -t -cf "$ARQ_CONF" >/dev/null 2>&1 ||
	erro "o dhcpd recusou $ARQ_CONF. Rode 'dhcpd -t -cf $ARQ_CONF' para ver o motivo."

comando_ligar

echo
echo "==> Concluido"
printf 'atende em      %s (%s)\n' "$LAN_IF" "$LAN_IP"
printf 'faixa          %s a %s\n' "$FAIXA_INICIO" "$FAIXA_FIM"
printf 'resolvedor     %s\n' "$RESOLVEDOR"
printf 'servico        %s\n' "$(systemctl is-active "$UNIDADE")"
echo
echo "Concessoes em $ARQ_LEASES; o painel as mostra na tela DHCP do no."
echo "Desligar sem desinstalar:  sudo $0 desligar"
