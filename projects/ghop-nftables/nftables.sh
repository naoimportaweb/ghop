#!/bin/bash
#
# nftables.sh - instala e liga o ghop-nftables: o DONO do firewall da maquina.
#
# Ate aqui as regras moravam dentro do scripts/lojmIt.sh, misturadas com a
# configuracao de interface e encaminhamento. Separar tem um motivo pratico:
# o firewall e a unica coisa da maquina que se reescreve INTEIRA a cada
# aplicacao ('nft flush ruleset'), e por isso precisa de um dono so. Com dois
# scripts escrevendo, o ultimo a rodar apaga o outro e ninguem descobre.
#
# O que este papel escreve:
#   /usr/local/sbin/ghop-nftables.sh   as regras, geradas a partir daqui
#   ghop-nftables.service              aplica no boot
#   /etc/ghop/nftables/interfaces      WAN e LAN, para os outros papeis lerem
#
# Os fragmentos de /etc/ghop/nft.d/*.sh, escritos pelos outros papeis (a 53 do
# ghop-dns, a 67 do ghop-dhcp), sao aplicados DEPOIS das regras base. E o que
# permite cada papel abrir a sua porta sem conhecer este arquivo.
#
# 'desligar' APAGA O RULESET (nft flush ruleset). A maquina continua roteando,
# mas sem NAT nem filtro: a LAN perde a internet e a maquina fica exposta na
# WAN. E o unico papel do GHop cujo desligar piora a seguranca, e por isso o
# aviso aparece na tela do painel antes de qualquer clique.
#
# Uso interativo:      sudo ./projects/ghop-nftables/nftables.sh
# Uso nao interativo:  sudo WAN_IF=enp1s0 LAN_IF=br0 ./projects/ghop-nftables/nftables.sh --sim
# Depois:              sudo ./projects/ghop-nftables/nftables.sh ligar | desligar | estado | desinstalar

set -euo pipefail
trap 'echo "Erro: $0 parou na linha $LINENO (comando: $BASH_COMMAND)" >&2' ERR

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEM_SERVICE="$DIR_SCRIPT/../../scripts/service.sh"
DIR_CONFIG=/etc/ghop
DIR_NFTABLES="$DIR_CONFIG/nftables"
ARQ_ESTADO="$DIR_NFTABLES/interfaces"
DIR_NFT="$DIR_CONFIG/nft.d"
ARQ_REGRAS=/usr/local/sbin/ghop-nftables.sh
ARQ_SERVICO=/etc/systemd/system/ghop-nftables.service
UNIDADE=ghop-nftables.service
# O que havia antes: as regras moravam no papel lojmIt.
ARQ_REGRAS_ANTIGO=/usr/local/sbin/gateway.sh
UNIDADE_ANTIGA=gateway.service

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

comando_estado() {
	echo "ghop-nftables"
	printf '  %-24s %s / %s\n' "$UNIDADE" \
		"$(systemctl is-active "$UNIDADE" 2>/dev/null || true)" \
		"$(systemctl is-enabled "$UNIDADE" 2>/dev/null || true)"
	if [ -f "$ARQ_ESTADO" ]; then
		printf '  %-24s %s\n' "interfaces" "$(tr '\n' ' ' < "$ARQ_ESTADO")"
	fi
	printf '  %-24s %s\n' "encaminhamento" "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)"
	printf '  %-24s %s regra(s)\n' "ruleset ativo" \
		"$(nft list ruleset 2>/dev/null | grep -cE '^\s+(ip|iifname|oif|meta|tcp|udp|ct)' || echo 0)"
	if [ -d "$DIR_NFT" ]; then
		printf '  %-24s %s\n' "fragmentos" \
			"$(ls "$DIR_NFT" 2>/dev/null | tr '\n' ' ' || true)"
	fi
	return 0
}

comando_ligar() {
	[ -x "$ARQ_REGRAS" ] ||
		erro "ghop-nftables ainda nao foi instalado aqui. Rode: sudo $0"
	systemctl daemon-reload
	systemctl enable "$UNIDADE"
	systemctl restart "$UNIDADE"
	echo "==> ghop-nftables ligado"
	comando_estado
}

comando_desligar() {
	systemctl disable --now "$UNIDADE" 2>/dev/null || true
	# Parar a unidade nao apaga regra nenhuma: ela e 'oneshot' e o ruleset
	# vive no kernel. Sem este flush, 'desligar' nao desligaria nada.
	nft flush ruleset 2>/dev/null || true
	echo "==> ghop-nftables desligado: RULESET APAGADO"
	echo "    A maquina continua roteando, mas sem NAT e sem filtro:"
	echo "    a LAN perde a internet e as portas ficam abertas na WAN."
	comando_estado
}

comando_desinstalar() {
	systemctl disable --now "$UNIDADE" 2>/dev/null || true
	nft flush ruleset 2>/dev/null || true
	rm -f "$ARQ_SERVICO" "$ARQ_REGRAS"
	rm -rf "$DIR_NFTABLES"
	systemctl daemon-reload
	echo "==> ghop-nftables desinstalado"
	echo "    Ficaram os fragmentos em $DIR_NFT, que sao dos outros papeis."
	echo "    A maquina esta SEM FIREWALL ate alguem escrever regras de novo."
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

# Sugestoes: primeiro o que ja foi decidido antes (nossa propria instalacao
# anterior, ou a bridge do Wi-Fi), e so entao o chute.
WAN_SUGERIDA="$(ip route show default 2>/dev/null | awk '{print $5; exit}' || true)"
LAN_SUGERIDA=""
if [ -f "$ARQ_ESTADO" ]; then
	# shellcheck disable=SC1090
	. "$ARQ_ESTADO"
	WAN_SUGERIDA="${WAN_IF:-$WAN_SUGERIDA}"
	LAN_SUGERIDA="${LAN_IF:-}"
fi
if [ -z "$LAN_SUGERIDA" ] && [ -f /etc/ghop/wifi/interfaces ]; then
	LAN_SUGERIDA="$(sed -n 's/^PONTE_IF=//p' /etc/ghop/wifi/interfaces)"
fi
if [ -z "$LAN_SUGERIDA" ]; then
	LAN_SUGERIDA="$(interfaces | grep -v "^${WAN_SUGERIDA}$" | head -n1 || true)"
fi

WAN_IF="$(perguntar "Interface de SAIDA para a internet (WAN, faz o masquerade)" "${WAN_IF:-$WAN_SUGERIDA}")"
LAN_IF="$(perguntar "Interface da rede INTERNA (LAN)" "${LAN_IF:-$LAN_SUGERIDA}")"

for interface in "$WAN_IF" "$LAN_IF"; do
	[ -e "/sys/class/net/$interface" ] ||
		erro "interface '$interface' nao existe. Disponiveis: $(interfaces | tr '\n' ' ')"
done
[ "$WAN_IF" != "$LAN_IF" ] || erro "WAN e LAN nao podem ser a mesma interface ($WAN_IF)."

echo
echo "Sera aplicado nesta maquina:"
echo "  WAN (masquerade)  : $WAN_IF"
echo "  LAN               : $LAN_IF"
echo "  SSH (porta 22)    : somente por $LAN_IF"
echo "  portas 7000-7100  : somente por $LAN_IF (agente/painel GHop)"
echo "  fragmentos        : $DIR_NFT/*.sh, dos outros papeis, aplicados depois"
echo "  pacotes           : os do papel 'nftables' (ver scripts/service.sh)"
echo "  arquivos          : $ARQ_REGRAS"
echo "                      $ARQ_SERVICO"
if [ -f "$ARQ_REGRAS_ANTIGO" ] || systemctl list-unit-files "$UNIDADE_ANTIGA" >/dev/null 2>&1; then
	echo "  migracao          : as regras saem do papel lojmIt ($UNIDADE_ANTIGA)"
	echo "                      e passam a ser deste papel"
fi
echo
echo "Atencao: as regras de firewall atuais serao apagadas (nft flush ruleset)."

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
"$ORIGEM_SERVICE" nftables

echo "==> Escrevendo regras em $ARQ_REGRAS (masquerade em $WAN_IF)"
mkdir -p "$DIR_NFT"
cat > "$ARQ_REGRAS" <<REGRAS
#!/bin/bash
# Gerado por projects/ghop-nftables/nftables.sh do GHop.
# Alteracoes manuais serao sobrescritas: mexa no papel, nao aqui.

nft flush ruleset

nft add table inet filter
nft add chain inet filter input '{type filter hook input priority 0; }'
# Regra de CONTAGEM no topo da cadeia: nao decide nada (nao tem veredito),
# so conta tudo o que entra. E o unico jeito de saber quanto passa por uma
# cadeia -- somar os contadores das regras conta o mesmo pacote varias vezes,
# porque ele incrementa cada regra por que passa ate uma decidir.
nft add rule  inet filter input counter

# 'counter' em toda regra: e o que o painel mostra na tela Roteamento, e e
# como se descobre regra que nunca pegou nada -- a que sobra, ou a que
# deveria estar barrando algo e nao esta.
nft add rule  inet filter input ip protocol tcp ct state established counter accept
nft add rule  inet filter input ip protocol udp ct state established counter accept

# SSH somente pela LAN: a porta 22 nao responde na interface da internet.
nft add rule  inet filter input iifname lo counter accept
nft add rule  inet filter input iifname $LAN_IF tcp dport 22 counter accept
nft add rule  inet filter input tcp dport 22 counter drop

# Faixa de servicos internos do GHop (agente, painel): so responde na LAN.
nft add rule  inet filter input iifname $LAN_IF meta l4proto '{ tcp, udp }' th dport 7000-7100 counter accept
nft add rule  inet filter input meta l4proto '{ tcp, udp }' th dport 7000-7100 counter drop

nft add chain inet filter forward '{ type filter hook forward priority 0; }'
nft add rule  inet filter forward counter
nft add rule  inet filter forward ip protocol tcp ct state established counter accept
nft add rule  inet filter forward ip protocol udp ct state established counter accept

nft add table  inet nat
nft add chain  inet nat prerouting '{ type nat hook prerouting priority -100; }'
nft add rule   inet nat prerouting counter
nft add chain  inet nat postrouting '{ type nat hook postrouting priority 100; }'
nft add rule   inet nat postrouting counter
nft add rule   inet nat postrouting oif $WAN_IF counter masquerade

# Fragmentos dos outros papeis (a 53 do ghop-dns, a 67 do ghop-dhcp). Vem
# depois das regras base, para cada papel abrir a sua porta sem conhecer
# este arquivo e sem que a reinstalacao do firewall apague o que ele fez.
for extra in $DIR_NFT/*.sh; do
	[ -f "\$extra" ] && bash "\$extra"
done
exit 0
REGRAS
chmod 755 "$ARQ_REGRAS"

echo "==> Escrevendo servico em $ARQ_SERVICO"
cat > "$ARQ_SERVICO" <<SERVICO
[Unit]
Description=GHop - nftables: firewall e NAT desta maquina
After=network.target
# A bridge do ghop-wifi nasce no ifupdown; regra que cita interface
# inexistente falha, entao as regras vem depois da rede de pe.
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ARQ_REGRAS

[Install]
WantedBy=multi-user.target
SERVICO

mkdir -p "$DIR_NFTABLES"
chmod 755 "$DIR_NFTABLES"
printf 'WAN_IF=%s\nLAN_IF=%s\n' "$WAN_IF" "$LAN_IF" > "$ARQ_ESTADO"

# Migracao: o papel lojmIt nao escreve mais regra. Se a unidade antiga
# ainda existir, ela some agora -- duas unidades aplicando ruleset e
# exatamente o problema que este papel veio resolver.
if systemctl list-unit-files "$UNIDADE_ANTIGA" >/dev/null 2>&1 &&
	[ -f "/etc/systemd/system/$UNIDADE_ANTIGA" ]; then
	echo "==> Migrando: desativando $UNIDADE_ANTIGA (as regras agora sao daqui)"
	systemctl disable --now "$UNIDADE_ANTIGA" 2>/dev/null || true
	rm -f "/etc/systemd/system/$UNIDADE_ANTIGA" "$ARQ_REGRAS_ANTIGO"
fi

comando_ligar

echo
echo "==> Concluido"
printf 'WAN            %s\n' "$WAN_IF"
printf 'LAN            %s\n' "$LAN_IF"
printf 'servico        %s\n' "$(systemctl is-active "$UNIDADE")"
echo
echo "Ver o ruleset:  sudo nft list ruleset"
echo "Desligar (APAGA o firewall):  sudo $0 desligar"
