#!/bin/bash
#
# lojmIt.sh - transforma uma maquina Debian limpa em um lojmIt GHop.
#
# Pergunta as interfaces (WAN/LAN), instala os programas e habilita o
# encaminhamento de pacotes. O FIREWALL NAO MORA MAIS AQUI: as regras sao do
# papel 'nftables' (projects/ghop-nftables), que este script chama. O motivo
# esta la -- ruleset se reescreve inteiro, e por isso precisa de um dono so.
# Idempotente: pode rodar novamente sobre uma maquina ja configurada.
#
# Uso interativo:      sudo ./scripts/lojmIt.sh
# Uso nao interativo:  sudo WAN_IF=enp1s0 LAN_IF=enp3s0 ./scripts/lojmIt.sh --sim

set -euo pipefail

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEM_SERVICE="$DIR_SCRIPT/service.sh"

ARQ_SYSCTL=/etc/sysctl.d/99-forward.conf
ORIGEM_NFTABLES="$DIR_SCRIPT/../projects/ghop-nftables/nftables.sh"

SEM_PERGUNTA=0
ARG_SIM=""
[ "${1:-}" = "--sim" ] && { SEM_PERGUNTA=1; ARG_SIM="--sim"; }
[ -t 0 ] || SEM_PERGUNTA=1

if [ "$(id -u)" -ne 0 ]; then
	echo "Erro: execute como root (sudo $0)." >&2
	exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
	echo "Erro: apt-get nao encontrado; este script e para Debian." >&2
	exit 1
fi

if [ ! -x "$ORIGEM_NFTABLES" ]; then
	echo "Erro: $ORIGEM_NFTABLES nao encontrado." >&2
	echo "      O lojmIt depende do papel nftables; copie o repositorio inteiro." >&2
	exit 1
fi

if [ ! -x "$ORIGEM_SERVICE" ]; then
	echo "Erro: $ORIGEM_SERVICE nao encontrado." >&2
	echo "      Copie o repositorio inteiro para esta maquina, nao so este script." >&2
	exit 1
fi

# Lista as interfaces de rede, ignorando a loopback.
interfaces() {
	ls /sys/class/net | grep -v '^lo$'
}

# Pergunta algo ao usuario, oferecendo um valor padrao entre colchetes.
perguntar() {
	local texto="$1" padrao="$2" resposta
	if [ "$SEM_PERGUNTA" -eq 1 ]; then
		echo "$padrao"
		return
	fi
	read -r -p "$texto [$padrao]: " resposta </dev/tty
	echo "${resposta:-$padrao}"
}

# Um lojmIt roteia entre duas redes: com uma interface so, esta maquina nao
# e um lojmIt -- e provavelmente e o computador do operador, onde rodar
# isto apagaria o firewall a toa. Sem esta checagem o script morria calado
# no grep abaixo, que falha quando nao sobra interface para sugerir.
if [ "$(interfaces | wc -l)" -lt 2 ]; then
	echo "Erro: esta maquina tem so uma interface de rede ($(interfaces | tr '\n' ' '))." >&2
	echo "      Um lojmIt precisa de WAN e LAN. Rode isto na maquina de borda," >&2
	echo "      nao na do operador." >&2
	exit 1
fi

# Sugestoes: a WAN e a interface da rota padrao; a LAN e a outra que sobrar.
WAN_SUGERIDA="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
WAN_SUGERIDA="${WAN_SUGERIDA:-$(interfaces | head -n1)}"
LAN_SUGERIDA="$(interfaces | grep -v "^${WAN_SUGERIDA}$" | head -n1 || true)"

if [ "$SEM_PERGUNTA" -eq 0 ]; then
	echo "Interfaces de rede desta maquina:"
	ip -brief addr | grep -v '^lo ' | sed 's/^/  /'
	echo
fi

WAN_IF="$(perguntar "Interface de SAIDA para a internet (WAN, faz o masquerade)" "${WAN_IF:-$WAN_SUGERIDA}")"
LAN_IF="$(perguntar "Interface da rede INTERNA (LAN)" "${LAN_IF:-$LAN_SUGERIDA}")"

for interface in "$WAN_IF" "$LAN_IF"; do
	if [ ! -e "/sys/class/net/$interface" ]; then
		echo "Erro: interface '$interface' nao existe nesta maquina." >&2
		echo "      Disponiveis: $(interfaces | tr '\n' ' ')" >&2
		exit 1
	fi
done

if [ "$WAN_IF" = "$LAN_IF" ]; then
	echo "Erro: WAN e LAN nao podem ser a mesma interface ($WAN_IF)." >&2
	exit 1
fi

echo
echo "Sera aplicado nesta maquina:"
echo "  WAN (masquerade) : $WAN_IF"
echo "  LAN              : $LAN_IF"
echo "  SSH (porta 22)   : somente por $LAN_IF"
echo "  portas 7000-7100 : somente por $LAN_IF (agente/painel GHop)"
echo "  firewall         : escrito pelo papel 'nftables', chamado a seguir"
echo "  pacotes          : os do papel 'lojmIt' (ver scripts/service.sh)"
echo "  arquivos         : $ARQ_SYSCTL"
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
"$ORIGEM_SERVICE" lojmIt

echo "==> Firewall: delegando ao papel nftables"
# As interfaces ja foram respondidas aqui; o papel nftables as recebe pelo
# ambiente para nao perguntar duas vezes a mesma coisa.
WAN_IF="$WAN_IF" LAN_IF="$LAN_IF" "$ORIGEM_NFTABLES" $ARG_SIM

echo "==> Habilitando encaminhamento de pacotes em $ARQ_SYSCTL"
echo "net.ipv4.ip_forward=1" > "$ARQ_SYSCTL"
sysctl --system >/dev/null


echo
echo "==> Concluido"
printf 'WAN  %-10s %s\n' "$WAN_IF" "$(ip -brief addr show "$WAN_IF" | awk '{$1="";$2="";print}')"
printf 'LAN  %-10s %s\n' "$LAN_IF" "$(ip -brief addr show "$LAN_IF" | awk '{$1="";$2="";print}')"
printf 'ip_forward  %s\n' "$(cat /proc/sys/net/ipv4/ip_forward)"
printf 'firewall    %s (ghop-nftables.service)\n' "$(systemctl is-active ghop-nftables.service)"
