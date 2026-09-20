#!/bin/bash
#
# install.sh - instala um elemento do GHop nesta maquina.
#
# Ponto de entrada unico: em cada no, clonar o repositorio e rodar so isto.
#
#   git clone https://github.com/naoimportaweb/ghop.git
#   cd ghop
#   sudo ./install.sh <papel> [<papel>...]
#
# Papeis:
#   lojmIt   roteia, mascara e filtra a rede
#   agente   observa a maquina (coletor de IPs e dominios)
#   dns      resolvedor da LAN cifrado para cima, com lista de negacao (opcional)
#   wifi     ponto de acesso Wi-Fi em bridge com a LAN (opcional)
#   dhcp     servidor DHCP da LAN (opcional)
#   filtro   filtro de camada de aplicacao: SNI e Host da LAN (opcional)
#   nftables firewall e NAT (instalado junto com o lojmIt)
#   painel   a maquina do operador: fala com os agentes e guarda a CA
#
# Papeis se somam, e a ordem de instalacao e sempre a mesma
# independentemente da ordem em que forem passados:
#
#   sudo ./install.sh lojmIt agente
#
# Com --sim nao ha perguntas: os valores sugeridos sao aceitos. Use apenas
# quando souber o que sera aplicado.

set -euo pipefail

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SEM_PERGUNTA=""
papeis=()
for argumento in "$@"; do
	case "$argumento" in
	--sim) SEM_PERGUNTA="--sim" ;;
	lojmIt | agente | dns | wifi | dhcp | filtro | nftables | painel) papeis+=("$argumento") ;;
	*)
		echo "Erro: argumento desconhecido '$argumento'." >&2
		echo "      Uso: sudo $0 <papel> [<papel>...] [--sim]" >&2
		echo "      Papeis: lojmIt, agente, dns, wifi, dhcp, filtro, nftables, painel" >&2
		exit 1
		;;
	esac
done

if [ "${#papeis[@]}" -eq 0 ]; then
	echo "Uso: sudo $0 <papel> [<papel>...] [--sim]" >&2
	echo "Papeis: lojmIt, agente, dns, wifi, dhcp, filtro, nftables, painel" >&2
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "Erro: execute como root (sudo $0 $*)." >&2
	exit 1
fi

tem_papel() {
	local procurado="$1" papel
	for papel in "${papeis[@]}"; do
		[ "$papel" = "$procurado" ] && return 0
	done
	return 1
}

# O wifi vem antes de todos: ele cria a bridge que passa a ser a LAN, e os
# demais papeis precisam dela existindo para apontar LAN_IF para ela.
if tem_papel wifi; then
	echo "########## papel: wifi ##########"
	"$DIR_SCRIPT/projects/ghop-wifi/wifi.sh" $SEM_PERGUNTA
	# Daqui em diante a LAN e a bridge, para quem vier a seguir.
	if [ -f /etc/ghop/wifi/interfaces ]; then
		LAN_IF="$(sed -n 's/^PONTE_IF=//p' /etc/ghop/wifi/interfaces)"
		export LAN_IF
	fi
	echo
fi

# O firewall sozinho, para quem pediu so ele. Com 'lojmIt' na linha nao
# entra aqui: o proprio lojmIt.sh o chama, ja com as interfaces respondidas.
if tem_papel nftables && ! tem_papel lojmIt; then
	echo "########## papel: nftables ##########"
	"$DIR_SCRIPT/projects/ghop-nftables/nftables.sh" $SEM_PERGUNTA
	echo
fi

# O lojmIt vem em seguida: e ele que estabelece rede e firewall, e os
# demais elementos dependem da maquina ja estar roteando.
if tem_papel lojmIt; then
	echo "########## papel: lojmIt ##########"
	"$DIR_SCRIPT/scripts/lojmIt.sh" $SEM_PERGUNTA
	echo
fi

# O dns vem antes do agente: o coletor le o DNS na entrada da LAN, e e
# melhor que o resolvedor ja esteja atendendo ali quando a captura subir.
if tem_papel dns; then
	echo "########## papel: dns ##########"
	"$DIR_SCRIPT/projects/ghop-dns/dns.sh" $SEM_PERGUNTA
	echo
fi

# O dhcp vem depois do dns: o que ele entrega como resolvedor depende de o
# ghop-dns ja estar no ar nesta maquina.
if tem_papel dhcp; then
	echo "########## papel: dhcp ##########"
	"$DIR_SCRIPT/projects/ghop-dhcp/dhcp.sh" $SEM_PERGUNTA
	echo
fi

# O filtro vem depois do dhcp e antes do agente. Depois do dhcp porque a LAN
# ja tem de estar recebendo endereco para valer a pena filtra-la; antes do
# agente porque e o agente que passa a poder liga-lo e desliga-lo, e ele ja
# deve existir quando o painel perguntar quais papeis ha aqui.
if tem_papel filtro; then
	echo "########## papel: filtro ##########"
	"$DIR_SCRIPT/projects/ghop-filtro/filtro.sh" $SEM_PERGUNTA
	echo
fi

if tem_papel agente; then
	echo "########## papel: agente ##########"
	"$DIR_SCRIPT/projects/ghop-request/requests.sh" $SEM_PERGUNTA
	echo
	# O agente so sobe com certificado, e certificado chega presencialmente --
	# pode ainda nao estar aqui na primeira passada. Nesse caso a instalacao
	# nao falha: o coletor ja fica de pe, e o agente entra quando a chave
	# chegar. E o unico jeito de o instalador nao empurrar o operador a
	# transportar certificado pela rede so para nao ver um erro.
	if [ -f /etc/ghop/certs/agente.crt ] && [ -f /etc/ghop/certs/ca.crt ]; then
		"$DIR_SCRIPT/projects/ghop-agente/agente.sh" $SEM_PERGUNTA
	else
		echo "--- agente (comandos do painel): adiado ---"
		echo "Sem certificado em /etc/ghop/certs; so o coletor foi instalado."
		echo "Emita na maquina do operador e traga presencialmente:"
		echo "  ./ca.sh agente $(hostname)"
		echo "Depois, aqui:"
		echo "  sudo GHOP_CERTS=<diretorio> $DIR_SCRIPT/projects/ghop-agente/agente.sh"
	fi
	echo
fi

if tem_papel painel; then
	echo "########## papel: painel ##########"
	# Ainda nao ha instalador proprio do painel: por ora so os pacotes.
	"$DIR_SCRIPT/scripts/service.sh" painel
	echo
fi

echo "########## concluido: ${papeis[*]} ##########"
