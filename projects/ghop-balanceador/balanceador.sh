#!/bin/bash
#
# balanceador.sh - instala e liga o ghop-balanceador nesta maquina: a escolha de por qual
# placa cada conexao da LAN sai para a internet.
#
# Dois estagios, nesta ordem:
#
#   ENVIO PARA IP FORA -> lista da placa A -> lista da placa B -> ... ->
#                         balanceamento de carga
#
# A primeira lista que casa decide; o que sobra cai no balanceamento, que e
# 'rodizio' (contador que gira, respeitando peso) ou 'afinidade' (hash do IP
# de origem: o mesmo cliente sempre pela mesma placa).
#
# Este papel LIGA E DESLIGA sem tocar no resto, e e OPCIONAL: o lojmIt roteia
# igual sem ele, pela WAN principal. Ao contrario do ghop-filtro, ele NAO fica
# no caminho do dado -- quem marca e roteia e o kernel, e nao ha processo que,
# caindo, pare a rede. 'desligar' tira as regras de politica e o fragmento de
# firewall, e a maquina volta a sair toda pela WAN principal.
#
# O que ele escreve:
#   /etc/ghop/balanceador/placas      as placas: nome, interface, gateway, peso
#   /etc/ghop/balanceador/interface   a LAN cujo trafego e decidido
#   /etc/ghop/balanceador/regras.json as listas, escritas pelo painel (DADO)
#   /etc/ghop/nft.d/balanceador.sh    o fragmento, gerado -- aplicado pelo nftables
#   /usr/local/sbin/ghop-balanceador.py  o gerador
#   /etc/sysctl.d/90-ghop-balanceador.conf  rp_filter frouxo (ver abaixo)
#   /etc/udev/rules.d/90-ghop-balanceador.rules  reaplica quando placa cai ou volta
#
# ATENCAO ao rp_filter. Com duas saidas e rota por politica, a resposta de uma
# conexao volta pela placa por onde ela saiu -- que nao e a placa da rota
# default. Com rp_filter ESTRITO (1) o kernel descarta essa resposta, e o
# sintoma e "a segunda placa nao funciona". Este papel poe 2 (frouxo), que
# ainda barra endereco de origem sem rota nenhuma. Sem isso o balanceamento
# parece montado e nao passa trafego.
#
# Uso interativo:      sudo ./projects/ghop-balanceador/balanceador.sh
# Uso nao interativo:  sudo LAN_IF=enp3s0 \
#                        GHOP_BALANCEADOR_PLACAS='wan1:enp1s0:192.168.0.1:7 wan2:enx00e04c:10.9.9.1:3' \
#                        ./projects/ghop-balanceador/balanceador.sh --sim
# Depois:              sudo ./projects/ghop-balanceador/balanceador.sh estado | ligar | desligar | recarregar

set -euo pipefail

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEM_SERVICE="$DIR_SCRIPT/../../scripts/service.sh"
ORIGEM_BALANCEADOR="$DIR_SCRIPT/ghop-balanceador.py"
DIR_CONFIG=/etc/ghop
# O diretorio E a marca do papel: o agente procura /etc/ghop/balanceador para dizer
# se este papel existe nesta maquina.
DIR_BALANCEADOR="$DIR_CONFIG/balanceador"
ARQ_PLACAS="$DIR_BALANCEADOR/placas"
ARQ_INTERFACE="$DIR_BALANCEADOR/interface"
ARQ_REGRAS="$DIR_BALANCEADOR/regras.json"
DIR_NFT="$DIR_CONFIG/nft.d"
ARQ_NFT="$DIR_NFT/balanceador.sh"
ARQ_BALANCEADOR=/usr/local/sbin/ghop-balanceador.py
ARQ_SERVICO=/etc/systemd/system/ghop-balanceador.service
ARQ_SYSCTL=/etc/sysctl.d/90-ghop-balanceador.conf
ARQ_UDEV=/etc/udev/rules.d/90-ghop-balanceador.rules
ARQ_SONDA=/etc/systemd/system/ghop-balanceador-sonda.service
ARQ_TIMER=/etc/systemd/system/ghop-balanceador-sonda.timer
UNIDADE_SONDA=ghop-balanceador-sonda.timer
# Quanto tempo uma placa que caiu fica FORA depois de melhorar. O failover e
# imediato; isto atrasa so a volta, para placa instavel nao ficar entrando e
# saindo da rotacao a cada ciclo.
QUARENTENA="${GHOP_BALANCEADOR_QUARENTENA:-5}"
# 'nexthop' pinga o gateway da propria placa (um salto, rede local dela);
# um IPv4 explicito prova a internet e e opt-in; 'nao' desliga a sonda.
SONDA="${GHOP_BALANCEADOR_SONDA:-nexthop}"
DIR_LINK=/etc/systemd/network
UNIDADE=ghop-balanceador.service
ARQ_INTERFACES_NFT="$DIR_CONFIG/nftables/interfaces"
REGRAS_FIREWALL=/usr/local/sbin/ghop-nftables.sh
UNIDADE_FIREWALL=ghop-nftables.service

erro() {
	echo "Erro: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || erro "execute como root (sudo $0 $*)."
command -v apt-get >/dev/null 2>&1 || erro "apt-get nao encontrado; este script e para Debian."
[ -x "$ORIGEM_SERVICE" ] || erro "$ORIGEM_SERVICE nao encontrado.
      Copie o repositorio inteiro para esta maquina, nao so este script."
[ -f "$ORIGEM_BALANCEADOR" ] || erro "$ORIGEM_BALANCEADOR nao encontrado.
      Copie o repositorio inteiro para esta maquina, nao so este script."

SEM_PERGUNTA=0
ACAO=instalar
for argumento in "$@"; do
	case "$argumento" in
	--sim) SEM_PERGUNTA=1 ;;
	ligar | desligar | estado | recarregar | desinstalar | instalar) ACAO="$argumento" ;;
	*) erro "argumento desconhecido '$argumento'. Uso: $0 [instalar|ligar|desligar|desinstalar|estado|recarregar] [--sim]" ;;
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

# Placa USB tem nome por CAMINHO de barramento ('enp0s20f0u2') ou por MAC
# ('enx00e04c...'). O por caminho MUDA se alguem plugar em outra porta -- e ai
# a tabela de rota, a regra de politica e o masquerade apontam para interface
# que nao existe, calados. Por isso o nome vira fato fixado por MAC.
e_usb() {
	local interface="$1" caminho
	caminho="$(readlink -f "/sys/class/net/$interface" 2>/dev/null || true)"
	case "$caminho" in
	*/usb*) return 0 ;;
	esac
	return 1
}

mac_de() {
	cat "/sys/class/net/$1/address" 2>/dev/null || true
}

fixa_nome() {
	local interface="$1" nome="$2" mac
	mac="$(mac_de "$interface")"
	[ -n "$mac" ] || return 0
	mkdir -p "$DIR_LINK"
	cat > "$DIR_LINK/10-ghop-$nome.link" <<LINK
# Gerado por projects/ghop-balanceador/balanceador.sh do GHop.
#
# Prende o nome '$nome' ao MAC desta placa. Placa USB nomeada por caminho de
# barramento muda de nome quando troca de porta, e regra de rota aponta por
# NOME: sem isto, mudar a porta USB manda metade do trafego para uma
# interface que nao existe, sem erro nenhum na tela.
[Match]
MACAddress=$mac

[Link]
Name=$nome
LINK
	echo "    nome '$nome' preso ao MAC $mac em $DIR_LINK/10-ghop-$nome.link"
	echo "    Vale no proximo boot ou quando a placa for replugada. Ate la ela"
	echo "    aparece como '$interface' e fica FORA da rotacao -- o que e o"
	echo "    comportamento certo: nao se manda trafego para placa que nao se"
	echo "    sabe nomear."
}

aplica_firewall() {
	if [ -x "$REGRAS_FIREWALL" ]; then
		systemctl restart "$UNIDADE_FIREWALL"
	else
		echo "Atencao: esta maquina nao tem o papel nftables do GHop." >&2
		echo "         Instale o firewall (sudo ./install.sh nftables) para o" >&2
		echo "         fragmento persistir. Aplicando so por agora." >&2
		bash "$ARQ_NFT" || true
	fi
}

# O fragmento pode ser recusado pelo nft -- versao de kernel sem 'numgen', por
# exemplo. Conferir depois de aplicar e DESFAZER se nao pegou e o que impede o
# caso ruim: regra de politica em pe, mandando trafego para uma tabela de rota
# cuja marca ninguem poe. Aqui degradar quer dizer voltar a sair toda pela WAN
# principal, que e o que a maquina fazia antes deste papel existir.
confere_ou_desfaz() {
	if nft list chain inet ghop_balanceador prerouting >/dev/null 2>&1; then
		return 0
	fi
	echo "Erro: o nft nao aceitou o fragmento $ARQ_NFT." >&2
	echo "      Desfazendo: a maquina volta a sair pela WAN principal." >&2
	"$ARQ_BALANCEADOR" --remover || true
	rm -f "$ARQ_NFT"
	[ -x "$REGRAS_FIREWALL" ] && systemctl restart "$UNIDADE_FIREWALL" || true
	echo "      Para ver o que ele recusou:" >&2
	echo "        sudo bash -x $ARQ_NFT" >&2
	exit 1
}

comando_estado() {
	echo "ghop-balanceador"
	printf '  %-24s %s / %s\n' "$UNIDADE" \
		"$(systemctl is-active "$UNIDADE" 2>/dev/null || true)" \
		"$(systemctl is-enabled "$UNIDADE" 2>/dev/null || true)"
	[ -f "$ARQ_INTERFACE" ] && printf '  %-24s %s\n' "decide o que entra por" "$(cat "$ARQ_INTERFACE")"
	if [ -f "$ARQ_PLACAS" ]; then
		echo "  placas"
		while read -r linha; do
			case "$linha" in '' | \#*) continue ;; esac
			local nome interface
			nome="$(echo "$linha" | tr ' ' '\n' | sed -n 's/^nome=//p')"
			interface="$(echo "$linha" | tr ' ' '\n' | sed -n 's/^if=//p')"
			local carrier="fora"
			[ "$(cat "/sys/class/net/$interface/carrier" 2>/dev/null || echo 0)" = "1" ] && carrier="no ar"
			printf '    %-14s %-12s %s\n' "$nome" "$interface" "$carrier"
		done < "$ARQ_PLACAS"
	fi
	printf '  %-24s %s\n' "$UNIDADE_SONDA" "$(systemctl is-active "$UNIDADE_SONDA" 2>/dev/null || true)"
	if [ -x "$ARQ_BALANCEADOR" ]; then
		printf '  %-24s %s\n' "regras e pesos" "$ARQ_REGRAS"
		ip rule show 2>/dev/null | grep -c fwmark | sed 's/^/    regras de politica: /'
	fi
	[ -f "$ARQ_NFT" ] && printf '  %-24s %s\n' "firewall" "$ARQ_NFT"
	return 0
}

comando_ligar() {
	[ -x "$ARQ_BALANCEADOR" ] && [ -f "$ARQ_PLACAS" ] ||
		erro "ghop-balanceador ainda nao foi instalado aqui. Rode: sudo $0"
	systemctl daemon-reload
	systemctl enable --now "$UNIDADE"
	[ -f "$ARQ_TIMER" ] && systemctl enable --now "$UNIDADE_SONDA" >/dev/null 2>&1
	aplica_firewall
	confere_ou_desfaz
	echo "==> ghop-balanceador ligado"
	comando_estado
}

comando_desligar() {
	# Esta e a saida de emergencia do operador: "se der merda, eu desligo".
	# Entao ela nao pode so TENTAR -- tem de desfazer tudo e CONFERIR que
	# desfez, porque metade desfeita e pior que nada: regra de politica em pe
	# com marca que ninguem poe manda trafego para uma tabela sem rota.
	#
	# A ordem importa. O temporizador sai primeiro, senao ele reaplica no meio
	# do caminho. Depois a marca (o fragmento sai do firewall), e so entao as
	# regras de politica -- ao contrario, haveria um instante com pacote
	# marcado e nenhuma regra que soubesse o que fazer com a marca.
	systemctl disable --now "$UNIDADE_SONDA" 2>/dev/null || true
	rm -f "$ARQ_NFT"
	[ -x "$REGRAS_FIREWALL" ] && systemctl restart "$UNIDADE_FIREWALL" || true
	[ -x "$ARQ_BALANCEADOR" ] && "$ARQ_BALANCEADOR" --remover || true
	systemctl disable --now "$UNIDADE" 2>/dev/null || true

	# Estado da quarentena e assinatura do que estava aplicado: sem apagar,
	# um 'ligar' logo em seguida acharia que nada mudou, ou deixaria placa
	# em quarentena de uma queda que ja passou.
	rm -f /var/ghop/balanceador-historico.json /var/ghop/balanceador-aplicado.json

	# Cinto e suspensorio: se sobrou regra de politica de alguma execucao
	# anterior (ou de um 'aplicar' interrompido), ela sai aqui.
	local marca
	for marca in 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8; do
		while ip rule show 2>/dev/null | grep -q "fwmark $marca"; do
			ip rule del fwmark "$marca" 2>/dev/null || break
		done
	done
	local tabela
	for tabela in 101 102 103 104 105 106 107 108; do
		ip route flush table "$tabela" 2>/dev/null || true
	done

	echo "==> ghop-balanceador desligado"

	# A conferencia, que e o que torna este comando confiavel.
	local sobrou=0
	local regras_politica
	regras_politica="$(ip rule show 2>/dev/null | grep -c fwmark || true)"
	if [ "${regras_politica:-0}" -ne 0 ]; then
		echo "    ATENCAO: sobraram $regras_politica regra(s) de politica com fwmark" >&2
		ip rule show | grep fwmark | sed 's/^/      /' >&2
		sobrou=1
	fi
	if nft list chain inet ghop_balanceador prerouting >/dev/null 2>&1; then
		echo "    ATENCAO: a cadeia de marcacao ainda esta no ruleset" >&2
		sobrou=1
	fi
	if [ -f "$ARQ_NFT" ]; then
		echo "    ATENCAO: o fragmento $ARQ_NFT ainda existe" >&2
		sobrou=1
	fi
	if [ "$sobrou" -eq 1 ]; then
		echo "    NAO confie: desfiz pela metade. Rode 'sudo bash /root/reverter.sh'." >&2
		return 1
	fi

	echo "    Conferido: nenhuma regra de politica, nenhuma marcacao no firewall."
	echo "    A LAN voltou a sair toda pela WAN principal."
	echo "    As placas e as regras ficaram em $DIR_BALANCEADOR, para o proximo 'ligar'."
	return 0
}

comando_recarregar() {
	# O caminho normal depois de o painel escrever regra nova: regera o
	# fragmento e reaplica as rotas, sem derrubar conexao nenhuma -- conexao
	# em curso guarda a escolha dela na propria marca de conntrack.
	systemctl restart "$UNIDADE"
	aplica_firewall
	confere_ou_desfaz
	echo "==> ghop-balanceador recarregado (regras e pesos relidos)"
}

comando_desinstalar() {
	comando_desligar
	rm -f "$ARQ_SERVICO" "$ARQ_BALANCEADOR" "$ARQ_SYSCTL" "$ARQ_UDEV" \
		"$ARQ_SONDA" "$ARQ_TIMER"
	rm -rf "$DIR_BALANCEADOR"
	systemctl daemon-reload
	udevadm control --reload >/dev/null 2>&1 || true
	# O arquivo .link NAO e apagado junto: ele so fixa um nome, e apagar
	# faria a placa USB voltar a trocar de nome -- quebrando a configuracao de
	# rede de quem passou a chamar a interface pelo nome fixado.
	echo "==> ghop-balanceador desinstalado"
	echo "    Ficaram os nomes fixados em $DIR_LINK/10-ghop-*.link"
	echo "    (apagar faria a placa USB voltar a trocar de nome)."
	echo "    O rp_filter volta ao padrao da distribuicao no proximo boot."
}

case "$ACAO" in
estado) comando_estado; exit 0 ;;
ligar) comando_ligar; exit 0 ;;
desligar) comando_desligar; exit 0 ;;
recarregar) comando_recarregar; exit 0 ;;
desinstalar) comando_desinstalar; exit 0 ;;
esac

# ---------------------------------------------------------------- instalar

if [ "$SEM_PERGUNTA" -eq 0 ]; then
	echo "Interfaces de rede desta maquina:"
	ip -brief addr | grep -v '^lo ' | sed 's/^/  /'
	echo
	echo "Rotas default de hoje:"
	ip route show default | sed 's/^/  /'
	echo
fi

# Com duas interfaces nao ha o que balancear: uma e a LAN e a outra e a saida.
if [ "$(interfaces | wc -l)" -lt 3 ]; then
	erro "esta maquina tem $(interfaces | wc -l) interface(s): $(interfaces | tr '\n' ' ').
      Balancear saida exige a LAN mais DUAS ou mais placas de saida.
      Com uma saida so, o papel nftables ja faz o que ha para fazer."
fi

LAN_SUGERIDA=""
[ -f "$ARQ_INTERFACE" ] && LAN_SUGERIDA="$(cat "$ARQ_INTERFACE")"
# A LAN e a mesma que o resto do GHop usa: quem manda e o papel nftables.
if [ -z "$LAN_SUGERIDA" ] && [ -f "$ARQ_INTERFACES_NFT" ]; then
	LAN_SUGERIDA="$(sed -n 's/^LAN_IF=//p' "$ARQ_INTERFACES_NFT" | tail -n1)"
fi
LAN_IF="$(perguntar "Interface INTERNA (LAN), cujo trafego sera decidido" "${LAN_IF:-$LAN_SUGERIDA}")"
[ -e "/sys/class/net/$LAN_IF" ] || erro "interface '$LAN_IF' nao existe. Disponiveis: $(interfaces | tr '\n' ' ')"

# As placas de saida. Nao interativo: GHOP_BALANCEADOR_PLACAS='nome:if:gw:peso ...'
declare -a PLACAS=()
if [ -n "${GHOP_BALANCEADOR_PLACAS:-}" ]; then
	for item in $GHOP_BALANCEADOR_PLACAS; do
		IFS=: read -r nome interface gateway peso <<< "$item"
		[ -n "$nome" ] && [ -n "$interface" ] && [ -n "$gateway" ] ||
			erro "GHOP_BALANCEADOR_PLACAS: '$item' nao e nome:if:gw[:peso]"
		PLACAS+=("$nome:$interface:$gateway:${peso:-1}")
	done
else
	echo
	echo "Agora as placas de SAIDA, uma por vez. Nome vazio encerra."
	echo "O nome e como o painel vai chamar a placa (minusculas, sem espaco);"
	echo "o peso e a proporcao do balanceamento -- 7 e 3 manda 70% e 30%."
	echo "Placa USB 2.0 nao segura o que uma gigabit segura: pese a favor da boa."
	while :; do
		echo
		nome="$(perguntar "Nome da placa (vazio encerra)" "")"
		[ -n "$nome" ] || break
		interface="$(perguntar "  interface de '$nome'" "")"
		[ -e "/sys/class/net/$interface" ] || erro "interface '$interface' nao existe."
		[ "$interface" != "$LAN_IF" ] || erro "'$interface' e a LAN; nao pode ser saida."
		# Sem rota default nesta interface (placa ainda sem cabo, ou que
		# pega endereco por DHCP), o padrao e 'auto': o gateway e aprendido
		# na hora de aplicar, e ate la a placa fica fora da rotacao. Melhor
		# que um numero inventado -- rota default para gateway errado nao da
		# erro, da trafego que sai e nao volta.
		sugestao="$(ip route show default dev "$interface" 2>/dev/null | awk '{print $3; exit}')"
		gateway="$(perguntar "  gateway de '$nome' ('auto' aprende da rota dela)" "${sugestao:-auto}")"
		[ -n "$gateway" ] || erro "a placa '$nome' precisa de gateway (ou 'auto')."
		peso="$(perguntar "  peso de '$nome'" "1")"
		PLACAS+=("$nome:$interface:$gateway:$peso")
	done
fi

[ "${#PLACAS[@]}" -ge 2 ] ||
	erro "informe pelo menos DUAS placas de saida; com uma nao ha balanceamento."

WAN_PRINCIPAL="$(sed -n 's/^WAN_IF=//p' "$ARQ_INTERFACES_NFT" 2>/dev/null | tail -n1 || true)"

echo
echo "Sera aplicado nesta maquina:"
echo "  decide o que entra por: $LAN_IF, e so para destino PUBLICO"
echo "  estagios            : lista por placa (a primeira que casa decide),"
echo "                        e o que sobra vai ao balanceamento"
echo "  placas de saida     :"
for item in "${PLACAS[@]}"; do
	IFS=: read -r nome interface gateway peso <<< "$item"
	marca_usb=""
	e_usb "$interface" && marca_usb="  [USB: nome sera preso ao MAC]"
	printf '      %-12s %-12s gw %-15s peso %s%s\n' "$nome" "$interface" "$gateway" "$peso" "$marca_usb"
done
echo "  regras              : $ARQ_REGRAS, escritas pelo painel"
echo "                        (sem regra nenhuma, TUDO vai ao balanceamento)"
echo "  algoritmo           : rodizio (o painel troca para 'afinidade' se quiser)"
echo "  firewall            : $ARQ_NFT, aplicado pelo papel nftables"
echo "  rotas               : uma tabela e uma regra de politica por placa"
echo "  rp_filter           : 2 (frouxo) em $ARQ_SYSCTL -- sem isso a resposta"
echo "                        que volta pela segunda placa e DESCARTADA"
echo "  hotplug             : $ARQ_UDEV reaplica quando placa cai ou volta"
echo "  sonda               : $SONDA -- placa com link e gateway que NAO passa"
echo "                        trafego sai da rotacao; a que sobrou leva tudo"
echo "  quarentena          : $QUARENTENA min -- a placa so VOLTA depois disso"
echo "                        (a queda e imediata; isto da estabilidade)"
echo "  temporizador        : $UNIDADE_SONDA, de minuto em minuto, e so reaplica"
echo "                        o firewall quando o conjunto de placas muda"
echo "  servico             : $UNIDADE (oneshot: aplica e sai, sem daemon)"
echo
echo "  IPv6 NAO e balanceado: sai pelo caminho normal, de proposito."
echo "  Nada fica no caminho do dado: quem marca e roteia e o kernel."
echo

if [ "$SEM_PERGUNTA" -eq 0 ]; then
	read -r -p "Confirma? [s/N]: " confirmacao </dev/tty
	case "$confirmacao" in
	s | S | sim | SIM) ;;
	*) echo "Cancelado."; exit 0 ;;
	esac
fi

echo
"$ORIGEM_SERVICE" balanceador

echo "==> Configuracao em $DIR_BALANCEADOR"
mkdir -p "$DIR_BALANCEADOR"
chmod 755 "$DIR_BALANCEADOR"
echo "$LAN_IF" > "$ARQ_INTERFACE"

{
	echo "# Gerado por projects/ghop-balanceador/balanceador.sh do GHop."
	echo "#"
	echo "# As placas de saida desta MAQUINA: nome, interface, gateway, peso."
	echo "# Interface e gateway sao fato local e nunca vem do painel -- o painel"
	echo "# conhece o NOME da placa, e e por ele que ele manda lista e peso."
	echo "# A ordem define a marca, a tabela de rota e a prioridade da regra."
	for item in "${PLACAS[@]}"; do
		IFS=: read -r nome interface gateway peso <<< "$item"
		if e_usb "$interface"; then
			fixa_nome "$interface" "$nome" >&2
			# Grava o nome FIXADO, nao o de hoje: e o que vai existir depois
			# do replug. Ate la a placa aparece sem carrier e fica fora da
			# rotacao, que e a degradacao certa.
			interface="$nome"
		fi
		printf 'nome=%s if=%s gw=%s peso=%s sonda=%s quarentena=%s\n' \
			"$nome" "$interface" "$gateway" "$peso" "$SONDA" "$QUARENTENA"
	done
} > "$ARQ_PLACAS"
chmod 644 "$ARQ_PLACAS"

if [ ! -f "$ARQ_REGRAS" ]; then
	# Vazio de proposito: papel recem-instalado nao prende nada a placa
	# nenhuma -- tudo vai ao balanceamento. Quem escreve aqui e o agente, com
	# campos que ele mesmo validou. Este arquivo e DADO, nunca texto de regra.
	cat > "$ARQ_REGRAS" <<'JSON'
{
  "versao": 1,
  "algoritmo": "rodizio",
  "placas": [],
  "regras": []
}
JSON
	echo "    $ARQ_REGRAS criado, sem regra nenhuma (tudo ao balanceamento)"
else
	echo "    $ARQ_REGRAS ja existe, preservado"
fi
chmod 644 "$ARQ_REGRAS"

echo "==> Instalando gerador em $ARQ_BALANCEADOR"
install -m 750 "$ORIGEM_BALANCEADOR" "$ARQ_BALANCEADOR"

echo "==> rp_filter frouxo em $ARQ_SYSCTL"
cat > "$ARQ_SYSCTL" <<SYSCTL
# Gerado por projects/ghop-balanceador/balanceador.sh do GHop.
#
# Com duas saidas e rota por politica, a resposta de uma conexao volta pela
# placa por onde ela saiu -- que NAO e a placa da rota default. Com rp_filter
# estrito (1) o kernel descarta essa resposta, e o sintoma e "a segunda placa
# nao funciona". 2 e o modo frouxo: ainda barra origem sem rota nenhuma, mas
# aceita a que tem rota por outra interface.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
SYSCTL
sysctl -q --system || true

echo "==> Servico em $ARQ_SERVICO"
cat > "$ARQ_SERVICO" <<SERVICO
[Unit]
Description=GHop - escolha de saida: lista por placa e balanceamento de carga
After=network.target ghop-nftables.service
Wants=network-online.target

[Service]
# Oneshot, e nao daemon: nao ha nada para vigiar em laco -- quem marca e
# roteia e o kernel. Quando placa cai ou volta, quem reaplica e o udev.
Type=oneshot
RemainAfterExit=yes
ExecStart=$ARQ_BALANCEADOR --aplicar
ExecStop=$ARQ_BALANCEADOR --remover
Environment=GHOP_BALANCEADOR_PRINCIPAL=$WAN_PRINCIPAL

[Install]
WantedBy=multi-user.target
SERVICO

echo "==> Sonda periodica em $ARQ_TIMER"
# Unidade PROPRIA, e nao o timer apontando para ghop-balanceador.service:
# aquela e oneshot com RemainAfterExit=yes, e mandar 'start' numa unidade ja
# ativa assim e um no-op silencioso -- a sonda nunca rodaria.
cat > "$ARQ_SONDA" <<SONDA_UNIT
[Unit]
Description=GHop - reavalia as placas do balanceador (sonda e quarentena)
After=ghop-balanceador.service

[Service]
Type=oneshot
ExecStart=$ARQ_BALANCEADOR --aplicar
SONDA_UNIT
cat > "$ARQ_TIMER" <<TIMER_UNIT
[Unit]
Description=GHop - sonda das placas do balanceador

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s
Unit=ghop-balanceador-sonda.service

[Install]
WantedBy=timers.target
TIMER_UNIT

echo "==> Hotplug em $ARQ_UDEV"
cat > "$ARQ_UDEV" <<UDEV
# Gerado por projects/ghop-balanceador/balanceador.sh do GHop.
#
# Placa USB cai e volta -- cabo, porta, driver. Quando isso acontece a rota
# dela desaparece, e placa sem carrier que ficasse na rotacao mandaria parte
# do trafego da LAN para um buraco negro. Reaplicar no evento e o que tira
# (e devolve) a placa sozinha, sem processo nenhum vigiando em laco.
# So interface de VERDADE: sem isto, cada veth de conteiner, cada tap de VM e
# cada interface de teste reinicia o balanceador -- e reiniciar remove e
# recoloca as regras de politica, o que em maquina movimentada vira tranco
# constante na rede. ENV{DEVTYPE} vazio e placa fisica; veth/bridge/tun tem
# DEVTYPE proprio.
SUBSYSTEM=="net", ACTION=="add|remove|change", ENV{DEVTYPE}=="", RUN+="/usr/bin/systemctl --no-block restart $UNIDADE"
UDEV
udevadm control --reload >/dev/null 2>&1 || true

comando_ligar

echo
echo "==> Concluido"
printf 'decide         %s -> %s placa(s)\n' "$LAN_IF" "${#PLACAS[@]}"
printf 'regras         %s\n' "$ARQ_REGRAS"
printf 'algoritmo      %s\n' "rodizio"
echo
echo "Ver o que foi montado, sem adivinhar:"
echo "  sudo $ARQ_BALANCEADOR --estado"
echo "Conferir por qual placa um destino sairia:"
echo "  sudo $ARQ_BALANCEADOR --testar 203.0.113.9"
echo "Desligar sem desinstalar (volta a sair toda pela WAN principal):"
echo "  sudo $0 desligar"
