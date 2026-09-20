#!/bin/bash
#
# wifi.sh - instala e liga o ghop-wifi: a placa Wi-Fi do lojmIt vira ponto
# de acesso, e o radio entra na MESMA LAN do cabo por uma bridge.
#
# A bridge e a decisao central. Com ela o Wi-Fi nao e uma rede nova: e mais
# uma porta da LAN que ja existe. O DHCP, o ghop-dns, a regra da 53 e o
# coletor continuam valendo sem duplicar nada -- so trocam de interface, da
# do cabo para a da bridge. Cada celular ou tablet que entra pelo radio vira
# um cliente da LAN com IP e MAC proprios, visivel na monitoracao e no DNS,
# que e exatamente o que se quer observar.
#
# Consequencia: depois deste script, a LAN do lojmIt E A BRIDGE. Os outros
# papeis devem ser (re)instalados com LAN_IF=<bridge>; o install.sh faz isso
# na ordem certa quando 'wifi' vem junto dos demais.
#
# Este papel LIGA E DESLIGA: 'desligar' apaga o radio (hostapd) e so; a
# bridge fica, porque ela e a LAN agora e o cabo continua passando por ela.
#
# Uso interativo:      sudo ./projects/ghop-wifi/wifi.sh            (instala e liga)
# Uso nao interativo:  sudo WIFI_IF=wlp2s0 CABO_IF=enp3s0 GHOP_WIFI_SSID=ghop \
#                           GHOP_WIFI_SENHA=... ./projects/ghop-wifi/wifi.sh --sim
# Depois:              sudo ./projects/ghop-wifi/wifi.sh desligar | ligar | estado

set -euo pipefail
# Com set -e um comando que falha encerra o script; sem isto, encerra calado.
trap 'echo "Erro: $0 parou na linha $LINENO (comando: $BASH_COMMAND)" >&2' ERR

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEM_SERVICE="$DIR_SCRIPT/../../scripts/service.sh"
DIR_CONFIG=/etc/ghop
DIR_WIFI="$DIR_CONFIG/wifi"
ARQ_ESTADO="$DIR_WIFI/interfaces"
ARQ_HOSTAPD=/etc/hostapd/hostapd.conf
ARQ_DEFAULT_HOSTAPD=/etc/default/hostapd
DIR_DROPIN=/etc/systemd/system/hostapd.service.d
ARQ_DROPIN="$DIR_DROPIN/ghop.conf"
ARQ_INTERFACES=/etc/network/interfaces
ARQ_REGDOM=/etc/modprobe.d/ghop-wifi.conf
ARQ_DHCP_DEFAULT=/etc/default/isc-dhcp-server
IW=/usr/sbin/iw
PONTE_IF="${PONTE_IF:-br0}"

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

sem_fio() {
	local i
	for i in $(interfaces); do
		[ -d "/sys/class/net/$i/wireless" ] && echo "$i"
	done
	return 0
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

perguntar_senha() {
	local resposta
	if [ "$SEM_PERGUNTA" -eq 1 ]; then
		echo "${GHOP_WIFI_SENHA:-}"
		return
	fi
	read -r -s -p "Senha do Wi-Fi (8 a 63 caracteres; vazio sorteia uma): " resposta </dev/tty
	echo >&2
	echo "${resposta:-${GHOP_WIFI_SENHA:-}}"
}

comando_estado() {
	echo "ghop-wifi"
	printf '  %-24s %s / %s\n' "hostapd.service" \
		"$(systemctl is-active hostapd 2>/dev/null || true)" \
		"$(systemctl is-enabled hostapd 2>/dev/null || true)"
	if [ -f "$ARQ_ESTADO" ]; then
		# shellcheck disable=SC1090
		. "$ARQ_ESTADO"
		printf '  %-24s %s\n' "ssid" "$(sed -n 's/^ssid=//p' "$ARQ_HOSTAPD" 2>/dev/null)"
		printf '  %-24s %s (canal %s)\n' "radio" "$WIFI_IF" "$(sed -n 's/^channel=//p' "$ARQ_HOSTAPD" 2>/dev/null)"
		printf '  %-24s %s = %s\n' "bridge" "$PONTE_IF" \
			"$(ls "/sys/class/net/$PONTE_IF/brif" 2>/dev/null | tr '\n' ' ' || true)"
		printf '  %-24s %s\n' "endereco" "$(ip -4 -o addr show dev "$PONTE_IF" 2>/dev/null | awk '{print $4}' || true)"
		if [ -x "$IW" ]; then
			printf '  %-24s %s\n' "clientes no radio" \
				"$($IW dev "$WIFI_IF" station dump 2>/dev/null | grep -c '^Station' || true)"
		fi
	fi
	return 0
}

comando_ligar() {
	[ -f "$ARQ_HOSTAPD" ] && [ -f "$ARQ_ESTADO" ] ||
		erro "ghop-wifi ainda nao foi instalado aqui. Rode: sudo $0"
	systemctl unmask hostapd 2>/dev/null || true
	systemctl daemon-reload
	systemctl enable hostapd
	systemctl restart hostapd
	echo "==> ghop-wifi ligado"
	comando_estado
}

comando_desligar() {
	systemctl disable --now hostapd 2>/dev/null || true
	echo "==> ghop-wifi desligado: radio apagado"
	echo "    A bridge $PONTE_IF fica: ela e a LAN agora, e o cabo passa por ela."
	comando_estado
}

comando_desinstalar() {
	# O mais perigoso dos tres: desfazer a bridge MEXE NA REDE da maquina, e
	# os outros papeis apontam para ela. Por isso o aviso no fim -- sem
	# reinstalar dhcp e agente, eles ficam olhando uma interface que sumiu.
	local cabo="" ponte="$PONTE_IF"
	if [ -f "$ARQ_ESTADO" ]; then
		# shellcheck disable=SC1090
		. "$ARQ_ESTADO"
		cabo="${CABO_IF:-}"
		ponte="${PONTE_IF:-br0}"
	fi
	systemctl disable --now hostapd 2>/dev/null || true
	rm -f "$ARQ_DROPIN"
	rmdir "$DIR_DROPIN" 2>/dev/null || true
	rm -f "$ARQ_HOSTAPD" "$ARQ_REGDOM"

	if [ -f "$ARQ_INTERFACES.anterior-ghop" ]; then
		echo "==> Desfazendo a bridge (a LAN cai por alguns segundos)"
		ifdown "$ponte" 2>/dev/null || true
		ip link del "$ponte" 2>/dev/null || true
		mv "$ARQ_INTERFACES.anterior-ghop" "$ARQ_INTERFACES"
		[ -n "$cabo" ] && ifup "$cabo" 2>/dev/null || true
		echo "    $ARQ_INTERFACES restaurado ao que havia antes do GHop"
	fi
	rm -rf "$DIR_WIFI"
	systemctl daemon-reload
	echo "==> ghop-wifi desinstalado"
	echo "    Ficou: o pacote hostapd."
	if [ -n "$cabo" ]; then
		echo "    A LAN voltou a ser $cabo. REINSTALE os papeis que apontavam"
		echo "    para $ponte, senao ficam presos a uma interface que nao existe:"
		echo "      sudo LAN_IF=$cabo ./install.sh lojmIt dns dhcp agente --sim"
	fi
}

case "$ACAO" in
estado) comando_estado; exit 0 ;;
ligar) comando_ligar; exit 0 ;;
desligar) comando_desligar; exit 0 ;;
desinstalar) comando_desinstalar; exit 0 ;;
esac

# ---------------------------------------------------------------- instalar

# So se sabe montar bridge persistente no ifupdown. Com systemd-networkd ou
# NetworkManager o arquivo certo e outro, e adivinhar aqui quebraria a rede.
[ -f "$ARQ_INTERFACES" ] && systemctl is-enabled networking >/dev/null 2>&1 ||
	erro "esta maquina nao usa ifupdown ($ARQ_INTERFACES + networking.service).
      O ghop-wifi so sabe persistir a bridge nesse arranjo."

if [ "$SEM_PERGUNTA" -eq 0 ]; then
	echo "Interfaces de rede desta maquina:"
	ip -brief addr | grep -v '^lo ' | sed 's/^/  /'
	echo
fi

WAN_SUGERIDA="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
WIFI_SUGERIDA="$(sem_fio | head -n1 || true)"
[ -n "$WIFI_SUGERIDA" ] || erro "nenhuma interface sem fio nesta maquina."

# Se ja ha bridge nossa, o cabo e o que esta dentro dela; senao, a interface
# com fio que nao e a WAN.
CABO_SUGERIDO=""
if [ -f "$ARQ_ESTADO" ]; then
	# shellcheck disable=SC1090
	. "$ARQ_ESTADO"
	CABO_SUGERIDO="${CABO_IF:-}"
fi
if [ -z "$CABO_SUGERIDO" ]; then
	for i in $(interfaces); do
		case "$i" in "$WAN_SUGERIDA" | "$WIFI_SUGERIDA" | "$PONTE_IF") continue ;; esac
		[ -d "/sys/class/net/$i/wireless" ] && continue
		[ -d "/sys/class/net/$i/bridge" ] && continue
		CABO_SUGERIDO="$i"
		break
	done
fi

WIFI_IF="$(perguntar "Interface SEM FIO (vira ponto de acesso)" "${WIFI_IF:-$WIFI_SUGERIDA}")"
CABO_IF="$(perguntar "Interface da LAN COM FIO (entra na bridge com o radio)" "${CABO_IF:-$CABO_SUGERIDO}")"

[ -d "/sys/class/net/$WIFI_IF/wireless" ] || erro "'$WIFI_IF' nao e uma interface sem fio."
[ -e "/sys/class/net/$CABO_IF" ] || erro "interface '$CABO_IF' nao existe."
[ "$CABO_IF" != "$WAN_SUGERIDA" ] || erro "'$CABO_IF' e a interface de saida para a internet, nao a LAN."
[ "$CABO_IF" != "$WIFI_IF" ] || erro "cabo e radio nao podem ser a mesma interface."

# O driver tem de anunciar modo AP; sem isso o hostapd sobe e morre.
[ -x "$IW" ] || apt-get install -y -qq iw >/dev/null 2>&1 || true
[ -x "$IW" ] || erro "iw nao esta instalado e nao consegui instala-lo."
if ! $IW phy "$(cat "/sys/class/net/$WIFI_IF/phy80211/name")" info | grep -qE '^\s+\* AP$'; then
	erro "o driver de '$WIFI_IF' nao anuncia o modo AP. Esta placa nao serve de ponto de acesso."
fi

# O endereco da LAN sai do cabo (ou da bridge, na reinstalacao) e vai para a
# bridge. E o mesmo IP: para o resto da rede nada muda.
# '|| true' porque a bridge pode nao existir ainda, e 'ip' falhando dentro
# da substituicao derrubaria o script pelo pipefail.
LAN_ADDR="$(ip -4 -o addr show dev "$PONTE_IF" 2>/dev/null | awk '{print $4; exit}' || true)"
LAN_ADDR="${LAN_ADDR:-$(ip -4 -o addr show dev "$CABO_IF" 2>/dev/null | awk '{print $4; exit}' || true)}"
[ -n "$LAN_ADDR" ] || erro "'$CABO_IF' nao tem endereco IPv4; configure a LAN antes."
LAN_IP="${LAN_ADDR%/*}"
LAN_PREFIXO="${LAN_ADDR#*/}"
CABO_MAC="$(cat "/sys/class/net/$CABO_IF/address")"

SSID="$(perguntar "Nome da rede (SSID)" "${GHOP_WIFI_SSID:-ghop}")"
[ -n "$SSID" ] && [ "${#SSID}" -le 32 ] || erro "SSID vazio ou com mais de 32 caracteres."

SENHA="$(perguntar_senha)"
SENHA_SORTEADA=0
if [ -z "$SENHA" ]; then
	SENHA="$(tr -dc 'a-hj-np-z2-9' </dev/urandom | head -c 16 || true)"
	SENHA_SORTEADA=1
fi
[ "${#SENHA}" -ge 8 ] && [ "${#SENHA}" -le 63 ] || erro "a senha WPA2 tem de ter entre 8 e 63 caracteres."

PAIS="$(perguntar "Pais (dominio regulatorio, 2 letras)" "${GHOP_WIFI_PAIS:-BR}")"
PAIS="$(echo "$PAIS" | tr '[:lower:]' '[:upper:]')"
[[ "$PAIS" =~ ^[A-Z]{2}$ ]] || erro "pais invalido '$PAIS'."

# 2,4 GHz e o padrao: alcance maior e e a banda em que o rtw88 em modo AP
# tem menos relatos de queda. 5 GHz e mais rapido e mais limpo; canal 36 e o
# que nao exige DFS.
BANDA="$(perguntar "Banda (2.4 ou 5)" "${GHOP_WIFI_BANDA:-2.4}")"
case "$BANDA" in
2.4) HW_MODE=g; CANAL_PADRAO=6 ;;
5) HW_MODE=a; CANAL_PADRAO=36 ;;
*) erro "banda invalida '$BANDA' (2.4 ou 5)." ;;
esac
CANAL="$(perguntar "Canal" "${GHOP_WIFI_CANAL:-$CANAL_PADRAO}")"
[[ "$CANAL" =~ ^[0-9]+$ ]] || erro "canal invalido '$CANAL'."

# O DHCP da LAN, se existir, tem de mudar para a bridge, senao ele para de
# ver a sub-rede e ninguem mais recebe endereco.
DHCP_AJUSTAR=0
if [ -f "$ARQ_DHCP_DEFAULT" ] && grep -q "^INTERFACESv4=.*\b$CABO_IF\b" "$ARQ_DHCP_DEFAULT"; then
	DHCP_AJUSTAR=1
fi

echo
echo "Sera aplicado nesta maquina:"
echo "  ponto de acesso     : $WIFI_IF, SSID '$SSID', $BANDA GHz canal $CANAL, pais $PAIS, WPA2"
echo "  bridge              : $PONTE_IF = $CABO_IF + $WIFI_IF, com $LAN_ADDR (era de $CABO_IF)"
echo "  ATENCAO             : a LAN passa a ser $PONTE_IF; lojmIt, dns e agente devem"
echo "                        ser (re)instalados com LAN_IF=$PONTE_IF -- o install.sh faz isso"
echo "  ifupdown            : $ARQ_INTERFACES (copia em $ARQ_INTERFACES.anterior-ghop)"
[ "$DHCP_AJUSTAR" -eq 1 ] &&
	echo "  dhcp                : $ARQ_DHCP_DEFAULT passa de $CABO_IF para $PONTE_IF"
echo "  regulatorio         : $ARQ_REGDOM (cfg80211 ieee80211_regdom=$PAIS)"
echo "  hostapd             : $ARQ_HOSTAPD (a senha fica so ali, modo 600)"
echo "  pacotes             : os do papel 'wifi' (ver scripts/service.sh)"
echo "  desconecta          : a LAN cai por alguns segundos enquanto o endereco muda de interface"
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
"$ORIGEM_SERVICE" wifi

echo "==> Dominio regulatorio $PAIS em $ARQ_REGDOM"
echo "options cfg80211 ieee80211_regdom=$PAIS" > "$ARQ_REGDOM"
$IW reg set "$PAIS" 2>/dev/null || true

echo "==> Ponto de acesso em $ARQ_HOSTAPD"
mkdir -p "$(dirname "$ARQ_HOSTAPD")"
{
	cat <<HOSTAPD
# Gerado por projects/ghop-wifi/wifi.sh do GHop. Alteracoes manuais serao sobrescritas.
interface=$WIFI_IF
# O hostapd poe o radio dentro da bridge ao subir; e ele quem sabe a hora,
# porque interface sem fio so entra em bridge depois de virar AP.
bridge=$PONTE_IF
driver=nl80211
ssid=$SSID
country_code=$PAIS
ieee80211d=1
hw_mode=$HW_MODE
channel=$CANAL
ieee80211n=1
wmm_enabled=1
HOSTAPD
	if [ "$HW_MODE" = "a" ]; then
		cat <<HOSTAPD
ieee80211ac=1
# Largura de 20 MHz: e o que o rtw88 em modo AP segura sem cair.
vht_oper_chwidth=0
HOSTAPD
	fi
	cat <<HOSTAPD
# WPA2-PSK com CCMP. Sem WPA (TKIP), que e quebrado; sem WPA3 por ora,
# porque o SAE no rtw88 em modo AP ainda nao e confiavel.
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=$SENHA
ignore_broadcast_ssid=0
macaddr_acl=0
# Clientes do radio se enxergam, como no cabo: e uma LAN so, de proposito.
ap_isolate=0
HOSTAPD
} > "$ARQ_HOSTAPD"
chmod 600 "$ARQ_HOSTAPD"

if [ -f "$ARQ_DEFAULT_HOSTAPD" ]; then
	sed -i "s|^#\?DAEMON_CONF=.*|DAEMON_CONF=\"$ARQ_HOSTAPD\"|" "$ARQ_DEFAULT_HOSTAPD"
	grep -q "^DAEMON_CONF=" "$ARQ_DEFAULT_HOSTAPD" || echo "DAEMON_CONF=\"$ARQ_HOSTAPD\"" >> "$ARQ_DEFAULT_HOSTAPD"
fi

echo "==> Servico em $ARQ_DROPIN"
mkdir -p "$DIR_DROPIN"
cat > "$ARQ_DROPIN" <<DROPIN
# Gerado por projects/ghop-wifi/wifi.sh do GHop.
[Unit]
# A bridge e do ifupdown; o radio so pode entrar nela depois que ela existe.
After=networking.service
Wants=networking.service

[Service]
# O rtw88 em modo AP as vezes cai; melhor voltar sozinho que ficar mudo.
Restart=on-failure
RestartSec=5
DROPIN

echo "==> Bridge $PONTE_IF em $ARQ_INTERFACES"
[ -f "$ARQ_INTERFACES.anterior-ghop" ] || cp -a "$ARQ_INTERFACES" "$ARQ_INTERFACES.anterior-ghop"
# Tira a estrofe do cabo e a nossa anterior (se houver), preservando o resto.
# Uma estrofe vai de 'auto/allow-/iface X' ate a proxima linha dessas.
awk -v cabo="$CABO_IF" -v ponte="$PONTE_IF" '
	/^(auto|allow-[a-z]+|iface) / {
		pular = ($2 == cabo || $2 == ponte)
	}
	/^# ghop-wifi/ { pular = 1 }
	!pular { print }
' "$ARQ_INTERFACES" > "$ARQ_INTERFACES.novo"
cat >> "$ARQ_INTERFACES.novo" <<INTERFACES

# ghop-wifi: a LAN e a bridge. O cabo entra nela aqui; o radio entra pelo
# hostapd. O endereco e o mesmo que o cabo tinha, para a rede nao perceber.
auto $CABO_IF
iface $CABO_IF inet manual

auto $PONTE_IF
iface $PONTE_IF inet static
    address $LAN_IP/$LAN_PREFIXO
    bridge_ports $CABO_IF
    bridge_stp off
    bridge_fd 0
    bridge_maxwait 0
    hwaddress ether $CABO_MAC
INTERFACES
mv "$ARQ_INTERFACES.novo" "$ARQ_INTERFACES"

mkdir -p "$DIR_WIFI"
chmod 700 "$DIR_WIFI"
cat > "$ARQ_ESTADO" <<ESTADO
WIFI_IF=$WIFI_IF
CABO_IF=$CABO_IF
PONTE_IF=$PONTE_IF
ESTADO

if [ "$DHCP_AJUSTAR" -eq 1 ]; then
	echo "==> DHCP: $ARQ_DHCP_DEFAULT de $CABO_IF para $PONTE_IF"
	sed -i "s/^INTERFACESv4=.*/INTERFACESv4=\"$PONTE_IF\"/" "$ARQ_DHCP_DEFAULT"
fi

echo "==> Subindo a bridge (a LAN cai por alguns segundos)"
# Se ja existe bridge de uma instalacao anterior, derruba antes de refazer.
if [ -d "/sys/class/net/$PONTE_IF" ]; then
	systemctl stop hostapd 2>/dev/null || true
	ifdown "$PONTE_IF" 2>/dev/null || ip link set "$PONTE_IF" down 2>/dev/null || true
	ip link del "$PONTE_IF" 2>/dev/null || true
fi
# O ifdown do cabo, ja com a estrofe 'manual', nao tira o endereco antigo;
# sem o flush o mesmo IP ficaria no cabo e na bridge, e o kernel responderia
# ora por um, ora por outro.
ifdown "$CABO_IF" 2>/dev/null || true
ip addr flush dev "$CABO_IF"
ifup "$CABO_IF"
ifup "$PONTE_IF"

if [ "$DHCP_AJUSTAR" -eq 1 ]; then
	systemctl restart isc-dhcp-server
fi

comando_ligar

echo
echo "==> Concluido"
printf 'rede           %s (%s GHz, canal %s)\n' "$SSID" "$BANDA" "$CANAL"
if [ "$SENHA_SORTEADA" -eq 1 ]; then
	printf 'senha          %s  (sorteada; esta em %s)\n' "$SENHA" "$ARQ_HOSTAPD"
else
	printf 'senha          (a informada; esta em %s)\n' "$ARQ_HOSTAPD"
fi
printf 'LAN            %s = %s + %s, %s\n' "$PONTE_IF" "$CABO_IF" "$WIFI_IF" "$LAN_ADDR"
printf 'hostapd        %s\n' "$(systemctl is-active hostapd)"
echo
echo "A LAN agora e $PONTE_IF. Reinstale os outros papeis apontando para ela:"
echo "  sudo LAN_IF=$PONTE_IF ./install.sh lojmIt dns agente --sim"
