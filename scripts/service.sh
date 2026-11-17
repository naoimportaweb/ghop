#!/bin/bash
#
# service.sh - prepara uma maquina Debian para ser um elemento do GHop.
#
# Instala os pacotes do papel pedido, a configuracao comum
# (/etc/ghop/ghop.conf) e o diretorio de dados (/var/ghop). E chamado pelos
# instaladores especificos -- lojmIt.sh, requests.sh -- e pode ser chamado
# direto quando a maquina nao for um lojmIt.
#
# Uso: sudo ./scripts/service.sh <papel> [<papel>...]
#
# Papeis:
#   lojmIt   roteia e filtra a rede
#   agente   observa a maquina e, no futuro, age sobre ela
#   dns      resolvedor da LAN, cifrado para cima, com lista de negacao
#   wifi     ponto de acesso na placa sem fio, em bridge com a LAN
#   dhcp     servidor DHCP da LAN: endereco, roteador e resolvedor
#   nftables firewall e NAT: o dono do ruleset desta maquina
#   balanceador  escolha de saida: lista por placa e balanceamento de carga
#   painel   a sua maquina: fala com os agentes e guarda a CA
#
# Um papel nao exclui o outro: um lojmIt observado e 'lojmIt agente'.

set -euo pipefail

# Comum a qualquer elemento.
PACOTES_BASE=(
	ca-certificates # raizes de confianca do sistema
	openssl         # geracao e verificacao de certificados
	python3         # linguagem dos servicos do GHop
)

PACOTES_LOJMIT=(
	nftables # firewall e NAT
	tcpdump  # captura de trafego de rede
)

# O dono do ruleset. Papel proprio desde que o firewall saiu do lojmIt.sh.
PACOTES_NFTABLES=(
	nftables # o firewall em si
)

PACOTES_AGENTE=(
	tcpdump # captura de trafego de rede
	sqlite3 # consulta aos bancos coletados
)

# Resolvedor da LAN, cifrado para cima. Papel opcional, liga e desliga.
PACOTES_DNS=(
	dnscrypt-proxy # resolvedor DNSCrypt/DoH com lista de negacao
	nftables       # a regra da 53 e escrita em /etc/ghop/nft.d
)

# Servidor DHCP da LAN. Papel opcional, liga e desliga.
PACOTES_DHCP=(
	isc-dhcp-server # servidor DHCP
	nftables        # a regra da 67 e escrita em /etc/ghop/nft.d
)

# Filtro de camada de aplicacao (SNI e Host). Papel opcional, liga e desliga.
# O programa e Python 3 puro, da biblioteca padrao: nada a instalar alem do
# que a base ja traz. O nftables entra porque o redirecionamento das portas
# 80 e 443 e escrito em /etc/ghop/nft.d.
PACOTES_FILTRO=(
	nftables # o redirecionamento e escrito em /etc/ghop/nft.d
)

# Escolha de saida: por qual placa cada conexao da LAN vai para fora. Papel
# opcional, liga e desliga. O gerador e Python 3 puro da biblioteca padrao; o
# iproute2 entra porque sao as tabelas de rota e as regras de politica que
# fazem a marca do nftables virar caminho, e o nftables porque o fragmento que
# marca as conexoes e escrito em /etc/ghop/nft.d.
PACOTES_BALANCEADOR=(
	iproute2 # 'ip rule' e 'ip route table': a marca vira caminho
	nftables # a marcacao e escrita em /etc/ghop/nft.d
)

# Ponto de acesso Wi-Fi em bridge com a LAN. Papel opcional, liga e desliga.
PACOTES_WIFI=(
	hostapd      # o ponto de acesso
	bridge-utils # 'bridge_ports' no /etc/network/interfaces
	iw           # consulta ao driver: modo AP, canais, clientes
)

# So o painel manuseia a YubiKey. O agente nao precisa de nada da Yubico:
# ele valida o certificado do painel contra a CA, o que e OpenSSL puro.
# Instalar essas ferramentas numa maquina que se observa seria dar
# ferramenta a quem invadir, sem ganho algum.
PACOTES_PAINEL=(
	yubikey-manager # ykman: PIN, PUK, reset e slots do PIV
	yubico-piv-tool # emissao e importacao de certificado no PIV
	opensc          # camada PKCS#11 para a chave em hardware
	pcscd           # daemon de leitora de smartcard
	# A base de OUI da IEEE, que traduz os tres primeiros bytes de um MAC no
	# fabricante. Fica SO no painel, e de proposito: a traducao e do lado de
	# quem olha, como a classificacao branca/negra -- o agente entrega o MAC
	# cru. Consulta local, sem um pedido de rede, que e o que permite ter
	# fabricante sem ferir o "nada consulta sozinho".
	ieee-data # /usr/share/ieee-data/oui.csv
)

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEM_CONFIG="$DIR_SCRIPT/../config/ghop.conf"
DIR_CONFIG=/etc/ghop
ARQ_CONFIG="$DIR_CONFIG/ghop.conf"
DIR_DADOS=/var/ghop

if [ "$#" -eq 0 ]; then
	echo "Uso: sudo $0 <papel> [<papel>...]" >&2
	echo "Papeis: lojmIt, agente, dns, wifi, dhcp, filtro, balanceador, nftables, painel" >&2
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "Erro: execute como root (sudo $0 $*)." >&2
	exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
	echo "Erro: apt-get nao encontrado; este script e para Debian." >&2
	exit 1
fi

if [ ! -f "$ORIGEM_CONFIG" ]; then
	echo "Erro: $ORIGEM_CONFIG nao encontrado." >&2
	echo "      Copie o repositorio inteiro para esta maquina, nao so este script." >&2
	exit 1
fi

pacotes=("${PACOTES_BASE[@]}")
for papel in "$@"; do
	case "$papel" in
	lojmIt) pacotes+=("${PACOTES_LOJMIT[@]}") ;;
	agente) pacotes+=("${PACOTES_AGENTE[@]}") ;;
	dns) pacotes+=("${PACOTES_DNS[@]}") ;;
	wifi) pacotes+=("${PACOTES_WIFI[@]}") ;;
	dhcp) pacotes+=("${PACOTES_DHCP[@]}") ;;
	filtro) pacotes+=("${PACOTES_FILTRO[@]}") ;;
	balanceador) pacotes+=("${PACOTES_BALANCEADOR[@]}") ;;
	nftables) pacotes+=("${PACOTES_NFTABLES[@]}") ;;
	painel) pacotes+=("${PACOTES_PAINEL[@]}") ;;
	*)
		echo "Erro: papel desconhecido '$papel'." >&2
		echo "      Papeis validos: lojmIt, agente, dns, wifi, dhcp, filtro, balanceador, nftables, painel" >&2
		exit 1
		;;
	esac
done

# Um pacote pode aparecer em mais de um papel.
mapfile -t pacotes < <(printf '%s\n' "${pacotes[@]}" | sort -u)

export DEBIAN_FRONTEND=noninteractive

echo "==> Papeis: $*"
echo "==> Instalando: ${pacotes[*]}"
apt-get update
apt-get install -y --no-install-recommends "${pacotes[@]}"

echo "==> Configuracao em $ARQ_CONFIG"
mkdir -p "$DIR_CONFIG"
if [ -f "$ARQ_CONFIG" ]; then
	echo "    ja existe, preservado"
else
	install -m 640 "$ORIGEM_CONFIG" "$ARQ_CONFIG"
	echo "    instalado"
fi

echo "==> Diretorio de dados em $DIR_DADOS"
mkdir -p "$DIR_DADOS"
chmod 750 "$DIR_DADOS"

echo "==> Pacotes instalados"
for pacote in "${pacotes[@]}"; do
	printf '    %-16s %s\n' "$pacote" \
		"$(dpkg-query -W -f='${Version}' "$pacote" 2>/dev/null || echo 'NAO INSTALADO')"
done
