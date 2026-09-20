#!/bin/bash
#
# dns.sh - instala e liga o ghop-dns nesta maquina: o resolvedor da LAN,
# cifrado para cima (dnscrypt-proxy) e com lista de negacao propria.
#
# Os clientes da LAN continuam perguntando em claro ao lojmIt -- e o que o
# coletor le na entrada da LAN. Daqui para cima a pergunta sai cifrada
# (DNSCrypt ou DoH), e o provedor deixa de ver os nomes. Dominio que esteja
# em /etc/ghop/dns/negados.txt recebe REFUSED e a tentativa fica em
# /var/log/dnscrypt-proxy/bloqueados.log.
#
# Este papel LIGA E DESLIGA sem tocar no resto: e um servico a mais, e nada
# no GHop depende dele. 'desligar' para o resolvedor e tira a regra de
# firewall; a configuracao e as listas ficam para o proximo 'ligar'.
#
# Uso interativo:      sudo ./projects/ghop-dns/dns.sh            (instala e liga)
# Uso nao interativo:  sudo LAN_IF=enp3s0 ./projects/ghop-dns/dns.sh --sim
# Depois:              sudo ./projects/ghop-dns/dns.sh desligar | ligar | estado | recarregar

set -euo pipefail

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEM_SERVICE="$DIR_SCRIPT/../../scripts/service.sh"
DIR_CONFIG=/etc/ghop
DIR_DNS="$DIR_CONFIG/dns"
ARQ_NEGADOS="$DIR_DNS/negados.txt"
ARQ_PERMITIDOS="$DIR_DNS/permitidos.txt"
# O dnscrypt-proxy le UM arquivo de cada especie. Varias listas so existem
# porque estes dois sao GERADOS: cada lista e um arquivo em negados.d/ ou
# permitidos.d/, e o agente concatena as ativas. Assim da para ter a lista
# propria ao lado de listas coladas pelo operador, ligando e desligando cada
# uma sem perder as outras.
DIR_NEGADOS="$DIR_DNS/negados.d"
DIR_PERMITIDOS="$DIR_DNS/permitidos.d"
ARQ_LISTAS="$DIR_DNS/listas.json"
ARQ_INTERFACE="$DIR_DNS/interface"
DIR_NFT="$DIR_CONFIG/nft.d"
ARQ_NFT="$DIR_NFT/dns.sh"
ARQ_TOML=/etc/dnscrypt-proxy/dnscrypt-proxy.toml
DIR_SOCKET=/etc/systemd/system/dnscrypt-proxy.socket.d
ARQ_SOCKET="$DIR_SOCKET/ghop.conf"
DIR_SERVICO=/etc/systemd/system/dnscrypt-proxy.service.d
ARQ_SERVICO="$DIR_SERVICO/ghop.conf"
# A espera pelo IP da LAN roda no ExecStartPre do socket; como todo o resto
# do GHop, o que roda e o PUBLICADO, nao o do repositorio.
ORIGEM_ESPERA="$DIR_SCRIPT/espera-lan.sh"
ARQ_ESPERA=/usr/local/sbin/ghop-dns-espera.sh
ESPERA_SEGUNDOS=30
ARQ_LOG_BLOQUEIO=/var/log/dnscrypt-proxy/bloqueados.log
# Quem aplica o ruleset e o papel nftables; o caminho antigo fica como
# reserva para maquina que ainda nao migrou.
REGRAS_FIREWALL=/usr/local/sbin/ghop-nftables.sh
UNIDADE_FIREWALL=ghop-nftables.service
# O script do lojmIt ANTIGO, de quando o firewall morava nele. O nome
# do arquivo continua 'gateway.sh' porque e assim que ele esta na
# maquina que ainda nao migrou -- procurar 'lojmIt.sh' aqui seria nao
# achar nada e perder o caminho de reserva.
REGRAS_LOJMIT_ANTIGO=/usr/local/sbin/gateway.sh

# Debian sobe o dnscrypt-proxy por socket do systemd; o servico exige o
# socket. Ligar e desligar e sempre os dois juntos, senao o socket reabre a
# porta e o systemd sobe o servico de volta na primeira consulta.
UNIDADES=(dnscrypt-proxy.socket dnscrypt-proxy.service)

erro() {
	echo "Erro: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || erro "execute como root (sudo $0 $*)."
command -v apt-get >/dev/null 2>&1 || erro "apt-get nao encontrado; este script e para Debian."
[ -x "$ORIGEM_SERVICE" ] || erro "$ORIGEM_SERVICE nao encontrado.
      Copie o repositorio inteiro para esta maquina, nao so este script."
[ -f "$ORIGEM_ESPERA" ] || erro "$ORIGEM_ESPERA nao encontrado.
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

ip_da_interface() {
	ip -4 -o addr show dev "$1" 2>/dev/null | awk '{print $4; exit}' | cut -d/ -f1
}

# O firewall e do lojmIt, e o lojmIt.sh reescreve as regras inteiras a cada
# instalacao. Por isso a regra da 53 nao vai la dentro: vai em um arquivo
# proprio em /etc/ghop/nft.d, que o script de regras do lojmIt aplica depois
# das dele. Assim ela sobrevive ao reinicio E a reinstalacao do lojmIt.
escreve_regra_firewall() {
	local lan="$1"
	mkdir -p "$DIR_NFT"
	cat > "$ARQ_NFT" <<REGRAS
# Gerado por projects/ghop-dns/dns.sh. Aplicado por $REGRAS_LOJMIT_ANTIGO.
# A 53 responde SO na LAN: o resolvedor e para a rede interna, e uma porta
# 53 aberta para a internet vira amplificador de DDoS em minutos.
nft add rule inet filter input iifname $lan meta l4proto '{ tcp, udp }' th dport 53 counter accept
nft add rule inet filter input meta l4proto '{ tcp, udp }' th dport 53 counter drop
REGRAS
	chmod 755 "$ARQ_NFT"
}

aplica_firewall() {
	if [ -x "$REGRAS_LOJMIT_ANTIGO" ] && grep -q "nft.d" "$REGRAS_LOJMIT_ANTIGO"; then
		# O lojmIt conhece o nft.d: recarregar as regras dele aplica a nossa.
		systemctl restart gateway.service
	elif [ -x "$REGRAS_LOJMIT_ANTIGO" ]; then
		echo "Atencao: o lojmIt desta maquina foi instalado por uma versao antiga (o" >&2
		echo "         script chamava-se gateway.sh)," >&2
		echo "         que nao aplica $DIR_NFT. A regra da 53 vale ate o proximo reinicio." >&2
		echo "         Reinstale o lojmIt (sudo ./install.sh lojmIt) para ela persistir." >&2
		nft list table inet filter >/dev/null 2>&1 && bash "$ARQ_NFT"
	else
		# Sem lojmIt aqui: aplica agora, e a persistencia e de quem cuidar do
		# firewall desta maquina.
		nft list table inet filter >/dev/null 2>&1 && bash "$ARQ_NFT" || true
	fi
}

remove_firewall() {
	rm -f "$ARQ_NFT"
	if [ -x "$REGRAS_FIREWALL" ]; then
		systemctl restart "$UNIDADE_FIREWALL"
	elif [ -x "$REGRAS_LOJMIT_ANTIGO" ] && grep -q "nft.d" "$REGRAS_LOJMIT_ANTIGO"; then
		systemctl restart gateway.service
	fi
}

comando_estado() {
	local unidade
	echo "ghop-dns"
	for unidade in "${UNIDADES[@]}"; do
		printf '  %-24s %s / %s\n' "$unidade" \
			"$(systemctl is-active "$unidade" 2>/dev/null || true)" \
			"$(systemctl is-enabled "$unidade" 2>/dev/null || true)"
	done
	if [ -f "$ARQ_INTERFACE" ]; then
		local lan
		lan="$(cat "$ARQ_INTERFACE")"
		printf '  %-24s %s (%s)\n' "escuta" "$(ip_da_interface "$lan"):53" "$lan"
	fi
	if [ -f "$ARQ_NEGADOS" ]; then
		printf '  %-24s %s regra(s) em %s\n' "negados" \
			"$(grep -cv '^\s*\(#\|$\)' "$ARQ_NEGADOS" || true)" "$ARQ_NEGADOS"
	fi
	if [ -f "$ARQ_LOG_BLOQUEIO" ]; then
		printf '  %-24s %s linha(s) em %s\n' "bloqueios registrados" \
			"$(wc -l < "$ARQ_LOG_BLOQUEIO")" "$ARQ_LOG_BLOQUEIO"
	fi
	[ -f "$ARQ_NFT" ] && printf '  %-24s %s\n' "firewall" "$ARQ_NFT"
	return 0
}

comando_ligar() {
	[ -f "$ARQ_TOML" ] && [ -f "$ARQ_INTERFACE" ] ||
		erro "ghop-dns ainda nao foi instalado aqui. Rode: sudo $0"
	escreve_regra_firewall "$(cat "$ARQ_INTERFACE")"
	aplica_firewall
	systemctl daemon-reload
	systemctl enable "${UNIDADES[@]}"
	# Para os dois antes de subir: o systemd recusa abrir um socket cujo
	# servico ja esta ativo, e e o caso na reinstalacao e no 'ligar' repetido.
	systemctl stop dnscrypt-proxy.service dnscrypt-proxy.socket
	systemctl start dnscrypt-proxy.socket dnscrypt-proxy.service
	echo "==> ghop-dns ligado"
	comando_estado
}

comando_desligar() {
	systemctl disable --now "${UNIDADES[@]}" 2>/dev/null || true
	remove_firewall
	echo "==> ghop-dns desligado"
	echo "    A configuracao e as listas ficaram em $DIR_DNS e $ARQ_TOML."
	echo "    Os clientes que apontavam para este resolvedor ficam sem DNS ate"
	echo "    voltarem para outro -- este script nao mexe no DHCP nem nos clientes."
	comando_estado
}

comando_recarregar() {
	# O dnscrypt-proxy 2.1 recarrega as listas sozinho ao ve-las mudar; o
	# reinicio e o jeito garantido, e e o que o agente vai chamar quando
	# gravar a lista vinda do painel.
	systemctl restart dnscrypt-proxy.service
	echo "==> listas recarregadas"
}

comando_desinstalar() {
	# Desfaz o que ESTE script fez, e so isso: o pacote apt fica, e o log de
	# bloqueio tambem -- e registro do que a maquina negou, e apagar rastro
	# em nome de "limpeza" e o oposto do que o GHop existe para fazer.
	systemctl disable --now "${UNIDADES[@]}" 2>/dev/null || true
	rm -f "$ARQ_SOCKET"
	rmdir "$DIR_SOCKET" 2>/dev/null || true
	rm -f "$ARQ_SERVICO"
	rmdir "$DIR_SERVICO" 2>/dev/null || true
	rm -f "$ARQ_ESPERA"
	if [ -f "$ARQ_TOML.anterior" ]; then
		mv "$ARQ_TOML.anterior" "$ARQ_TOML"
		echo "==> $ARQ_TOML restaurado ao que havia antes do GHop"
	elif [ -f "$ARQ_TOML" ] && grep -q "Gerado por projects/ghop-dns" "$ARQ_TOML"; then
		# Nosso do inicio ao fim (o carimbo prova, e e o mesmo que a
		# instalacao consulta na linha 355 para decidir o backup).
		rm -f "$ARQ_TOML"
	elif [ -f "$ARQ_TOML" ]; then
		echo "==> $ARQ_TOML preservado: nao foi o GHop que o escreveu"
	fi
	rm -rf "$DIR_DNS"
	remove_firewall
	systemctl daemon-reload
	echo "==> ghop-dns desinstalado"
	echo "    Ficaram: o pacote dnscrypt-proxy e $ARQ_LOG_BLOQUEIO."
	echo "    A LAN fica sem resolvedor: quem entrega DNS por DHCP e o"
	echo "    ghop-dhcp, e ele precisa ser reinstalado para passar a"
	echo "    entregar outro servidor."
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
fi

# O resolvedor e para a LAN; com uma interface so nao ha LAN para atender,
# e esta e provavelmente a maquina do operador.
if [ "$(interfaces | wc -l)" -lt 2 ]; then
	erro "esta maquina tem so uma interface de rede ($(interfaces | tr '\n' ' ')).
      O ghop-dns atende a LAN de um lojmIt; rode isto la."
fi

WAN_SUGERIDA="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
LAN_SUGERIDA=""
[ -f "$ARQ_INTERFACE" ] && LAN_SUGERIDA="$(cat "$ARQ_INTERFACE")"
if [ -z "$LAN_SUGERIDA" ]; then
	LAN_SUGERIDA="$(interfaces | grep -v "^${WAN_SUGERIDA}$" | head -n1 || true)"
fi

LAN_IF="$(perguntar "Interface INTERNA (LAN), onde o resolvedor escuta" "${LAN_IF:-$LAN_SUGERIDA}")"
[ -e "/sys/class/net/$LAN_IF" ] || erro "interface '$LAN_IF' nao existe. Disponiveis: $(interfaces | tr '\n' ' ')"
[ "$LAN_IF" != "$WAN_SUGERIDA" ] ||
	erro "'$LAN_IF' e a interface de saida para a internet. O resolvedor e para a LAN;
      escutar na WAN seria oferecer DNS ao mundo."
LAN_IP="$(ip_da_interface "$LAN_IF")"
[ -n "$LAN_IP" ] || erro "'$LAN_IF' nao tem endereco IPv4; o resolvedor precisa de um para escutar."

# Vazio deixa o dnscrypt-proxy escolher, pela latencia, entre os servidores
# publicos que declaram nao guardar log e nao filtrar. Nome fixo (ex.:
# 'quad9-dnscrypt-ip4-nofilter-pri') prende a um provedor; a lista e
# https://dnscrypt.info/public-servers.
SERVIDORES="$(perguntar "Servidores de cima (vazio = automatico, sem log e sem filtro)" "${GHOP_DNS_SERVIDORES:-}")"
LISTA_SERVIDORES=""
if [ -n "$SERVIDORES" ]; then
	LISTA_SERVIDORES="$(echo "$SERVIDORES" | tr ', ' '\n\n' | grep -v '^$' | sed "s/.*/'&'/" | paste -sd, -)"
fi

echo
echo "Sera aplicado nesta maquina:"
echo "  escuta              : $LAN_IP:53 ($LAN_IF), TCP e UDP -- e 127.0.2.1:53 para esta maquina"
echo "  para cima           : ${SERVIDORES:-automatico (DNSCrypt/DoH, sem log, sem filtro)}"
echo "  negacao             : $ARQ_NEGADOS (vazia; formato do dnscrypt-proxy)"
echo "  excecoes            : $ARQ_PERMITIDOS (vence a negacao)"
echo "  registra            : SO as consultas negadas, em $ARQ_LOG_BLOQUEIO"
echo "  nao registra        : as demais consultas (query_log e nx_log desligados)"
echo "  firewall            : porta 53 so por $LAN_IF, via $ARQ_NFT"
echo "  pacotes             : os do papel 'dns' (ver scripts/service.sh)"
echo "  boot                : espera ate ${ESPERA_SEGUNDOS}s pelo IP da LAN antes de abrir a"
echo "                        porta, e o servico reinicia sozinho se cair"
echo "  arquivos            : $ARQ_TOML"
echo "                        $ARQ_SOCKET"
echo "                        $ARQ_SERVICO"
echo "                        $ARQ_ESPERA"
echo "  nao mexe            : no resolv.conf desta maquina nem no DHCP da LAN;"
echo "                        aponte os clientes para $LAN_IP"
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
"$ORIGEM_SERVICE" dns

echo "==> Listas em $DIR_DNS"
mkdir -p "$DIR_NEGADOS" "$DIR_PERMITIDOS"
chmod 755 "$DIR_NEGADOS" "$DIR_PERMITIDOS"
# Legiveis pelo usuario do servico (_dnscrypt-proxy), que nao e root.
mkdir -p "$DIR_DNS"
chmod 755 "$DIR_DNS"
echo "$LAN_IF" > "$ARQ_INTERFACE"
if [ ! -f "$ARQ_NEGADOS" ]; then
	cat > "$ARQ_NEGADOS" <<'LISTA'
# negados.txt - dominios que este resolvedor se recusa a responder.
#
# Um por linha, no formato do dnscrypt-proxy:
#   exemplo.com      o dominio e todos os subdominios
#   =exemplo.com     so o dominio, exato
#   ads.*            prefixo
#   *rastreio*       qualquer nome que contenha
# Comentario depois de '#'. Excecoes vao em permitidos.txt e vencem.
#
# Esta lista vai ser escrita pelo painel, pelo agente. Editar a mao vale
# ate a proxima sincronizacao.
LISTA
	echo "    $ARQ_NEGADOS criado, vazio"
else
	echo "    $ARQ_NEGADOS ja existe, preservado"
fi
if [ ! -f "$ARQ_PERMITIDOS" ]; then
	cat > "$ARQ_PERMITIDOS" <<'LISTA'
# permitidos.txt - excecoes: nome aqui e respondido mesmo que a negacao o
# cubra. Mesmo formato de negados.txt.
LISTA
	echo "    $ARQ_PERMITIDOS criado, vazio"
else
	echo "    $ARQ_PERMITIDOS ja existe, preservado"
fi
chmod 644 "$ARQ_NEGADOS" "$ARQ_PERMITIDOS"

# Migracao para o formato de varias listas: o que havia nos dois arquivos
# vira a lista 'propria', e eles passam a ser gerados a partir dela.
for especie in negados permitidos; do
	diretorio="$DIR_DNS/$especie.d"
	if [ ! -f "$diretorio/propria.txt" ]; then
		if [ -s "$DIR_DNS/$especie.txt" ]; then
			cp "$DIR_DNS/$especie.txt" "$diretorio/propria.txt"
			echo "    $especie: o que havia virou a lista 'propria'"
		else
			: > "$diretorio/propria.txt"
		fi
		chmod 644 "$diretorio/propria.txt"
	fi
done
if [ ! -f "$ARQ_LISTAS" ]; then
	cat > "$ARQ_LISTAS" <<'JSON'
{
  "negados": {"propria": {"ativa": true, "origem": "painel"}},
  "permitidos": {"propria": {"ativa": true, "origem": "painel"}}
}
JSON
	chmod 644 "$ARQ_LISTAS"
fi

echo "==> Configuracao em $ARQ_TOML"
if [ -f "$ARQ_TOML" ] && ! grep -q "Gerado por projects/ghop-dns" "$ARQ_TOML"; then
	cp -a "$ARQ_TOML" "$ARQ_TOML.anterior"
	echo "    o que havia foi guardado em $ARQ_TOML.anterior"
fi
cat > "$ARQ_TOML" <<TOML
# Gerado por projects/ghop-dns/dns.sh do GHop. Alteracoes manuais serao sobrescritas.

# Vazio: quem escuta e o socket do systemd (ver $ARQ_SOCKET).
listen_addresses = []
server_names = [$LISTA_SERVIDORES]

ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true

# O laco do boot: para saber COM QUEM falar cifrado, o dnscrypt-proxy busca a
# lista de resolvedores por HTTPS -- e para isso precisa resolver um nome
# ANTES de existir resolvedor. Sem estas linhas ele cai no resolvedor do
# sistema, que NESTA maquina pode ser ele mesmo: pergunta a si proprio e nao
# sobe. Os dois enderecos abaixo sao usados so nisso, em claro, e so quando o
# cache de /var/cache/dnscrypt-proxy vence (refresh_delay, 72h) -- consulta de
# cliente nenhuma passa por aqui. netprobe e a espera pela rede, que no boot
# ainda nao existe quando o servico sobe.
ignore_system_dns = true
bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']
netprobe_address = '9.9.9.9:53'
netprobe_timeout = 60

# Sem log e sem filtro la em cima: filtrar e papel desta maquina, e log de
# quem esta acima nao e auditavel daqui.
require_dnssec = false
require_nolog = true
require_nofilter = true

# Latencia decide entre os candidatos.
lb_strategy = 'p2'
lb_estimator = true

timeout = 5000
keepalive = 30
cert_refresh_delay = 240

# Cache local: a mesma pergunta nao sobe duas vezes. E por isso que o coletor
# le o DNS na entrada da LAN, e nao aqui em cima.
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

# Nome negado recebe REFUSED, e nao um endereco falso: o cliente sabe na
# hora que foi recusado, em vez de tentar conectar em 0.0.0.0 e esperar.
blocked_query_response = 'refused'

# NAO registra as consultas: o coletor do GHop ja sumariza o que se pergunta,
# e um registro nome a nome, cliente a cliente, e exatamente o que a
# arquitetura proibe. So a consulta NEGADA fica registrada, porque negar e
# acao, e acao tem de deixar rastro de quem tentou e o que.
[query_log]
  file = ''

[nx_log]
  file = ''

[blocked_names]
  blocked_names_file = '$ARQ_NEGADOS'
  log_file = '$ARQ_LOG_BLOQUEIO'
  log_format = 'tsv'

[allowed_names]
  allowed_names_file = '$ARQ_PERMITIDOS'

[sources]
  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md', 'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md']
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
  prefix = ''
TOML
chmod 644 "$ARQ_TOML"

echo "==> Espera pela LAN em $ARQ_ESPERA"
install -m 755 "$ORIGEM_ESPERA" "$ARQ_ESPERA"

echo "==> Servico em $ARQ_SERVICO"
mkdir -p "$DIR_SERVICO"
cat > "$ARQ_SERVICO" <<SERVICO
# Gerado por projects/ghop-dns/dns.sh do GHop. Alteracoes manuais serao sobrescritas.
#
# Resolvedor que desiste e LAN sem DNS -- e ninguem esta olhando o journal no
# boot. Entao ele tenta de novo, para sempre, de 5 em 5 segundos:
# StartLimitIntervalSec=0 desliga o teto de 5 partidas em 10s do systemd, que
# marcaria a unidade como falhada justamente no caso que importa (a rede que
# ainda nao subiu). O RestartSec e o que impede isso de virar laco quente.
[Unit]
StartLimitIntervalSec=0

[Service]
Restart=on-failure
RestartSec=5
SERVICO

echo "==> Socket em $ARQ_SOCKET"
mkdir -p "$DIR_SOCKET"
cat > "$ARQ_SOCKET" <<SOCKET
# Gerado por projects/ghop-dns/dns.sh do GHop. Alteracoes manuais serao sobrescritas.
#
# O pacote Debian escuta so em 127.0.2.1. A linha vazia zera a lista e as
# seguintes acrescentam o endereco da LAN, TCP e UDP. Nao se escuta em
# 0.0.0.0: o endereco da WAN fica de fora do socket, e o firewall ainda
# barra a 53 por fora da LAN.
[Socket]
# Antes de abrir a porta, espera o IP da LAN aparecer -- uma tentativa por
# segundo, ate $ESPERA_SEGUNDOS. Nao atrasa boot nenhum em que a LAN ja esteja
# de pe: o script sai no instante em que ve o endereco.
ExecStartPre=$ARQ_ESPERA $LAN_IP $ESPERA_SEGUNDOS
# Sem FreeBind o socket abre ANTES de a LAN ter endereco e o bind em
# $LAN_IP:53 morre com "Cannot assign requested address" -- o socket vai a
# falha e o servico nem tenta ("Dependency failed for dnscrypt-proxy"). Nao e
# corrida rara: sockets.target e cedo no boot, e com o papel wifi a LAN e uma
# bridge, que demora ainda mais a ganhar o IP. FreeBind deixa reservar a porta
# num endereco que ainda nao existe; os pacotes chegam quando ele aparecer.
FreeBind=true
ListenStream=
ListenDatagram=
ListenStream=127.0.2.1:53
ListenDatagram=127.0.2.1:53
ListenStream=$LAN_IP:53
ListenDatagram=$LAN_IP:53
SOCKET

comando_ligar

echo
echo "==> Concluido"
printf 'resolvedor     %s:53 (%s)\n' "$LAN_IP" "$LAN_IF"
printf 'servico        %s\n' "$(systemctl is-active dnscrypt-proxy.service)"
printf 'negados        %s\n' "$ARQ_NEGADOS"
printf 'bloqueios      %s\n' "$ARQ_LOG_BLOQUEIO"
echo
echo "Teste de um cliente da LAN:   dig @$LAN_IP debian.org"
echo "Desligar sem desinstalar:     sudo $0 desligar"
