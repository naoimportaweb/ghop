#!/bin/bash
#
# filtro.sh - instala e liga o ghop-filtro nesta maquina: o filtro de camada
# de aplicacao da LAN, que decide pelo NOME pedido na propria conexao.
#
# O resolvedor (ghop-dns) so alcanca quem pergunta a ele. Cliente que use
# DoH, DNS proprio ou cache sai sem passar por la, e a lista de negacao nao
# vale nada para ele. O nome, esse, vai na conexao: o SNI do ClientHello no
# TLS e o Host no HTTP em claro. E onde este papel decide.
#
# NAO DESCRIPTOGRAFA NADA. O SNI e o unico campo que o TLS manda em claro,
# antes de qualquer chave; o filtro le, decide, e dai em diante so emenda os
# dois lados. Nenhum certificado do GHop e instalado em cliente nenhum.
#
# Este papel LIGA E DESLIGA sem tocar no resto, e e OPCIONAL: o lojmIt
# roteia igual sem ele. 'desligar' para o servico e tira o redirecionamento
# do firewall -- a LAN volta a falar direto com a internet.
#
# ATENCAO: enquanto LIGADO, o servico esta no caminho do dado. Se ele cair, o
# redirecionamento continua e as portas 80 e 443 da LAN param. E deliberado
# (filtro que falha aberto e filtro em que nao se pode confiar), e a saida e
# uma ordem so: 'filtro.sh desligar'.
#
# Uso interativo:      sudo ./projects/ghop-filtro/filtro.sh          (instala e liga)
# Uso nao interativo:  sudo LAN_IF=enp3s0 ./projects/ghop-filtro/filtro.sh --sim
# Depois:              sudo ./projects/ghop-filtro/filtro.sh desligar | ligar | estado | recarregar

set -euo pipefail

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEM_SERVICE="$DIR_SCRIPT/../../scripts/service.sh"
ORIGEM_FILTRO="$DIR_SCRIPT/ghop-filtro.py"
DIR_CONFIG=/etc/ghop
# O diretorio E a marca do papel: o agente procura /etc/ghop/filtro para
# dizer se este papel existe na maquina.
DIR_FILTRO="$DIR_CONFIG/filtro"
ARQ_REGRAS="$DIR_FILTRO/regras.json"
ARQ_INTERFACE="$DIR_FILTRO/interface"
DIR_NFT="$DIR_CONFIG/nft.d"
ARQ_NFT="$DIR_NFT/filtro.sh"
ARQ_FILTRO=/usr/local/sbin/ghop-filtro.py
ARQ_SERVICO=/etc/systemd/system/ghop-filtro.service
ARQ_CONFIG="$DIR_CONFIG/ghop.conf"
ARQ_ESTADO=/var/ghop/filtro.json
ARQ_LOG=/var/log/ghop/filtro-bloqueados.log
UNIDADE=ghop-filtro.service
# Dentro da faixa 7000-7100, que o nftables ja fecha para fora da LAN. Nao e
# detalhe: e o que impede a internet de usar o filtro como proxy aberto.
PORTA=7010
# Quem aplica o ruleset e o papel nftables; o caminho antigo fica como
# reserva para maquina que ainda nao migrou.
REGRAS_FIREWALL=/usr/local/sbin/ghop-nftables.sh
UNIDADE_FIREWALL=ghop-nftables.service
# O script do lojmIt ANTIGO, de quando o firewall morava nele. O nome
# do arquivo continua 'gateway.sh' porque e assim que ele esta na
# maquina que ainda nao migrou -- procurar 'lojmIt.sh' aqui seria nao
# achar nada e perder o caminho de reserva.
REGRAS_LOJMIT_ANTIGO=/usr/local/sbin/gateway.sh

erro() {
	echo "Erro: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || erro "execute como root (sudo $0 $*)."
command -v apt-get >/dev/null 2>&1 || erro "apt-get nao encontrado; este script e para Debian."
[ -x "$ORIGEM_SERVICE" ] || erro "$ORIGEM_SERVICE nao encontrado.
      Copie o repositorio inteiro para esta maquina, nao so este script."
[ -f "$ORIGEM_FILTRO" ] || erro "$ORIGEM_FILTRO nao encontrado.
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

# ghop.conf define USER e GROUP e sobrescreveria o shell se fosse 'source'.
le_config() {
	local chave="$1" padrao="$2" valor=""
	[ -f "$ARQ_CONFIG" ] && valor="$(sed -n "s/^$chave=//p" "$ARQ_CONFIG" | tail -n1)"
	echo "${valor:-$padrao}"
}

# O firewall e do papel nftables, que reescreve o ruleset inteiro a cada
# aplicacao. Por isso o redirecionamento nao vai la dentro: vai num arquivo
# proprio em /etc/ghop/nft.d, aplicado depois das regras base.
escreve_regra_firewall() {
	local lan="$1"
	mkdir -p "$DIR_NFT"
	cat > "$ARQ_NFT" <<REGRAS
# Gerado por projects/ghop-filtro/filtro.sh. Aplicado por $REGRAS_FIREWALL.
#
# So o que ENTRA pela LAN e vai para endereco PUBLICO. Duas consequencias
# que valem a linha comprida: trafego nascido nesta maquina nao passa por
# prerouting, entao o filtro nunca redireciona a propria saida (seria laco);
# e conexao de um cliente da LAN para outro, ou para o proprio lojmIt, sai
# de fora do filtro -- e rede interna, nao e "para fora".
nft add rule inet nat prerouting iifname $lan tcp dport '{ 80, 443 }' ip daddr != '{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16 }' counter redirect to :$PORTA
REGRAS
	chmod 755 "$ARQ_NFT"
}

aplica_firewall() {
	if [ -x "$REGRAS_FIREWALL" ]; then
		systemctl restart "$UNIDADE_FIREWALL"
	elif [ -x "$REGRAS_LOJMIT_ANTIGO" ] && grep -q "nft.d" "$REGRAS_LOJMIT_ANTIGO"; then
		systemctl restart gateway.service
	else
		echo "Atencao: esta maquina nao tem o papel nftables do GHop." >&2
		echo "         O redirecionamento vale ate o proximo reinicio." >&2
		echo "         Instale o firewall (sudo ./install.sh nftables) para ele persistir." >&2
		nft list table inet nat >/dev/null 2>&1 && bash "$ARQ_NFT" || true
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
	echo "ghop-filtro"
	printf '  %-24s %s / %s\n' "$UNIDADE" \
		"$(systemctl is-active "$UNIDADE" 2>/dev/null || true)" \
		"$(systemctl is-enabled "$UNIDADE" 2>/dev/null || true)"
	if [ -f "$ARQ_INTERFACE" ]; then
		printf '  %-24s %s, portas 80 e 443 -> :%s\n' "redireciona" \
			"$(cat "$ARQ_INTERFACE")" "$PORTA"
	fi
	if [ -f "$ARQ_REGRAS" ]; then
		printf '  %-24s %s\n' "regras" "$ARQ_REGRAS"
	else
		printf '  %-24s %s\n' "regras" "nenhuma ainda (tudo passa)"
	fi
	if [ -f "$ARQ_LOG" ]; then
		printf '  %-24s %s linha(s) em %s\n' "bloqueios registrados" \
			"$(wc -l < "$ARQ_LOG")" "$ARQ_LOG"
	fi
	[ -f "$ARQ_NFT" ] && printf '  %-24s %s\n' "firewall" "$ARQ_NFT"
	[ -f "$ARQ_ESTADO" ] && printf '  %-24s %s\n' "contadores" "$ARQ_ESTADO"
	return 0
}

comando_ligar() {
	[ -x "$ARQ_FILTRO" ] && [ -f "$ARQ_INTERFACE" ] ||
		erro "ghop-filtro ainda nao foi instalado aqui. Rode: sudo $0"
	systemctl daemon-reload
	# O servico SOBE ANTES do redirecionamento. Na ordem inversa haveria uma
	# janela, curta mas real, em que a LAN estaria redirecionada para uma
	# porta que ninguem atende -- ou seja, sem 80 nem 443.
	systemctl enable --now "$UNIDADE"
	escreve_regra_firewall "$(cat "$ARQ_INTERFACE")"
	aplica_firewall
	echo "==> ghop-filtro ligado"
	comando_estado
}

comando_desligar() {
	# E aqui a ordem se inverte, pelo mesmo motivo: tira o redirecionamento
	# primeiro, para nao existir instante nenhum em que a LAN aponte para um
	# servico ja parado.
	remove_firewall
	systemctl disable --now "$UNIDADE" 2>/dev/null || true
	echo "==> ghop-filtro desligado"
	echo "    A LAN voltou a falar direto com a internet nas portas 80 e 443."
	echo "    As regras ficaram em $ARQ_REGRAS, para o proximo 'ligar'."
	comando_estado
}

comando_recarregar() {
	# O servico reve o regras.json sozinho pelo mtime, a cada poucos
	# segundos; reiniciar e o jeito garantido -- e derruba as conexoes que
	# estiverem passando, por isso nao e o caminho normal. O agente, ao
	# gravar regra nova, so escreve o arquivo e deixa o servico perceber.
	systemctl restart "$UNIDADE"
	echo "==> ghop-filtro reiniciado (regras relidas)"
}

comando_desinstalar() {
	# Desfaz o que ESTE script fez. O log de bloqueio FICA: e registro do que
	# a maquina negou, e apagar rastro em nome de limpeza e o oposto do que o
	# GHop existe para fazer.
	remove_firewall
	systemctl disable --now "$UNIDADE" 2>/dev/null || true
	rm -f "$ARQ_SERVICO" "$ARQ_FILTRO"
	rm -rf "$DIR_FILTRO"
	systemctl daemon-reload
	echo "==> ghop-filtro desinstalado"
	echo "    Ficaram: $ARQ_LOG e $ARQ_ESTADO."
	echo "    A LAN voltou a falar direto com a internet nas portas 80 e 443."
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

# O filtro fica entre a LAN e a internet. Com uma interface so nao ha LAN
# para filtrar, e esta e provavelmente a maquina do operador.
if [ "$(interfaces | wc -l)" -lt 2 ]; then
	erro "esta maquina tem so uma interface de rede ($(interfaces | tr '\n' ' ')).
      O ghop-filtro fica entre a LAN e a internet; rode isto no lojmIt."
fi

WAN_SUGERIDA="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
LAN_SUGERIDA=""
[ -f "$ARQ_INTERFACE" ] && LAN_SUGERIDA="$(cat "$ARQ_INTERFACE")"
if [ -z "$LAN_SUGERIDA" ]; then
	LAN_SUGERIDA="$(interfaces | grep -v "^${WAN_SUGERIDA}$" | head -n1 || true)"
fi

LAN_IF="$(perguntar "Interface INTERNA (LAN), cujo trafego sera filtrado" "${LAN_IF:-$LAN_SUGERIDA}")"
[ -e "/sys/class/net/$LAN_IF" ] || erro "interface '$LAN_IF' nao existe. Disponiveis: $(interfaces | tr '\n' ' ')"
[ "$LAN_IF" != "$WAN_SUGERIDA" ] ||
	erro "'$LAN_IF' e a interface de saida para a internet. O filtro le o que a
      LAN PEDE, antes do masquerade; na WAN a origem ja nao existe."

GHOP_USER="$(le_config USER root)"
GHOP_GROUP="$(le_config GROUP root)"

echo
echo "Sera aplicado nesta maquina:"
echo "  filtra              : $LAN_IF, portas 80 e 443, so para destino publico"
echo "  decide por          : SNI do ClientHello (TLS) e cabecalho Host (HTTP)"
echo "  NAO descriptografa  : nenhum certificado e instalado em cliente nenhum;"
echo "                        depois de ler o nome, so emenda os dois lados"
echo "  regras              : $ARQ_REGRAS, escritas pelo painel"
echo "                        (sem regra nenhuma, TUDO PASSA)"
echo "  registra            : SO o que for bloqueado, em $ARQ_LOG"
echo "  nao registra        : o que passou -- disso o coletor ja cuida"
echo "  contadores          : $ARQ_ESTADO (lidos pelo agente)"
echo "  firewall            : redireciona para :$PORTA, via $ARQ_NFT"
echo "  servico             : $UNIDADE, como $GHOP_USER:$GHOP_GROUP"
echo "  programa            : $ARQ_FILTRO"
echo "  pacotes             : os do papel 'filtro' (ver scripts/service.sh)"
echo
echo "  ATENCAO: enquanto ligado, este servico fica NO CAMINHO do trafego da"
echo "           LAN. Se ele cair, as portas 80 e 443 param -- o filtro falha"
echo "           FECHADO, de proposito. Para abrir: sudo $0 desligar"
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
"$ORIGEM_SERVICE" filtro

echo "==> Regras em $DIR_FILTRO"
mkdir -p "$DIR_FILTRO"
chmod 755 "$DIR_FILTRO"
echo "$LAN_IF" > "$ARQ_INTERFACE"
if [ ! -f "$ARQ_REGRAS" ]; then
	# Vazio de proposito: papel recem-instalado nao bloqueia nada. Quem
	# escreve aqui e o agente, com campos que ele mesmo validou -- este
	# arquivo e DADO, nunca texto de regra vindo do painel.
	cat > "$ARQ_REGRAS" <<'JSON'
{
  "versao": 1,
  "politica": "permitir",
  "regras": []
}
JSON
	echo "    $ARQ_REGRAS criado, sem regra nenhuma (tudo passa)"
else
	echo "    $ARQ_REGRAS ja existe, preservado"
fi
chmod 644 "$ARQ_REGRAS"

mkdir -p "$(dirname "$ARQ_ESTADO")" "$(dirname "$ARQ_LOG")"

echo "==> Instalando filtro em $ARQ_FILTRO"
install -m 750 "$ORIGEM_FILTRO" "$ARQ_FILTRO"

echo "==> Escrevendo servico em $ARQ_SERVICO"
cat > "$ARQ_SERVICO" <<SERVICO
[Unit]
Description=GHop - filtro de camada de aplicacao (SNI e Host) da LAN
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$ARQ_FILTRO
User=$GHOP_USER
Group=$GHOP_GROUP
# Fica no caminho do dado: cair e a LAN sem 80 nem 443. Volta sempre, e
# rapido. Sem StartLimit, para um defeito repetido nao virar rede parada
# ate alguem reparar.
Restart=always
RestartSec=1
StartLimitIntervalSec=0
Environment=GHOP_FILTRO_DIR=$DIR_FILTRO
Environment=GHOP_FILTRO_PORTA=$PORTA
Environment=GHOP_FILTRO_ESTADO=$ARQ_ESTADO
Environment=GHOP_FILTRO_LOG=$ARQ_LOG

[Install]
WantedBy=multi-user.target
SERVICO

comando_ligar

echo
echo "==> Concluido"
printf 'filtra         %s (80, 443 -> :%s)\n' "$LAN_IF" "$PORTA"
printf 'servico        %s\n' "$(systemctl is-active "$UNIDADE")"
printf 'regras         %s\n' "$ARQ_REGRAS"
printf 'bloqueios      %s\n' "$ARQ_LOG"
echo
echo "Conferir uma regra sem esperar alguem tropecar nela:"
echo "  sudo $ARQ_FILTRO --testar exemplo.com"
echo "Desligar sem desinstalar (a LAN volta a sair direto):"
echo "  sudo $0 desligar"
