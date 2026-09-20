#!/bin/bash
#
# agente.sh - instala o agente do GHop nesta maquina.
#
# O agente escuta comandos do painel sobre mTLS e responde. O conjunto de
# comandos e fechado (ver COMANDOS em ghop-agente.py): leituras dos contadores
# do ghop-requests, dos eventos monitorados e da rede da maquina, e uma so
# escrita, a lista de IPs a monitorar. Quem classifica e o painel.
#
# Este script NAO emite nem baixa certificado, e isso e proposital: certificado
# de agente e emitido na maquina do operador e trazido presencialmente. Traga
# em pendrive e aponte com GHOP_CERTS, ou deixe os arquivos ja em /etc/ghop/certs.
#
# Uso interativo:      sudo ./projects/ghop-agente/agente.sh
# Trazendo do pendrive: sudo GHOP_CERTS=/media/pendrive ./projects/ghop-agente/agente.sh
# Uso nao interativo:  sudo GHOP_PORTA=7000 ./projects/ghop-agente/agente.sh --sim

set -euo pipefail

DIR_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORIGEM_AGENTE="$DIR_SCRIPT/ghop-agente.py"
ORIGEM_SERVICE="$DIR_SCRIPT/../../scripts/service.sh"
DIR_CONFIG=/etc/ghop
ARQ_CONFIG="$DIR_CONFIG/ghop.conf"
DIR_CERTS="$DIR_CONFIG/certs"
ARQ_AGENTE=/usr/local/sbin/ghop-agente.py
ARQ_SERVICO=/etc/systemd/system/ghop-agente.service
DIR_REPO="$(cd "$DIR_SCRIPT/../.." && pwd)"

SEM_PERGUNTA=0
[ "${1:-}" = "--sim" ] && SEM_PERGUNTA=1
[ -t 0 ] || SEM_PERGUNTA=1

erro() {
	echo "Erro: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || erro "execute como root (sudo $0)."
command -v apt-get >/dev/null 2>&1 || erro "apt-get nao encontrado; este script e para Debian."
[ -x "$ORIGEM_SERVICE" ] || erro "$ORIGEM_SERVICE nao encontrado.
      Copie o repositorio inteiro para esta maquina, nao so este script."
[ -f "$ORIGEM_AGENTE" ] || erro "$ORIGEM_AGENTE nao encontrado.
      Copie o repositorio inteiro para esta maquina, nao so este script."

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

PORTA="$(perguntar "Porta de escuta do agente (faixa 7000-7100)" "${GHOP_PORTA:-7000}")"
case "$PORTA" in
'' | *[!0-9]*) erro "porta invalida '$PORTA'." ;;
esac
# A faixa 7000-7100 e a que o nftables do lojmIt ja fecha para fora da LAN.
# Escutar fora dela seria abrir uma porta que o firewall nao cobre.
[ "$PORTA" -ge 7000 ] && [ "$PORTA" -le 7100 ] ||
	erro "porta $PORTA fora da faixa 7000-7100, que e a reservada aos servicos do GHop."

# Se o operador trouxe os certificados, instala-os agora com a permissao certa.
if [ -n "${GHOP_CERTS:-}" ]; then
	[ -d "$GHOP_CERTS" ] || erro "GHOP_CERTS='$GHOP_CERTS' nao e um diretorio."
	origem_crt="$(ls "$GHOP_CERTS"/ghop-agente-*.crt "$GHOP_CERTS"/agente.crt 2>/dev/null | head -n1 || true)"
	origem_key="$(ls "$GHOP_CERTS"/ghop-agente-*.key "$GHOP_CERTS"/agente.key 2>/dev/null | head -n1 || true)"
	[ -n "$origem_crt" ] && [ -n "$origem_key" ] ||
		erro "nao achei o par ghop-agente-*.crt/.key em $GHOP_CERTS."
	[ -f "$GHOP_CERTS/ca.crt" ] || erro "nao achei ca.crt em $GHOP_CERTS."
	mkdir -p "$DIR_CERTS"
	chmod 700 "$DIR_CERTS"
	install -m 644 "$origem_crt" "$DIR_CERTS/agente.crt"
	install -m 600 "$origem_key" "$DIR_CERTS/agente.key"
	install -m 644 "$GHOP_CERTS/ca.crt" "$DIR_CERTS/ca.crt"
	echo "==> Certificados copiados de $GHOP_CERTS"
fi

for arquivo in agente.crt agente.key ca.crt; do
	[ -f "$DIR_CERTS/$arquivo" ] || erro "falta $DIR_CERTS/$arquivo.
      Emita na maquina do operador:
        ./ca.sh agente $(hostname)
      e traga ghop-agente-$(hostname).crt, .key e ca.crt presencialmente.
      Depois: sudo GHOP_CERTS=<diretorio> $0
      Nunca transporte certificado pela rede."
done

# Traz o arquivo errado e o erro so aparece meses depois, no primeiro comando:
# confere agora que o certificado e de AGENTE e que foi emitido por esta CA.
CN_AGENTE="$(openssl x509 -in "$DIR_CERTS/agente.crt" -noout -subject -nameopt multiline |
	sed -n 's/^ *commonName *= *//p')"
case "$CN_AGENTE" in
ghop-agente-*) ;;
*) erro "$DIR_CERTS/agente.crt tem CN '$CN_AGENTE', que nao e de agente." ;;
esac
openssl verify -CAfile "$DIR_CERTS/ca.crt" "$DIR_CERTS/agente.crt" >/dev/null 2>&1 ||
	erro "$DIR_CERTS/agente.crt nao foi emitido pela CA de $DIR_CERTS/ca.crt."

echo
echo "Sera aplicado nesta maquina:"
echo "  identidade      : $CN_AGENTE"
echo "  escuta          : 0.0.0.0:$PORTA (o nftables limita a LAN)"
echo "  comandos        : conjunto FECHADO -- nao ha execucao generica"
echo "                    leitura: resumo, eventos, sistema, interfaces, rotas,"
echo "                             vizinhos, conexoes, trafego, papeis, dhcp,"
echo "                             dns, wifi, nftables, filtro, listas, acao"
echo "                    escrita: monitorar, papel, lista, firewall, filtrar,"
echo "                             limpar"
echo "  certificados    : $DIR_CERTS/"
echo "  configuracao    : $ARQ_CONFIG (USER/GROUP dos servicos)"
echo "  pacotes         : os do papel 'agente' (ver scripts/service.sh)"
echo "  repositorio     : $DIR_REPO (de onde saem as acoes de papel)"
echo "  arquivos        : $ARQ_AGENTE"
echo "                    $ARQ_SERVICO"
echo
echo "O agente fica rodando permanentemente (ghop-agente.service)."

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
[ -n "$GHOP_USER" ] && [ -n "$GHOP_GROUP" ] || erro "USER ou GROUP ausentes em $ARQ_CONFIG."
id "$GHOP_USER" >/dev/null 2>&1 ||
	erro "usuario '$GHOP_USER' de $ARQ_CONFIG nao existe nesta maquina."
echo "    servico rodara como $GHOP_USER:$GHOP_GROUP"

chown -R "$GHOP_USER:$GHOP_GROUP" "$DIR_CERTS"

echo "==> Instalando agente em $ARQ_AGENTE"
install -m 750 "$ORIGEM_AGENTE" "$ARQ_AGENTE"

echo "==> Escrevendo servico em $ARQ_SERVICO"
cat > "$ARQ_SERVICO" <<SERVICO
[Unit]
Description=GHop - agente: recebe comandos do painel sobre mTLS
After=network.target

[Service]
Type=simple
User=$GHOP_USER
Group=$GHOP_GROUP
Environment=GHOP_PORTA=$PORTA
Environment=GHOP_CERT=$DIR_CERTS/agente.crt
Environment=GHOP_CHAVE=$DIR_CERTS/agente.key
Environment=GHOP_CA=$DIR_CERTS/ca.crt
Environment=GHOP_DIR=/var/ghop/tmp
# Onde o repositorio mora nesta maquina. E dele que saem os scripts das
# acoes de papel, e o agente recusa rodar se ele nao for de root.
Environment=GHOP_REPO=$DIR_REPO
ExecStart=$ARQ_AGENTE
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICO

echo "==> Ativando ghop-agente.service"
systemctl daemon-reload
systemctl enable ghop-agente.service
systemctl restart ghop-agente.service

echo
echo "==> Concluido"
printf 'identidade  %s\n' "$CN_AGENTE"
printf 'porta       %s\n' "$PORTA"
printf 'servico     %s\n' "$(systemctl is-active ghop-agente.service)"
echo
echo "Do painel, para conferir o handshake e os comandos:"
echo "  ./teste-agente.py ${CN_AGENTE#ghop-agente-} <nome-do-painel>"
