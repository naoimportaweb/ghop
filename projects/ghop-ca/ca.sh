#!/bin/bash
#
# ca.sh - autoridade certificadora do GHop.
#
# Cria a CA e emite os certificados que agentes e paineis usam no mTLS.
#
# ESTA CA NAO DEVE MORAR EM SERVIDOR. Ela roda na maquina do operador, de
# preferencia num diretorio que so exista quando voce for emitir algo (um
# pendrive, por exemplo). Se a chave da CA vive numa maquina em servico, quem
# invadir essa maquina emite agentes e paineis legitimos, e o mTLS inteiro
# deixa de significar alguma coisa.
#
# Uso:
#   ./ca.sh criar                    cria a CA (uma vez so)
#   ./ca.sh agente <host>            emite certificado de agente
#   ./ca.sh painel <nome>            emite certificado de painel com chave em arquivo
#   ./ca.sh assinar <arquivo.csr>    assina um pedido gerado pela YubiKey
#   ./ca.sh listar                   lista o que ja foi emitido
#
# O diretorio da CA e ~/.ghop/ca, ou o valor de GHOP_CA_DIR.

set -euo pipefail

DIR_CA="${GHOP_CA_DIR:-$HOME/.ghop/ca}"
ARQ_CHAVE="$DIR_CA/ca.key"
ARQ_CERT="$DIR_CA/ca.crt"
DIR_EMITIDOS="$DIR_CA/emitidos"

# Curva usada em tudo. P-256 e o denominador comum: o PIV da YubiKey suporta,
# o OpenSSL suporta, e o modulo ssl do Python suporta. Ed25519 seria melhor,
# mas so existe em YubiKey de firmware 5.7 em diante.
CURVA=prime256v1

# Validades. Assimetricas de proposito: renovar agente custa N visitas as
# maquinas, renovar painel custa uma -- e o painel e a chave que vale por
# toda a infra, entao e a que se quer poder cortar rapido.
DIAS_CA=3650
DIAS_AGENTE=730
DIAS_PAINEL=90

PREFIXO_AGENTE=ghop-agente
PREFIXO_PAINEL=ghop-painel

erro() {
	echo "Erro: $*" >&2
	exit 1
}

if [ "$(id -u)" -eq 0 ]; then
	erro "nao execute a CA como root; ela pertence ao seu usuario, nao a maquina."
fi

command -v openssl >/dev/null 2>&1 || erro "openssl nao encontrado."

# A senha protege a chave da CA em disco. GHOP_CA_SENHA existe para teste
# automatizado; no uso real, deixe o openssl perguntar.
if [ -n "${GHOP_CA_SENHA:-}" ]; then
	SENHA=(-passin "env:GHOP_CA_SENHA")
	SENHA_SAIDA=(-pass "env:GHOP_CA_SENHA")
else
	SENHA=()
	SENHA_SAIDA=()
fi

# A chave do painel tambem e cifrada, e pelo mesmo motivo que a da CA: e ela
# que manda comando em todas as maquinas. Enquanto nao houver YubiKey com PIV
# ela vive em arquivo, e arquivo em claro cai junto com a maquina. A do agente
# segue sem senha, e de proposito -- ver comando_agente.
# GHOP_PAINEL_SENHA existe para teste automatizado; no uso real, o openssl
# pergunta.
if [ -n "${GHOP_PAINEL_SENHA:-}" ]; then
	SENHA_PAINEL=(-passin "env:GHOP_PAINEL_SENHA")
	SENHA_PAINEL_SAIDA=(-pass "env:GHOP_PAINEL_SENHA")
else
	SENHA_PAINEL=()
	SENHA_PAINEL_SAIDA=()
fi

exige_ca() {
	[ -f "$ARQ_CHAVE" ] || erro "CA nao encontrada em $DIR_CA. Rode '$0 criar' antes."
}

# Nomes viram nome de arquivo e vao para o certificado: aceite so o obvio.
valida_nome() {
	[[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] ||
		erro "nome invalido '$1'. Use letras, numeros, ponto, hifen e sublinhado."
}

# Assina uma CSR com as extensoes do tipo pedido.
#   $1 caminho da CSR   $2 destino .crt   $3 dias   $4 serverAuth|clientAuth   $5 CN
assina() {
	local csr="$1" destino="$2" dias="$3" uso="$4" nome="$5" extensoes
	extensoes="$(mktemp)"
	cat > "$extensoes" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = $uso
subjectAltName = DNS:$nome
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid, issuer
EXT
	openssl x509 -req -in "$csr" -CA "$ARQ_CERT" -CAkey "$ARQ_CHAVE" \
		-CAcreateserial -days "$dias" -sha256 -extfile "$extensoes" \
		-out "$destino" "${SENHA[@]}" 2>/dev/null
	rm -f "$extensoes"
}

comando_criar() {
	[ -f "$ARQ_CHAVE" ] && erro "ja existe uma CA em $DIR_CA. Apague o diretorio para recomecar."
	mkdir -p "$DIR_EMITIDOS"
	chmod 700 "$DIR_CA" "$DIR_EMITIDOS"

	echo "==> Gerando a chave da CA ($CURVA)"
	if [ "${#SENHA_SAIDA[@]}" -eq 0 ]; then
		echo "    A senha protege esta chave em disco. Guarde-a: sem ela nao se emite mais nada."
	fi
	openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$CURVA" \
		-aes256 "${SENHA_SAIDA[@]}" -out "$ARQ_CHAVE"
	chmod 600 "$ARQ_CHAVE"

	echo "==> Gerando o certificado raiz (valido por $DIAS_CA dias)"
	openssl req -x509 -new -key "$ARQ_CHAVE" -sha256 -days "$DIAS_CA" \
		-subj "/CN=ghop-ca" \
		-addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" \
		-out "$ARQ_CERT" "${SENHA[@]}"
	chmod 644 "$ARQ_CERT"

	echo
	echo "CA criada em $DIR_CA"
	echo "  $ARQ_CHAVE  chave privada, cifrada -- nunca copie para servidor"
	echo "  $ARQ_CERT  certificado raiz, publico -- vai para todo agente e painel"
}

comando_agente() {
	local host="$1" nome chave csr cert
	valida_nome "$host"
	exige_ca
	nome="$PREFIXO_AGENTE-$host"
	chave="$DIR_EMITIDOS/$nome.key"
	cert="$DIR_EMITIDOS/$nome.crt"
	[ -f "$cert" ] && erro "$nome ja foi emitido. Apague $cert para reemitir."

	echo "==> Emitindo $nome (valido por $DIAS_AGENTE dias)"
	# Sem senha: o agente sobe no boot, sem ninguem para digitar. E nao faz
	# falta -- quem consegue ler este arquivo ja e root naquela maquina.
	openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$CURVA" -out "$chave"
	chmod 600 "$chave"
	csr="$(mktemp)"
	openssl req -new -key "$chave" -subj "/CN=$nome" -out "$csr"
	assina "$csr" "$cert" "$DIAS_AGENTE" serverAuth "$nome"
	rm -f "$csr"

	echo
	echo "Leve para a maquina, presencialmente:"
	echo "  $chave"
	echo "  $cert"
	echo "  $ARQ_CERT"
	echo "Nunca emita nem transporte certificado pela rede."
}

comando_painel() {
	local apelido="$1" nome chave csr cert
	valida_nome "$apelido"
	exige_ca
	nome="$PREFIXO_PAINEL-$apelido"
	chave="$DIR_EMITIDOS/$nome.key"
	cert="$DIR_EMITIDOS/$nome.crt"
	[ -f "$cert" ] && erro "$nome ja foi emitido. Apague $cert para reemitir."

	echo "==> Emitindo $nome (valido por $DIAS_PAINEL dias)"
	echo "    Atencao: chave em arquivo. Para a chave dentro da YubiKey, use"
	echo "    './yubikey.sh matricular' e depois '$0 assinar'."
	if [ "${#SENHA_PAINEL_SAIDA[@]}" -eq 0 ]; then
		echo "    A senha protege esta chave em disco. Ela vale por toda a infra."
	fi
	openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$CURVA" \
		-aes256 "${SENHA_PAINEL_SAIDA[@]}" -out "$chave"
	chmod 600 "$chave"
	csr="$(mktemp)"
	openssl req -new -key "$chave" -subj "/CN=$nome" -out "$csr" "${SENHA_PAINEL[@]}"
	assina "$csr" "$cert" "$DIAS_PAINEL" clientAuth "$nome"
	rm -f "$csr"

	echo
	echo "  $chave"
	echo "  $cert"
}

comando_assinar() {
	local csr="$1" nome cert
	[ -f "$csr" ] || erro "arquivo '$csr' nao encontrado."
	exige_ca
	nome="$(openssl req -in "$csr" -noout -subject -nameopt multiline 2>/dev/null |
		sed -n 's/^ *commonName *= *//p')"
	[ -n "$nome" ] || erro "nao consegui ler o CN da CSR."
	valida_nome "$nome"

	case "$nome" in
	"$PREFIXO_PAINEL"-*) cert="$DIR_EMITIDOS/$nome.crt"; assina "$csr" "$cert" "$DIAS_PAINEL" clientAuth "$nome" ;;
	"$PREFIXO_AGENTE"-*) cert="$DIR_EMITIDOS/$nome.crt"; assina "$csr" "$cert" "$DIAS_AGENTE" serverAuth "$nome" ;;
	*) erro "CN '$nome' nao comeca com $PREFIXO_PAINEL- nem $PREFIXO_AGENTE-." ;;
	esac

	echo "==> Assinado: $cert"
}

comando_listar() {
	exige_ca
	printf '%-34s %-12s %s\n' NOME TIPO VENCE
	local cert nome tipo vence
	for cert in "$DIR_EMITIDOS"/*.crt; do
		[ -e "$cert" ] || continue
		nome="$(basename "$cert" .crt)"
		case "$nome" in
		"$PREFIXO_PAINEL"-*) tipo=painel ;;
		"$PREFIXO_AGENTE"-*) tipo=agente ;;
		*) tipo="?" ;;
		esac
		vence="$(openssl x509 -in "$cert" -noout -enddate | cut -d= -f2)"
		printf '%-34s %-12s %s\n' "$nome" "$tipo" "$vence"
	done
}

case "${1:-}" in
criar) comando_criar ;;
agente) [ $# -eq 2 ] || erro "uso: $0 agente <host>"; comando_agente "$2" ;;
painel) [ $# -eq 2 ] || erro "uso: $0 painel <nome>"; comando_painel "$2" ;;
assinar) [ $# -eq 2 ] || erro "uso: $0 assinar <arquivo.csr>"; comando_assinar "$2" ;;
listar) comando_listar ;;
*)
	sed -n '3,20p' "$0" | sed 's/^# \?//'
	exit 1
	;;
esac
