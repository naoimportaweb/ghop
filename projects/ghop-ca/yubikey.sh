#!/bin/bash
#
# yubikey.sh - matricula uma YubiKey como identidade de painel do GHop.
#
# A chave privada do painel nasce DENTRO da YubiKey e nunca existe em disco:
# o script gera o par no slot PIV, exporta so a parte publica e monta a CSR.
# Quem assina e a CA (./ca.sh assinar), que nao mora em servidor nenhum.
#
# Matricule AS DUAS YubiKeys desde o inicio. Chave PIV nao se copia: nao ha
# como duplicar depois a identidade de uma chave que ficou sozinha, e a unica
# saida seria emitir um painel novo com a CA na mao.
#
# Uso:
#   ./yubikey.sh matricular <nome>   reset do PIV, PIN/PUK, chave no slot e CSR
#   ./yubikey.sh csr <nome>          CSR nova para a chave que ja esta no slot
#   ./yubikey.sh importar <nome>     grava na YubiKey o .crt ja assinado
#   ./yubikey.sh estado              mostra a YubiKey conectada e seus slots
#
# Primeira vez, uma chave:
#   ./yubikey.sh matricular yubikey1
#   ./ca.sh assinar ~/.ghop/ca/emitidos/ghop-painel-yubikey1.csr
#   ./yubikey.sh importar yubikey1
#
# Renovacao (o certificado de painel vale 90 dias) -- 'csr' no lugar de
# 'matricular', que apagaria o slot:
#   ./yubikey.sh csr yubikey1
#   ./ca.sh assinar ~/.ghop/ca/emitidos/ghop-painel-yubikey1.csr
#   ./yubikey.sh importar yubikey1
#
# Com --sim nao ha perguntas. Use apenas sabendo o que sera aplicado: o
# 'matricular' comeca apagando o applet PIV da chave conectada.
#
# O diretorio da CA e ~/.ghop/ca, ou o valor de GHOP_CA_DIR.

set -euo pipefail

DIR_CA="${GHOP_CA_DIR:-$HOME/.ghop/ca}"
DIR_EMITIDOS="$DIR_CA/emitidos"

PREFIXO_PAINEL=ghop-painel

# Slot 9a (PIV Authentication) e o slot de autenticar-se perante outra
# maquina, que e exatamente o que o painel faz no mTLS. Os outros slots do
# PIV existem para assinatura e cifra de documento, nao para isto.
SLOT=9a

# Mesma curva do ca.sh (prime256v1 = P-256 = ECCP256 no vocabulario do ykman).
# Denominador comum entre o PIV da YubiKey, o OpenSSL e o modulo ssl do
# Python. Ed25519 seria melhor, mas so existe em firmware 5.7 em diante.
CURVA=ECCP256

# PIN uma vez por sessao, toque a cada uso da chave privada. E o "PIN mais
# toque" da arquitetura: o PIN sozinho cai junto com a maquina invadida, o
# toque exige alguem presente. A chave do painel manda comando em todas as
# maquinas -- e a que se quer cara de usar sem querer.
POLITICA_PIN=once
POLITICA_TOQUE=always

erro() {
	echo "Erro: $*" >&2
	exit 1
}

if [ "$(id -u)" -eq 0 ]; then
	erro "nao execute como root; a YubiKey pertence ao seu usuario, nao a maquina."
fi

# Nomes viram nome de arquivo e vao para o certificado: aceite so o obvio.
# Mesma regra do ca.sh, que recusa a CSR se o CN nao passar por ela.
valida_nome() {
	[[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]] ||
		erro "nome invalido '$1'. Use letras, numeros, ponto, hifen e sublinhado."
}

# Tudo o que so importa quando se vai mexer no hardware. Fica aqui, e nao no
# corpo do script, para que ler o uso nao dependa de ter a ferramenta.
#
# Em Qubes a YubiKey chega pelo sys-usb e precisa ser atribuida a este qube.
# Sem isso o AppVM nao ve USB nenhum, e o erro do ykman nao diz o porque.
exige_yubikey() {
	command -v ykman >/dev/null 2>&1 ||
		erro "ykman nao encontrado. Instale o papel painel: sudo ./install.sh painel
      Em Qubes, instale no TemplateVM -- apt em AppVM nao persiste."

	# O PIV fala CCID, e quem serve CCID no Linux e o pcscd. Sem ele o ykman
	# ate lista a chave por USB, mas falha em toda operacao de PIV.
	if ! pgrep -x pcscd >/dev/null 2>&1 && ! systemctl is-active --quiet pcscd 2>/dev/null; then
		echo "Aviso: pcscd nao parece estar rodando; o PIV pode falhar."
		echo "       sudo systemctl enable --now pcscd"
		echo
	fi

	if [ ! -d /sys/bus/usb/devices ] || [ -z "$(ls -A /sys/bus/usb/devices 2>/dev/null)" ]; then
		erro "esta maquina nao enxerga nenhum dispositivo USB.
      Em Qubes, atribua a YubiKey a este qube a partir do dom0:
        qvm-usb attach $(hostname) sys-usb:<dispositivo>"
	fi
	ykman list 2>/dev/null | grep -q . ||
		erro "nenhuma YubiKey encontrada. Conecte a chave e tente de novo."
}

comando_matricular() {
	local apelido="$1" nome pub csr
	valida_nome "$apelido"
	exige_yubikey
	nome="$PREFIXO_PAINEL-$apelido"
	pub="$DIR_EMITIDOS/$nome.pub"
	csr="$DIR_EMITIDOS/$nome.csr"

	[ -f "$DIR_EMITIDOS/$nome.crt" ] &&
		erro "$nome ja tem certificado emitido. Apague $DIR_EMITIDOS/$nome.crt para rematricular."

	echo "YubiKey conectada:"
	ykman list | sed 's/^/  /'
	echo
	echo "Sera aplicado nesta YubiKey:"
	echo "  identidade      : $nome"
	echo "  slot PIV        : $SLOT (autenticacao)"
	echo "  chave           : $CURVA, gerada dentro da chave e nao exportavel"
	echo "  politica        : PIN $POLITICA_PIN, toque $POLITICA_TOQUE"
	echo "  arquivos        : $pub"
	echo "                    $csr"
	echo
	echo "Atencao: o applet PIV desta YubiKey sera APAGADO (ykman piv reset)."
	echo "         Certificados e chaves que estejam nele se perdem, e nao ha volta."

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

	mkdir -p "$DIR_EMITIDOS"
	chmod 700 "$DIR_CA" "$DIR_EMITIDOS"

	echo
	echo "==> Apagando o applet PIV"
	ykman piv reset --force

	# O ykman pergunta os valores; este script nao escolhe PIN de ninguem.
	# Depois do reset valem os padroes de fabrica (PIN 123456, PUK 12345678).
	echo
	echo "==> Definindo o PIN (o atual e o de fabrica: 123456)"
	ykman piv access change-pin

	echo
	echo "==> Definindo o PUK (o atual e o de fabrica: 12345678)"
	echo "    O PUK so serve para destravar o PIN errado tres vezes. Guarde-o"
	echo "    longe da chave -- de preferencia no papel, nao na mesma maquina."
	ykman piv access change-puk

	# --generate sorteia a chave de gerenciamento e --protect a guarda no
	# proprio cartao, atras do PIN. Assim nao ha um segredo a mais para o
	# operador decorar, e o modelo continua sendo PIN mais toque.
	echo
	echo "==> Trocando a chave de gerenciamento (sorteada e guardada atras do PIN)"
	ykman piv access change-management-key --generate --protect

	echo
	echo "==> Gerando o par no slot $SLOT (toque a YubiKey quando ela piscar)"
	ykman piv keys generate \
		--algorithm "$CURVA" \
		--pin-policy "$POLITICA_PIN" \
		--touch-policy "$POLITICA_TOQUE" \
		"$SLOT" "$pub"

	echo
	echo "==> Montando a CSR para CN=$nome (toque de novo)"
	ykman piv certificates request --subject "CN=$nome" "$SLOT" "$pub" "$csr"

	echo
	echo "Matriculada. A chave privada esta dentro da YubiKey e nao sai de la."
	echo
	echo "Agora assine e devolva o certificado para a chave:"
	echo "  ./ca.sh assinar $csr"
	echo "  ./yubikey.sh importar $apelido"
	echo
	echo "E matricule a OUTRA YubiKey agora, nao depois: chave PIV nao se copia."
}

# Renovacao. O certificado de painel vale 90 dias, entao isto acontece quatro
# vezes por ano -- e nao pode passar por 'matricular', que comeca apagando o
# slot. Aqui a chave fica onde esta e so se pede um certificado novo para ela.
comando_csr() {
	local apelido="$1" nome pub csr
	valida_nome "$apelido"
	exige_yubikey
	nome="$PREFIXO_PAINEL-$apelido"
	pub="$DIR_EMITIDOS/$nome.pub"
	csr="$DIR_EMITIDOS/$nome.csr"

	mkdir -p "$DIR_EMITIDOS"
	chmod 700 "$DIR_CA" "$DIR_EMITIDOS"

	echo "==> Lendo a chave publica do slot $SLOT"
	ykman piv keys export "$SLOT" "$pub" ||
		erro "o slot $SLOT esta vazio. Esta YubiKey ainda nao foi matriculada:
      ./yubikey.sh matricular $apelido"

	echo "==> Montando a CSR para CN=$nome (toque a YubiKey quando ela piscar)"
	ykman piv certificates request --subject "CN=$nome" "$SLOT" "$pub" "$csr"

	echo
	echo "CSR nova, mesma chave de sempre. Assine e devolva:"
	echo "  ./ca.sh assinar $csr"
	echo "  ./yubikey.sh importar $apelido"
}

comando_importar() {
	local apelido="$1" nome cert
	valida_nome "$apelido"
	exige_yubikey
	nome="$PREFIXO_PAINEL-$apelido"
	cert="$DIR_EMITIDOS/$nome.crt"

	[ -f "$cert" ] || erro "$cert nao encontrado. Assine antes: ./ca.sh assinar $DIR_EMITIDOS/$nome.csr"

	# Importar no slot errado e silencioso: o certificado entra, o mTLS falha
	# depois sem dizer o porque. Confere que a chave publica do certificado e
	# a mesma que o slot guarda antes de gravar.
	local pub_cert pub_slot
	pub_cert="$(openssl x509 -in "$cert" -noout -pubkey)"
	pub_slot="$(ykman piv keys export "$SLOT" - 2>/dev/null || true)"
	if [ -n "$pub_slot" ] && [ "$pub_cert" != "$pub_slot" ]; then
		erro "o certificado nao corresponde a chave do slot $SLOT desta YubiKey.
      Esta e a chave certa? Cada YubiKey tem a sua propria identidade."
	fi

	echo "==> Importando $cert no slot $SLOT"
	ykman piv certificates import "$SLOT" "$cert"

	echo
	echo "==> Conferindo o que ficou gravado"
	ykman piv certificates export "$SLOT" - |
		openssl x509 -noout -subject -issuer -enddate | sed 's/^/  /'

	echo
	echo "Pronto: $nome vive nesta YubiKey."
}

comando_estado() {
	exige_yubikey
	echo "YubiKey conectada:"
	ykman list | sed 's/^/  /'
	echo
	ykman piv info
	echo
	echo "Certificado do slot $SLOT:"
	if ykman piv certificates export "$SLOT" - 2>/dev/null |
		openssl x509 -noout -subject -issuer -enddate 2>/dev/null | sed 's/^/  /'; then
		:
	else
		echo "  vazio -- nao matriculada, ou certificado ainda nao importado"
	fi
}

SEM_PERGUNTA=0
argumentos=()
for argumento in "$@"; do
	case "$argumento" in
	--sim) SEM_PERGUNTA=1 ;;
	*) argumentos+=("$argumento") ;;
	esac
done
[ -t 0 ] || SEM_PERGUNTA=1
set -- ${argumentos[@]+"${argumentos[@]}"}

case "${1:-}" in
matricular)
	[ $# -eq 2 ] || erro "uso: $0 matricular <nome>"
	comando_matricular "$2"
	;;
csr)
	[ $# -eq 2 ] || erro "uso: $0 csr <nome>"
	comando_csr "$2"
	;;
importar)
	[ $# -eq 2 ] || erro "uso: $0 importar <nome>"
	comando_importar "$2"
	;;
estado) comando_estado ;;
*)
	sed -n '3,33p' "$0" | sed 's/^# \?//'
	exit 1
	;;
esac
