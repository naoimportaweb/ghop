#!/bin/bash
#
# espera-lan.sh - espera o endereco da LAN existir nesta maquina.
#
# Publicado pelo dns.sh em /usr/local/sbin/ghop-dns-espera.sh e chamado no
# ExecStartPre do dnscrypt-proxy.socket. Existe porque sockets.target e cedo
# no boot: o socket abre antes de a interface da LAN ganhar endereco (com o
# papel wifi e pior -- a LAN vira uma bridge, que demora mais ainda). Sem o
# endereco o bind falha, e socket unit NAO tem Restart=: falha uma vez e fica
# falhada ate alguem subir a mao.
#
# Nao e sleep fixo: dorme so o que precisar e segue no instante em que o
# endereco aparece -- boot com a LAN ja pronta nao paga nada. E sai SEMPRE
# com 0: se o endereco nao vier no tempo, quem segura o bind e o FreeBind do
# socket, e recusar a subida aqui trocaria um resolvedor atrasado por
# resolvedor nenhum.
#
# Uso: ghop-dns-espera.sh <ip> [tentativas]   (uma tentativa por segundo)

set -uo pipefail

ip_alvo="${1:-}"
tentativas="${2:-30}"

if [ -z "$ip_alvo" ]; then
	echo "espera-lan: sem endereco para esperar; seguindo" >&2
	exit 0
fi

tem_endereco() {
	ip -4 -o addr show scope global 2>/dev/null |
		awk '{print $4}' | cut -d/ -f1 | grep -qx "$ip_alvo"
}

for _ in $(seq "$tentativas"); do
	if tem_endereco; then
		exit 0
	fi
	sleep 1
done

# Chegou aqui, o bind vai depender do FreeBind. Fica dito no journal, que e
# onde alguem vai procurar quando o DNS da LAN demorar a responder no boot.
echo "espera-lan: $ip_alvo nao apareceu em ${tentativas}s; seguindo com FreeBind" >&2
exit 0
