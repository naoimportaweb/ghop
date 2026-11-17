# ghop

GHop -- "mao" em klingon.

Ambiente para observar o que acontece em maquinas em que nao se confia e,
adiante, agir sobre elas a partir de um painel unico.

## Instalacao

Em cada no, clonar o repositorio e rodar apenas o ponto de entrada:

```sh
git clone https://github.com/naoimportaweb/ghop.git
cd ghop
sudo ./install.sh <papel> [<papel>...]
```

| papel | o que instala |
|---|---|
| `lojmIt` | nftables, firewall e NAT, servico `lojmIt` |
| `agente`  | coletor de IPs e dominios (`ghop-requests.service`) |
| `dns`     | resolvedor da LAN cifrado para cima, com lista de negacao (opcional, liga e desliga) |
| `wifi`    | ponto de acesso na placa sem fio, em bridge com a LAN (opcional, liga e desliga) |
| `dhcp`    | servidor DHCP da LAN: endereco, roteador e resolvedor (opcional, liga e desliga) |
| `filtro`  | filtro de camada de aplicacao: decide pelo nome pedido (SNI, Host) o que a LAN alcanca (opcional, liga e desliga) |
| `balanceador` | escolha de saida com mais de uma placa: lista por placa e, no que sobrar, balanceamento de carga (opcional, liga e desliga) |
| `nftables`| firewall e NAT: o dono do ruleset (instalado junto com o `lojmIt`) |
| `painel`  | ferramentas de YubiKey e certificado (maquina do operador) |

Papeis se somam. Um lojmIt que tambem se observa:

```sh
sudo ./install.sh lojmIt agente
```

Os instaladores perguntam as interfaces de rede, mostram o que sera aplicado e
pedem confirmacao antes de mexer em qualquer coisa. `--sim` aceita as sugestoes
sem perguntar -- use apenas sabendo o que sera aplicado.

## Estrutura

```
install.sh              ponto de entrada unico
scripts/service.sh      pacotes e configuracao comum, por papel
scripts/lojmIt.sh      provisiona o lojmIt (firewall, NAT, forwarding)
projects/ghop-request/  coletor de IPs e dominios requisitados para a WAN
projects/ghop-dns/      resolvedor da LAN (dnscrypt-proxy) com lista de negacao
projects/ghop-wifi/     ponto de acesso (hostapd) em bridge com a LAN
projects/ghop-dhcp/     servidor DHCP da LAN (isc-dhcp-server)
projects/ghop-nftables/ firewall e NAT: o dono do ruleset
projects/ghop-balanceador/    escolha de saida: lista por placa e balanceamento
projects/ghop-agente/   agente: recebe comandos do painel sobre mTLS
projects/ghop-painel/   painel minimo: conecta em um agente, autentica e le
projects/ghop-ca/       autoridade certificadora do mTLS (roda so no painel)
                        e a matricula da YubiKey do operador
config/ghop.conf        configuracao comum (instalada em /etc/ghop/)
docs/arquitetura.md     decisoes de arquitetura e o porque de cada uma
docs/evolucao.md        o que ainda vai ser comprado, trocado ou refeito
```

`scripts/` sao scripts soltos que preparam uma maquina; `projects/` sao os
subprojetos do GHop.

## Consultar o que foi coletado

Um banco SQLite por dia, em `/var/ghop/tmp/`:

```sh
sqlite3 /var/ghop/tmp/REQUESTS_$(date +%d_%m_%Y) \
  'SELECT dominio,total,ultimo FROM dominios ORDER BY total DESC LIMIT 20;'
```

## DNS da LAN

O papel `dns` poe um resolvedor no lojmIt, atendendo so a LAN, que cifra a
pergunta para cima (DNSCrypt ou DoH) e se recusa a responder o que estiver em
`/etc/ghop/dns/negados.txt`. So a consulta negada e registrada, em
`/var/log/dnscrypt-proxy/bloqueados.log`; as demais nao.

```sh
sudo ./install.sh dns                        # instala e liga
sudo ./projects/ghop-dns/dns.sh estado
sudo ./projects/ghop-dns/dns.sh desligar     # para e fecha a 53; listas ficam
sudo ./projects/ghop-dns/dns.sh ligar
sudo ./projects/ghop-dns/dns.sh recarregar   # depois de editar as listas
```

O instalador nao mexe no DHCP nem no `resolv.conf` do lojmIt: aponte os
clientes da LAN para o endereco dele. A porta 53 e aberta so na LAN, por uma
regra em `/etc/ghop/nft.d/` que o `lojmIt.sh` aplica junto com as dele.

## Wi-Fi

O papel `wifi` transforma a placa sem fio do lojmIt em ponto de acesso e a
poe em **bridge com o cabo**: o radio nao e uma rede nova, e mais uma porta
da LAN. DHCP, DNS, firewall e coletor continuam os mesmos, so passam a olhar
para a bridge (`br0`), e cada celular ou tablet que entra vira um cliente da
LAN com IP e MAC proprios.

```sh
sudo ./install.sh wifi lojmIt dns agente   # o wifi vem primeiro: cria a bridge
sudo ./projects/ghop-wifi/wifi.sh estado
sudo ./projects/ghop-wifi/wifi.sh desligar  # apaga o radio; a bridge fica
sudo ./projects/ghop-wifi/wifi.sh ligar
```

Depois do `wifi`, a LAN da maquina e a bridge: os demais papeis devem ser
instalados (ou reinstalados) com `LAN_IF=br0`, e o `install.sh` faz isso
sozinho quando eles vem na mesma linha. So funciona com `ifupdown`
(`/etc/network/interfaces`).

## DHCP da LAN

O papel `dhcp` adota o `isc-dhcp-server` e gera o `dhcpd.conf`: faixa,
roteador e resolvedor. O resolvedor entregue e o proprio lojmIt quando o
`ghop-dns` esta ligado, e o de cima quando nao esta.

```sh
sudo ./install.sh dhcp
sudo ./projects/ghop-dhcp/dhcp.sh estado
sudo ./projects/ghop-dhcp/dhcp.sh desligar   # ninguem novo recebe endereco
```

As concessoes aparecem na tela DHCP do no, no painel. Ela nao depende deste
instalador: aparece em qualquer no que tenha o `isc-dhcp-server`, tenha sido
o GHop a instalar ou nao -- que e o caso normal de uma maquina observada. A
tela "Servicos" diz de onde o servico veio, e "Desinstalar" fica desligado no
que nao foi o GHop que instalou. Iniciar e parar valem nos dois casos: num
servico alheio o script so faz `systemctl start`/`stop`, sem tocar em
configuracao, firewall, nem no que sobe no boot.

## Filtro de camada de aplicacao

O papel `filtro` decide, **pelo nome que a conexao pede**, o que a LAN pode
alcancar: o SNI do ClientHello no TLS e o cabecalho Host no HTTP em claro.

Existe porque o `ghop-dns` so alcanca quem pergunta a ele. Cliente que use
DoH, DNS proprio ou cache sai sem passar pelo resolvedor, e a lista de
negacao nao vale nada para ele -- a aba Clientes do DNS mostra em vermelho
quantos sao. O nome, esse, vai na propria conexao.

**Nao descriptografa nada.** O SNI e o unico campo que o TLS manda em claro,
antes de qualquer chave ser combinada. O filtro le, decide, e dai em diante
so emenda os dois lados. Nenhum certificado do GHop e instalado em cliente
nenhum, e nao ha caminho por onde conteudo cifrado passe a ser legivel.

```sh
sudo ./install.sh filtro                          # instala e liga
sudo ./projects/ghop-filtro/filtro.sh estado
sudo ./projects/ghop-filtro/filtro.sh desligar    # a LAN volta a sair direto
sudo /usr/local/sbin/ghop-filtro.py --testar exemplo.com   # confere uma regra
```

As regras sao escritas **no painel**, na tela "Filtro" do no, e enviadas por
comando -- o agente recebe a lista pronta e a aplica. A ordem importa: a
primeira regra que casa decide, e uma excecao (`permitir`) so vale acima do
bloqueio que ela abre.

**Enquanto ligado, o servico fica no caminho do trafego**: se ele cair, as
portas 80 e 443 da LAN param. E deliberado -- filtro que falha aberto e
filtro em que nao se pode confiar --, e a saida e `filtro.sh desligar`, que
tira o redirecionamento junto.

So o que for BLOQUEADO fica registrado, em
`/var/log/ghop/filtro-bloqueados.log`. O que passou nao e registrado nome a
nome: disso o coletor ja cuida.

## Escolha de saida e balanceamento de carga

Com mais de uma placa de saida, o papel `balanceador` decide por qual delas cada
conexao da LAN vai para fora, em **dois estagios**:

```
ENVIO PARA IP FORA -> lista da placa A -> lista da placa B -> ... -> BALANCEAMENTO
```

A **primeira lista que casa decide** -- e assim que se prende um destino a uma
placa sem descrever todo o resto. O que nao esta em lista nenhuma cai no
balanceamento, que e um de dois algoritmos:

| algoritmo | como escolhe | quando serve |
|---|---|---|
| `rodizio` | contador que gira, com **peso** por placa | distribui melhor; o peso acomoda placas de velocidades diferentes |
| `afinidade` | hash do IP de **origem** | o mesmo cliente sempre pela mesma placa, o que importa para sessao e portal |

```sh
sudo ./install.sh balanceador                          # instala e liga (pergunta as placas)
sudo ./projects/ghop-balanceador/balanceador.sh estado
sudo ./projects/ghop-balanceador/balanceador.sh desligar     # volta a sair toda pela WAN principal
sudo /usr/local/sbin/ghop-balanceador.py --estado      # placas, pesos, regras, quem esta no ar
sudo /usr/local/sbin/ghop-balanceador.py --testar 203.0.113.9   # por qual placa sairia, e por que
```

As regras e os pesos ficam em `/etc/ghop/balanceador/regras.json`. **Ainda nao ha
comando do painel para escreve-los**: hoje edita-se a mao e roda-se
`balanceador.sh recarregar` -- o mesmo degrau em que a lista do resolvedor ficou
antes do comando `lista`.

A decisao e **por conexao, nunca por pacote**: a placa escolhida e gravada na
propria conexao e restaurada nos pacotes seguintes. Balancear pacote a pacote
faria o mesmo fluxo sair por dois IPs de origem -- o outro lado descarta, e o
sintoma seria "a internet esta instavel".

**Placa sem link sai da rotacao sozinha** (o udev reaplica quando ela cai ou
volta), e a lista dela cai no balanceamento em vez de ir para uma tabela de
rota sem default. Sem placa nenhuma no ar, o papel nao escreve regra e a
maquina volta a sair pelo caminho normal.

Tres coisas ficam **de fora**, de proposito: IPv6 (sai pelo caminho normal --
marcar pacote v6 para tabela de rota v4 e defeito, nao cobertura parcial);
escolha por **nome** (rota decide por IP; nome quem le e o `ghop-filtro`); e
trafego nascido no proprio lojmIt (nao passa por `prerouting`, entao a
resposta do agente ao painel nunca sai por placa sorteada).

**Placa USB** tem o nome preso ao MAC em `/etc/systemd/network/`: nome por
caminho de barramento muda quando se troca a porta, e regra de rota aponta por
nome. Ate a placa ser replugada ela aparece fora da rotacao -- que e o certo:
nao se manda trafego para placa que nao se sabe nomear.

## Os nos

Um "no" e uma maquina observada. Quem conhece os nos e o **painel** -- o
agente nao sabe da existencia de nenhum outro. O cadastro fica em
`~/.ghop/nos.json`.

```sh
cd projects/ghop-painel
./ghop-painel.py nos adicionar gateway 192.168.101.1
./ghop-painel.py nos
./ghop-painel.py resumo gateway limite=20
./ghop-painel.py resumo gateway dia=02_09_2026 --json
```

A chave primaria de um no e o **nome**, nunca o endereco: o endereco diz so
onde bater, e o certificado diz com quem se esta falando. `nos adicionar` faz
o handshake antes de gravar e recusa se o nome nao bater; recadastrar o mesmo
nome apenas troca o endereco, que e o que acontece quando o IP muda.

O painel e PySide6 + Python, mas o que ele faz mora em `nucleo.py`, **sem
Qt**: a interface e casca. Ha duas: a linha de comando acima e a janela
(`./gui.py`), que abre cada no numa subjanela com uma aba por visao --
"Dados" (a maquina: trafego das interfaces ao vivo, interfaces e rotas) e "Analise de saida" (o que ela
pediu para fora).

A janela de um no comeca em "Maquina" (o que ela e: processador, memoria,
disco) e tem "Servicos", a unica tela que MUDA a maquina: instalar, iniciar,
parar e desinstalar cada papel, com confirmacao dizendo o que a acao causa.
Depois vem "Dados", que ganha uma aba por papel instalado (hoje so Wi-Fi).
Nao ha aba de topologia: topologia e propriedade da REDE, nao de uma maquina,
e por isso mora no menu Inventario (Ctrl+T). Assunto que nao cabe em aba escondida vira tela
inteira entre "Dados" e "Analise de saida": "Roteamento" (papel `nftables`),
"DNS", "DHCP" e "Filtro". Quem diz o que existe em cada maquina e o proprio
agente.

O conjunto de comandos e **fechado**: `resumo`, `eventos`, `sistema`,
`interfaces`, `rotas`, `vizinhos`, `conexoes`, `trafego`, `papeis`, `dhcp`, `dns`, `wifi`,
`nftables`, `filtro`, `listas` e `acao` leem; `monitorar`, `papel`, `lista`,
`firewall`, `filtrar` e `limpar` escrevem -- este ultimo e o unico que APAGA
dado coletado, e so pela janela.
Acrescentar comando e decisao de arquitetura, nao detalhe -- ver
`docs/arquitetura.md`.

```sh
./ghop-painel.py interfaces gateway
```

## Quem esta na rede

`vizinhos` le a tabela ARP/NDP que o kernel do no ja mantem -- **nao ha
varredura**: nenhum pacote a mais entra na rede observada. `topologia` cruza
essa tabela com quem pediu endereco (`dhcp`), quem esta no radio (`wifi`) e o
que a maquina e (`interfaces`).

```sh
./ghop-painel.py vizinhos gateway     # a tabela ARP crua
./ghop-painel.py conexoes gateway     # o mapa de quem falou com quem
./ghop-painel.py topologia gateway    # cruzada, com a leitura de cada caso
```

`conexoes` e a fonte mais completa das quatro, e tambem nao custa captura: a
maquina ja mantem a tabela do `nf_conntrack` porque **mascarar exige manter
estado**. Nenhum aparelho que queira internet escapa dela -- tenha endereco
fixo, DNS proprio ou nada nosso. Como a tabela e viva (entrada expira), o
agente le a cada 15 s e vai **acumulando** o mapa; a resposta diz desde
quando acumula e de quanto em quanto le, porque fluxo curto entre duas
amostras nao aparece.

Cruzar e o ponto, porque nenhuma fonte sozinha responde "quem esta aqui" -- e
**a discordancia entre elas e o que interessa**:

| o que se ve | o que quer dizer |
|---|---|
| concessao no DHCP, sem vizinho | tem endereco reservado e esta calado (desligado) |
| vizinho, sem concessao nossa | fala sem nunca ter pedido endereco: IP fixo, ou DHCP que nao e o nosso |
| no radio, sem endereco | associado ao Wi-Fi, ainda sem IP |

A chave e o **MAC**, nunca o IP: endereco muda, e com NAT aninhado o mesmo IP
privado existe em varios lugares. O MAC tambem diz o FABRICANTE: os tres
primeiros bytes sao o OUI da IEEE, e a traducao e local (pacote `ieee-data`,
instalado pelo papel `painel`) -- nunca uma consulta de rede. Aparelho que
sorteia o endereco por privacidade, como celular moderno, aparece marcado
assim em vez de "desconhecido".

A tela e uma ARVORE e nao um grafo: internet, saida, no, segmento, aparelho.
Aparelho falando com aparelho na mesma LAN nao passa pelo no -- um switch
entrega o quadro direto --, entao traco entre dois hosts seria invencao. Quando o endereco de um vizinho bate com o
de um no cadastrado, a tela sugere o nome -- **como palpite**, porque
identidade quem prova e o certificado.

## Certificados

O mTLS entre painel e agentes usa uma CA propria, que **nao mora em servidor**:
ela roda na maquina do operador. Ver `docs/arquitetura.md`.

```sh
cd projects/ghop-ca
./ca.sh criar                 # uma vez so
./ca.sh painel pessoal        # certificado de painel (90 dias, chave cifrada)
./ca.sh listar
GHOP_PAINEL_SENHA=... ./teste-mtls.py gateway pessoal   # prova o handshake
```

Para o agente, **a chave nasce na maquina dele** e nunca sai de la -- so a CSR
sobe e o certificado desce, ambos publicos. Na maquina a ser observada:

```sh
sudo openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
  -out /etc/ghop/certs/agente.key
sudo chmod 600 /etc/ghop/certs/agente.key
sudo openssl req -new -key /etc/ghop/certs/agente.key \
  -subj "/CN=ghop-agente-$(hostname)" -out agente.csr
```

Leve `agente.csr` ate o operador, assine, e leve o certificado de volta --
**no pendrive, nao pela rede**:

```sh
./ca.sh assinar agente.csr    # gera ghop-agente-<host>.crt
```

`./ca.sh agente <host>` tambem existe e gera o par inteiro aqui, mas ai a
chave privada precisa viajar. Prefira a CSR.

## YubiKey

A identidade do painel mora numa YubiKey, e a chave privada dela nasce dentro
do cartao: nunca existe em disco. Matricule **as duas** desde o inicio --
chave PIV nao se copia.

```sh
cd projects/ghop-ca
./yubikey.sh matricular yubikey1                       # apaga o PIV, PIN/PUK, chave e CSR
./ca.sh assinar ~/.ghop/ca/emitidos/ghop-painel-yubikey1.csr
./yubikey.sh importar yubikey1                         # devolve o certificado para a chave
./yubikey.sh estado
```

O certificado de painel vale 90 dias. Para renovar, `csr` no lugar de
`matricular` -- a chave fica onde esta e so o certificado e trocado:

```sh
./yubikey.sh csr yubikey1
./ca.sh assinar ~/.ghop/ca/emitidos/ghop-painel-yubikey1.csr
./yubikey.sh importar yubikey1
```

Em Qubes, os pacotes do papel `painel` tem de ser instalados no **TemplateVM**
(`apt` em AppVM nao persiste) e a YubiKey precisa ser atribuida ao qube do
painel pelo dom0, com `qvm-usb attach`.
