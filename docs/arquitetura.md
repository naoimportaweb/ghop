# Arquitetura do GHop

Documento vivo. Registra as decisoes tomadas e, principalmente, **por que** —
para nao reabrirmos discussao encerrada nem repetirmos analise ja feita.

GHop e "mao" em klingon.

## Principio

Nao se confia nas maquinas observadas. Tudo o mais decorre disso: o dado nao
pode ficar parado onde alguem pode edita-lo, o agente nao pode decidir sozinho,
e nenhuma maquina observada guarda segredo que valha para as outras.

## Elementos

| elemento | onde roda | funcao |
|---|---|---|
| lojmIt | maquina de borda | roteia, mascara e filtra a rede |
| coletor (`ghop-request`) | toda fronteira de NAT | observa e sumariza o que e requisitado |
| dns (`ghop-dns`) | lojmIt, opcional | resolve para a LAN, cifra para cima, nega o que o painel mandar |
| wifi (`ghop-wifi`) | lojmIt, opcional | ponto de acesso em bridge com a LAN: o radio e mais uma porta |
| filtro (`ghop-filtro`) | lojmIt, opcional | decide pelo NOME que a conexao pede (SNI, Host) o que a LAN alcanca |
| dhcp (`ghop-dhcp`) | lojmIt, opcional | entrega endereco, roteador e resolvedor a LAN |
| nftables (`ghop-nftables`) | lojmIt | o DONO do firewall: filtro, NAT e os fragmentos dos outros papeis |
| balanceador (`ghop-balanceador`) | lojmIt, opcional | com mais de uma placa de saida, decide por qual cada conexao sai: lista por placa e, no resto, balanceamento |
| agente | toda maquina observada | recebe comandos do painel e age (ainda nao existe) |
| painel | computador do operador | controla tudo; guarda as listas e a CA (ainda nao existe) |

Um elemento pode acumular papeis: este lojmIt e `lojmIt` + `agente`.

## Decisoes tomadas

### Canal e identidade

- **mTLS.** Token autentica so um lado; aqui os dois precisam se provar, porque
  o canal transporta comando, nao so dado.
- **CA propria, offline.** Nao mora em servidor nenhum. Se a CA vive numa
  maquina em servico, quem a invadir emite agentes e paineis legitimos.
- **Certificado emitido presencialmente, na instalacao.** Nunca pela rede. Isso
  dissolve o problema de bootstrap em vez de resolve-lo.
- **A chave do agente nasce na propria maquina que vai usa-la.** Gera-se o par
  e a CSR no agente; so a CSR sobe ate a CA, e so o certificado assinado
  desce. Os dois sao publicos -- nenhuma chave privada atravessa coisa
  alguma. E o mesmo principio da YubiKey, e e melhor que levar o par pronto no
  pendrive, onde a chave existiria fora da maquina de destino por um tempo.
  O "presencialmente" continua valendo para o transporte: em producao a CSR
  vai e o certificado volta no pendrive.
- **Validacao por nome** (`ghop-agente-<host>`, `ghop-painel-<nome>`), nunca por
  IP: com sub-redes aninhadas o mesmo IP privado existe em lugares diferentes, e
  IP muda sem avisar.
- **Validades invertidas:** agente 2 anos, painel 90 dias. Renovar agente custa N
  visitas; renovar painel custa uma. E o painel e a chave perigosa.
- **Revogacao no painel, sem CRL.** Maquina comprometida ignoraria a propria
  revogacao, e distribuir CRL para maquinas nao confiaveis nao faz sentido.
- **Chave do agente sem passphrase** (sobe no boot; quem le o arquivo ja e root
  ali). **Chave do painel com passphrase**, e de preferencia dentro da YubiKey.
- **Sem TOTP.** Segredo simetrico obrigaria cada maquina nao confiavel a guardar
  a semente do segundo fator. A YubiKey e assimetrica e resolve melhor: PIN mais
  toque, e os agentes so guardam parte publica.
- **Uma identidade YubiKey para toda a infra**, com as duas chaves matriculadas
  desde o inicio -- chave PIV nao se copia.
- **A chave privada do painel nasce dentro da YubiKey**
  (`projects/ghop-ca/yubikey.sh`). O par e gerado no cartao e so a parte
  publica sai: o que anda em disco e a CSR e o certificado assinado, nunca a
  chave. Por isso a matricula vem antes da emissao, e nao o contrario.
- **Slot 9a, P-256, PIN uma vez por sessao, toque a cada uso.** O 9a e o slot
  de autenticar-se perante outra maquina, que e o que o painel faz no mTLS; a
  curva e a mesma do `ca.sh`. A chave de gerenciamento do PIV e sorteada e
  guardada no proprio cartao atras do PIN, para nao existir um terceiro
  segredo a decorar. O PUK vai para o papel, longe da chave.
- **Hoje ainda nao ha YubiKey com PIV.** A chave em maos e uma Security Key
  NFC (firmware 5.2.7): so FIDO/U2F e FIDO2, `PIV -- Not available`. Ela
  autentica login, mas nao guarda X.509 e portanto nao serve de identidade de
  painel. Ate chegar uma **YubiKey 5**, o painel usa **chave em arquivo com
  passphrase** (`ca.sh painel`) -- o degrau de baixo que esta secao ja admitia.
  `yubikey.sh` fica escrito e sem uso ate la, e nunca foi exercitado contra
  hardware.

> A assimetria que guia tudo: a chave de um agente, roubada, permite **mentir
> sobre uma maquina**. A chave do painel, roubada, permite **mandar comando em
> todas**.

### Agente

- **O agente e burro.** Coleta e executa ordens explicitas; nunca decide. Recebe
  "bloqueie este IP", nunca "aplique esta politica". Agente que decide sozinho
  erra sozinho.
- **Conjunto de comandos fechado e enumerado.** No dia em que existir um comando
  generico de execucao, o GHop deixa de ser observador e vira backdoor com TLS.
  Leem `resumo`, `eventos`, `sistema` (o retrato da maquina: processador,
  memoria, disco), `interfaces`, `rotas`, `vizinhos`, `conexoes`, `trafego`, `papeis`,
  `dhcp`, `dns`, `wifi`, `nftables`, `filtro`, `listas` e `acao`. ESCREVEM
  seis: `monitorar`, `papel`, `lista`, `firewall`, `filtrar` e `limpar`. A
  divisao e o que importa na hora de acrescentar o proximo -- comando de
  leitura e barato de aceitar, comando de escrita amplia o que o painel pode
  causar. `interfaces`, `rotas` e `vizinhos` rodam `ip` e `iw` com argumentos
  fixos no codigo -- nada do painel entra na linha de comando, e nao ha
  argumento para "mostre outra coisa". Sao o retrato da maquina agora, nao
  historico.
- **`vizinhos` le a tabela ARP/NDP; nao varre nada.** E a diferenca que
  define o comando: o kernel ja mantem essa tabela para conseguir falar com
  a rede local, entao a resposta sai sem UM pacote a mais. Varredura seria
  outra coisa -- o GHop passaria a gerar trafego na rede que observa, e a
  aparecer no IDS de quem estiver do outro lado. O alcance e, por
  construcao, so a vizinhanca de camada 2: a LAN e o roteador de cima.
  Existe porque as outras fontes de "quem esta nesta rede" tem buraco no
  mesmo lugar -- `dhcp` so ve quem pediu endereco ao nosso servidor e `wifi`
  so quem esta no radio, entao maquina de IP fixo, ou LAN cujo DHCP e de
  outro (o caso normal de uma maquina observada), some das duas. Quem cruza
  as tres e o painel, em `Painel.topologia`, e **a discordancia entre elas e
  o produto**: concessao sem vizinho e aparelho calado; vizinho sem
  concessao e aparelho que fala sem nunca ter pedido endereco. O MAC vai
  inteiro porque e a unica chave que sobrevive ao cruzamento -- IP muda, e
  com NAT aninhado o mesmo IP privado existe em varios lugares.
- **`conexoes` le a tabela que a maquina JA mantem para mascarar.** Fazer NAT
  e manter estado: o `nf_conntrack` existe porque o roteamento precisa dele, e
  o proprio `firewall` do GHop casa por `ct state`. Ler `/proc/net/nf_conntrack`
  nao custa um pacote nem uma captura, e e a fonte mais completa de "quem esta
  na rede": nenhum aparelho que queira internet escapa dela, tenha endereco
  fixo, DNS proprio ou nada nosso -- que e onde `dhcp`, `dns` e `vizinhos`
  falham, cada um a seu modo. Le-se a direcao ORIGINAL de cada entrada (o
  primeiro `src=`/`dst=` da linha), que e a de antes do masquerade: ali a
  origem ainda e o cliente da LAN.
- **O agente ACUMULA o mapa, porque a tabela e viva.** Entrada expira (UDP em
  ~30 s), e uma leitura sozinha mostra o instante, nao a rede. Entao o mesmo
  amostrador do `trafego` le a cada 15 s e vai juntando os pares vistos --
  so em memoria, como todo o resto do amostrador, e com teto (5 mil pares, o
  mais velho sai primeiro) para nao virar consumo de memoria em maquina que
  roteia muito. O campo `amostras` de cada par diz **em quantas leituras ele
  apareceu**, e nao quantas conexoes houve, que e coisa que amostragem nao
  sabe; a resposta carrega `intervalo` e `vivas` para a tela poder dizer que
  fluxo curto entre duas amostras nao aparece. Numero certo com rotulo errado
  continua sendo pior do que numero nenhum.
- **Isto guarda a ORIGEM, e e uma extensao deliberada do "o coletor so
  sumariza".** Ate aqui o dado guardado era contador POR DESTINO -- o
  `ghop-requests` descarta de proposito quem falou, e o unico registro com
  origem era a tabela `eventos`, escopada aos IPs que o operador marcou. O
  mapa de conexoes guarda o par (origem, destino, porta). Tres coisas
  limitam o que isso significa: continua sendo contagem e nunca conteudo;
  vive so na memoria do agente e morre com o servico; e nao ha comando que o
  grave em disco. Persistir isso e outra decisao, e ainda nao foi tomada.

- **A janela de tempo do `resumo` diz QUEM apareceu, nunca QUANTO falou.**
  Com `minutos`, o agente devolve so as linhas cujo ultimo contato caiu no
  intervalo. O `total` de cada uma continua sendo o do DIA, porque as tabelas
  `ips` e `dominios` do coletor sao contadores acumulados por chave, sem
  evento a evento -- contagem por janela exigiria o que so a tabela `eventos`
  guarda, e essa existe apenas para os IPs que o operador mandou monitorar.
  A tela renomeia a coluna para "Total (dia)" quando ha janela, porque numero
  certo com rotulo errado e pior do que numero nenhum. O corte e feito no
  AGENTE, antes do `LIMIT`: a ordem e por total decrescente, entao filtrar no
  painel esconderia justamente o host que apareceu agora e falou pouco -- que
  e o que se procura numa janela de dez minutos. O agente ecoa `minutos` na
  resposta e o painel RECUSA se o eco nao bater: agente antigo ignora o
  argumento calado, e sem o eco a tela rotularia de "10 min" o dia inteiro.
- **`limpar` e o unico comando que DESTROI dado coletado.** Por isso e o mais
  estreito: uma especie por vez (`dominios` ou `ips`), um dia por vez, e o
  nome da tabela sai de um dicionario fixo no agente -- nunca do pedido. Nao
  toca em `eventos`, que e o registro evento a evento dos IPs que o operador
  mandou monitorar, nem na contagem de clientes do DNS: sao outras decisoes e
  outras telas. E o unico lugar em que o agente abre o banco do coletor para
  ESCRITA; todo o resto usa o modo ro, e essa separacao esta em dois helpers
  distintos para nao se perder de vista. Nao passa pela casca de linha de
  comando de proposito -- comando sem desfazer pede a confirmacao da janela,
  que diz que a tabela inteira do dia vai embora, e nao so as linhas a vista.
- **O agente diz quais PAPEIS DO GHOP tem, nao quais servicos existem.**
  `papeis` procura marca nossa (`/etc/ghop/dns`, `/etc/ghop/wifi`,
  `/etc/ghop/dhcp`, os scripts em `/usr/local/sbin`) e o estado da unidade
  conhecida. Farejar software de terceiros seria adivinhacao e devolveria ao
  painel uma lista que ele nao sabe ler. Cada papel tem seu comando de
  leitura, e o painel so oferece a tela dos que estao em `nucleo.PAPEIS`.
- **A excecao a isso e o DHCP, e o criterio da excecao e "o painel ja sabe
  ler".** Um papel marcado com `basta_a_unidade` tambem conta quando so a
  unidade existe, sem marca nossa. O `dhcp` le `/var/lib/dhcp/dhcpd.leases` e
  `/etc/dhcp/dhcpd.conf`, que sao do `isc-dhcp-server` e nao do GHop: a
  leitura funciona igual em maquina que nunca instalamos, entao reconhece-lo
  pela unidade nao e adivinhacao. E o caso de uso do projeto -- numa maquina
  observada o DHCP quase nunca foi instalado por nos, e quem entrega endereco
  decide quem fala com quem naquela rede. O que muda em relacao a regra
  acima e so o criterio de EXISTIR; a lista continua fechada, papel por papel.
- **Papel reconhecido assim vem com `origem: "sistema"`, e origem nao e
  enfeite de tela.** `desinstalar` e recusado pelo agente onde a marca do
  GHop nao existe -- e a trava vale so nos papeis com `basta_a_unidade`: e
  neles que a marca ausente quer dizer "o servico nao e nosso". Nos demais
  ela quer dizer unidade orfa, e recusar ali obrigaria a limpar por ssh.
- **Instalador so apaga arquivo com o carimbo dele.** A raiz do perigo acima
  estava no `dhcp.sh`: sem a copia `.anterior-ghop` ele fazia `rm -f` no
  `dhcpd.conf`, mesmo quando quem o escreveu foi a distribuicao. Agora ele
  so remove o que tem o carimbo "Gerado por projects/ghop-dhcp" -- o mesmo
  que a instalacao ja consultava para decidir o backup -- e preserva o
  resto dizendo por que. O `dns.sh` tinha a forma identica no
  `dnscrypt-proxy.toml` e foi corrigido junto. A recusa do agente vira, com
  isso, cinto e suspensorio: protege tambem quem roda o script por ssh, ou
  o agente publicado que ainda esteja numa versao velha.
- **`iniciar`/`parar` num servico alheio sao `systemctl` puro.** Sem marca
  nossa, `dhcp.sh ligar`/`desligar` nao escrevem regra de firewall nem
  mexem em configuracao, e usam `start`/`stop` em vez de `enable`/
  `disable --now`. Sem isso a acao anunciada como reversivel nao era: parar
  tirava do boot um servico que nao pusemos la, e `ligar` era recusado pelo
  proprio script ("ghop-dhcp ainda nao foi instalado aqui") -- a LAN ficava
  sem DHCP ate alguem entrar por ssh.
- **Existir e coisa que se pergunta ao `LoadState`, nao se deduz.** Unidade
  mascarada responde `ActiveState=inactive`, e `systemctl` que falha nao
  responde nada; tratar os dois como "nao existe" fazia servico mascarado
  virar papel em pe e servico real sumir da tela sem aviso. `papeis` tambem
  so pergunta ao systemd de quem pode entrar sem marca: a marca e um
  `stat`, e cinco processos por chamada pesam numa tela que recarrega.
- **A senha do Wi-Fi nao sai do agente.** `wifi` le o `hostapd.conf` mas
  devolve so o que descreve a rede; um comando de leitura que entregasse a
  chave transformaria observar em vazar.
- **O agente amostra o trafego das interfaces em memoria** (bytes/s a cada
  5 s, ultimos 10 min) desde que sobe, para o painel ter historico ao
  abrir a tela. Nada vai a disco e o dado e um numero por interface: e o
  mais sumarizado que se consegue. `trafego` devolve essa janela.
- **Acao sobre PAPEL e o primeiro comando que muda a maquina** (`papel`:
  instalar, iniciar, parar, desinstalar). Continua enumerado: o papel vem de
  uma tabela fixa no agente, o script e o que a tabela diz, e a acao e uma de
  quatro -- nada do painel entra em caminho de arquivo nem em linha de
  comando. Tres travas fazem a diferenca entre isto e um backdoor:
  1. **`lojmIt` e `agente` ficam de fora.** Parar o lojmIt derruba rota,
     NAT e firewall; parar o agente corta o canal por onde a ordem chegou.
  2. **O repositorio tem de ser de root e nao gravavel por outros.** O agente
     roda como root o que estiver la; se um usuario comum pudesse editar o
     script, teria root de graca -- o GHop abriria o buraco que existe para
     vigiar. O agente confere isso a cada pedido e recusa.
  3. **A acao roda destacada** (systemd-run), uma por vez, e o comando
     responde na hora. Instalacao leva minutos e prender a conexao ate o fim
     travaria o painel; o acompanhamento e o comando `acao`.
  Desinstalar desfaz o que o instalador fez e restaura a configuracao
  anterior, mas **nao apaga dado coletado**: banco do coletor, concessoes de
  DHCP e log de bloqueio ficam. Apagar rastro em nome de limpeza e o oposto
  do que o GHop existe para fazer.
- **Privilegio hoje e `root`** (`/etc/ghop/ghop.conf`), porque o agente precisa
  agir e o coletor precisa capturar. O caminho e separar quem fala na rede de
  quem executa, conversando por socket local. O `ghop.conf` e o lugar unico onde
  isso muda.

### Painel

- **PySide6, com nucleo sem Qt.** O painel e aplicacao de desktop (Qt +
  Python), mas o que ele *faz* -- cadastro dos nos, canal mTLS, comandos --
  mora em `nucleo.py`, que nao importa Qt, nao imprime e nao encerra
  processo: erro vira `ErroGHop`. A interface e casca **descartavel**: hoje
  uma CLI, amanha a janela, e as duas sobre o mesmo nucleo. Mesmo arranjo que
  o `fussador` usa no workspace, e pelo mesmo motivo -- casca se troca, regra
  nao se reescreve.
- **Toda chamada de rede do nucleo bloqueia.** A casca Qt tem de chama-la
  fora da thread de UI. Esta escrito la, porque e o erro que se comete uma
  vez por projeto.
- **Os nos sao cadastrados no painel**, em `~/.ghop/nos.json` (modo 600). O
  agente nao sabe da existencia de nenhum outro no; juntar as visoes e
  tarefa daqui, e e o que faz sentido depois de cada NAT ter colapsado seus
  clientes em um endereco so.
- **Cadastrar confere antes de gravar.** `nos adicionar` faz o handshake e so
  grava se o CN do certificado for o do no pedido -- cadastrar sem conferir e
  cadastrar um engano, e engano de cadastro so aparece meses depois. Ha
  `--sem-testar` para a maquina que esta desligada na hora.
- **Recadastrar o mesmo nome troca o endereco.** E a consequencia pratica de
  o nome ser a chave primaria: quando o IP do no muda, nao se cria no novo.
- **A casca nao inventa comando.** `nucleo.COMANDOS` recusa o que nao estiver
  na lista antes mesmo de abrir a conexao, para o conjunto fechado nao
  depender so da disciplina de quem escreve tela.
- **Juntar respostas e trabalho do PAINEL, e `Painel.topologia` e o primeiro
  caso.** Ate ela, todo metodo do nucleo repassava um comando; este pede
  quatro (`interfaces`, `vizinhos`, `dhcp`, `wifi`) e devolve uma coisa que
  nenhum agente sabe responder -- porque a resposta esta na DISCORDANCIA
  entre as fontes, e cada uma delas e cega num lugar diferente. E o mesmo
  principio da classificacao (que tambem so acontece aqui): o agente entrega
  cru, o painel e quem cruza. Papel ausente vira uma linha em `faltas`, nao
  um erro: `dhcp` e `wifi` sao recusados onde nao existem, e uma maquina sem
  os dois ainda tem topologia.
- **A tela nao afirma identidade por endereco.** Quando o IP de um vizinho
  bate com o de um no cadastrado, isso aparece como PALPITE, escrito assim.
  Identidade e por nome e quem a prova e o certificado -- afirmar pelo
  endereco seria desfazer, na tela, a regra que o canal inteiro segue.

### Servicos externos

- **Consulta a servico de fora sai do PAINEL, nunca do agente.** Dar ao agente
  um comando que faz pedido de saida o transformaria em proxy da rede
  observada, e o conjunto fechado de comandos existe exatamente para isso nao
  acontecer.
- **Nada consulta sozinho.** Abrir uma tela, trocar de aba ou passear pelos
  servicos nao gera trafego nenhum: so o clique do operador consulta, um
  servico por vez. Perguntar e acao ATIVA e atribuivel -- conta ao servidor,
  e a quem estiver no caminho, que alguem investiga aquele nome.
- **Tudo o que responde e guardado** (`~/.ghop/consultas/<servico>/`). O cache
  existe menos por velocidade e mais por privacidade: sem ele, abrir a mesma
  tela tres vezes pergunta tres vezes. E da valor de prova -- o que o servico
  dizia NAQUELA data so se sabe se foi capturado.
- **Em servico pago, o cache vira orcamento.** O botao diz o custo antes, a
  tela mostra o consumo, e reconsultar pede confirmacao. A contagem e local e
  a tela avisa disso: nao enxerga consultas feitas por fora do painel.
- **Chave de API nunca no repositorio nem em `~/.ghop`.** Vem do ambiente ou
  de `~/.env`, e nao passa por linha de comando, que vaza no `ps`. O codigo
  guarda so o NOME da variavel.
- **Servico e registro, nao codigo espalhado** (`nucleo.SERVICOS`). Cada um
  declara que especies atende, se custa, e devolve o resumo como pares
  `[rotulo, valor]` -- a tela e generica e nao sabe de qual servico veio.
  Acrescentar servico e uma entrada no dicionario.

### Dado

- **So sumariza.** Contadores por IP e por dominio, sem registro de evento
  individual.
- **Nao captura conteudo.** O filtro casa apenas SYN de TCP, que nao carrega
  dados, e perguntas DNS. Snaplen de 512 bytes e nenhuma opcao de despejo.
- **SYN na saida da WAN, DNS na entrada da LAN.** O SYN se le onde se sabe o
  que de fato foi para a internet. A pergunta DNS nao: na WAN ela chega pela
  metade ou nem chega -- resolvedor com cache so sobe o que nao tinha, DNS
  cifrado (dnscrypt-proxy, DoH) sobe ilegivel, e VPN sobe so o tunel. Na LAN
  o cliente pergunta em claro, toda vez, antes de qualquer dessas coisas. E
  a mesma razao de a monitoracao de IP ler a LAN: e o lado em que a
  informacao ainda existe. Sem interface de LAN o coletor le tudo na WAN e
  aceita a cegueira.
- **Um banco por dia**, `REQUESTS_DD_MM_YYYY`, rodizio automatico.
- **Listas branca e negra vivem no painel**, nao no agente. Duas consequencias:
  mudar a lista nao toca em servidor nenhum, e a classificacao acontece na
  leitura -- ao acrescentar uma regra, **todo o historico ja coletado e
  reclassificado junto**.
- Casamento por **sufixo** de dominio. Lista de nomes exatos e manutencao
  infinita.
- Whitelist de dominio **nao** cobre os IPs correspondentes: CDN troca endereco
  o tempo todo. Sao duas listas separadas, e a de IP envelhece mal.

### DNS (`ghop-dns`)

- **Liga e desliga sem tocar no resto.** E um servico a mais no lojmIt;
  o coletor, o agente e o painel funcionam iguais com ele ligado ou
  desligado. Por isso o coletor le o DNS na LAN e nao no resolvedor: se
  dependesse do log dele, desligar o `ghop-dns` cegaria a coleta.
- **`dnscrypt-proxy`, pacote Debian, escutando so no endereco da LAN.** Os
  clientes perguntam em claro ao lojmIt -- e o que o coletor ve -- e daqui
  para cima sai cifrado. O socket nao escuta em `0.0.0.0`, e o firewall
  ainda fecha a 53 por fora da LAN: DNS aberto ao mundo e amplificador.
- **O boot e o unico momento em que este papel quebra sozinho, e sao tres
  travas.** O socket do systemd abre em `sockets.target`, cedo, antes de a
  LAN ter endereco -- com o papel `wifi` e pior, que ai a LAN e uma bridge.
  O bind morria com `Cannot assign requested address`, e socket unit **nao
  tem `Restart=`**: falhava uma vez e ficava falhada ate alguem subir a mao,
  com o servico morrendo atras dela (`Dependency failed`). As tres travas
  cobrem coisas diferentes e por isso estao todas la: `ExecStartPre`
  (`espera-lan.sh`, publicado em `/usr/local/sbin/ghop-dns-espera.sh`) espera
  ate 30s pelo IP da LAN e sai no instante em que ele aparece, `FreeBind`
  deixa o bind valer num endereco que ainda nao existe, e
  `Restart=on-failure` com `StartLimitIntervalSec=0` faz o servico insistir
  de 5 em 5 segundos -- sem o `StartLimitIntervalSec` o teto de 5 partidas em
  10s do systemd marcaria a unidade como falhada justamente no caso que
  importa. A espera **nunca recusa a subida**: sai sempre com 0, porque
  trocar resolvedor atrasado por resolvedor nenhum nao e conserto.
- **O bootstrap nao pergunta a si mesmo.** Para saber com quem falar cifrado,
  o `dnscrypt-proxy` busca a lista de resolvedores por HTTPS, e para isso
  precisa resolver um nome antes de existir resolvedor. Sem
  `bootstrap_resolvers` ele cai no resolvedor do sistema, que nesta maquina
  pode ser ele proprio. Ficam fixos `9.9.9.9` e `1.1.1.1`, usados **so nisso**,
  em claro, e so quando o cache de 72h vence: consulta de cliente nenhuma
  passa por la. E o unico vazamento em claro que este papel aceita, e o preco
  de nao depender de um resolvedor que ainda nao subiu.
- **Servidor de cima: sem log e sem filtro.** Filtrar e papel desta maquina,
  onde a lista e auditavel; log de quem esta acima nao e auditavel daqui. O
  provedor e escolhido pela latencia entre os que declaram isso, salvo se o
  operador fixar um.
- **O resolvedor NAO registra as consultas.** `query_log` e `nx_log` ficam
  desligados: registro nome a nome, cliente a cliente, e exatamente o que a
  regra "so sumariza" proibe, e o coletor ja conta o que se pergunta. **So a
  consulta negada fica registrada**, porque negar e acao, e acao tem de
  deixar rastro de quem tentou e o que.
- **O painel acrescenta e tira UMA regra por vez** (acoes `adicionar_regra`
  e `remover_regra` do comando `lista`, em qualquer lista), e nao manda a
  lista inteira -- para isso ha o texto colado, que substitui uma lista de
  uma vez. E o contrario do `monitorar`, de proposito: aquela
  lista e so do painel, esta tambem e mantida na maquina e um dia recebera
  listas importadas -- mandar estado inteiro daqui apagaria o que nao veio
  do painel. Quando o painel for dono das listas importadas, a sincronia de
  estado volta a fazer sentido. O agente valida o nome contra a sintaxe do
  dnscrypt e recusa espaco, `#`, barra e quebra de linha: a lista e um
  arquivo lido por outro programa, e um `#` deixaria comentar a regra
  seguinte, uma quebra de linha escreveria duas regras onde se pediu uma.
- **Varias listas por especie, e o arquivo que o resolvedor le e GERADO.**
  O `dnscrypt-proxy` aceita um arquivo de negacao e um de excecao. Para ter
  a lista escrita a mao ao lado de listas grandes, cada uma vira um arquivo
  em `negados.d/` ou `permitidos.d/`, e o agente concatena as ativas. Isso
  compra o que importa: desligar uma lista nao apaga nada, e da para
  experimentar uma lista de cem mil linhas e voltar atras sem perder as
  regras proprias. A lista `propria` nao se apaga, so se esvazia.
- **Lista importada e lista COLADA.** Nao ha download em lugar nenhum: nem
  no agente, que nunca faz pedido para fora, nem no painel, que nao busca
  sozinho. O operador baixa, ABRE, le, e cola o texto na janela. Essa
  leitura e a diferenca entre importar e confiar numa URL, e e ela que
  impede uma lista publica de virar canal para bloquear o que o adversario
  quiser. O texto vai em pedacos de 32 kB, porque uma lista publica tem
  megabytes e o limite de linha do protocolo e 64 kB -- afrouxar esse
  limite para todos por causa de um comando seria pagar caro pelo caminho
  errado.
- **Linha que nao vira nome valido e CONTADA e descartada**, e linha com
  varias palavras que nao seja formato 'hosts' e recusada em vez de cortada
  na primeira palavra: cortar transformaria texto estranho em dominio
  plausivel, e uma lista de cem mil linhas passaria a bloquear coisa que
  ninguem escreveu.
- **A lista de negacao e do painel; o lojmIt so a aplica.** `negados.txt` e
  `permitidos.txt` em `/etc/ghop/dns/` no formato do proprio
  `dnscrypt-proxy`. Leva-las ao lojmIt sera o primeiro comando de acao do
  conjunto fechado, no molde do `monitorar`: estado inteiro, nao delta.
  Ate la, edita-se a mao e `dns.sh recarregar`.
- **Negar e marcar sao coisas diferentes.** A lista negra do painel diz
  "aparece em vermelho"; bloquear e um passo a mais, escolhido regra a
  regra. Quer-se VER quem fala com um dominio ruim antes de cega-lo.
- **Regras de firewall dos outros papeis vivem em `/etc/ghop/nft.d/`**, e o
  script do lojmIt as aplica depois das dele. O lojmIt reescreve as regras
  base a cada instalacao; sem isso, cada reinstalacao apagaria a 53.

### Filtro de camada de aplicacao (`ghop-filtro`)

- **Existe porque o resolvedor so alcanca quem pergunta a ele.** Cliente da
  LAN que use DoH, DNS proprio ou cache sai sem passar pelo `ghop-dns`, e a
  lista de negacao nao vale nada para ele -- e a aba Clientes do DNS ja
  mostra em vermelho quantos sao. O nome pedido, esse, vai na PROPRIA
  conexao: o SNI do ClientHello e o Host do HTTP. E o ultimo lugar em que
  ainda da para decidir sem adivinhar.
- **Nao descriptografa, e nao ha caminho para isso.** O SNI e o unico campo
  que o TLS manda em claro, antes de qualquer chave ser combinada. O filtro
  le esses bytes, decide, e dai em diante so emenda os dois lados. Nenhum
  certificado do GHop e instalado em cliente nenhum. Um proxy que
  terminasse TLS veria tudo e seria MITM da propria rede -- exatamente o que
  o principio proibe --, e foi por isso que a opcao caiu na hora de decidir.
- **O buraco esta a vista, e e a conta que a tela mostra.** Quem nao manda
  nome nao e filtrado por nome, porque nao ha nome: IP direto, protocolo
  que nao seja TLS nem HTTP, e o ECH quando chegar. Esse total aparece como
  "sem nome legivel" ao lado dos outros, em vez de a tela sugerir cobertura
  que nao existe. Fecha-lo e a politica `bloquear` (lista branca), que
  quebra tudo o que nao foi previsto -- e escolha do operador, com aviso.
- **Papel OPCIONAL, e o lojmIt nao depende dele.** Como o `dns` e o `wifi`:
  liga, desliga e desinstala sem tocar no resto.
- **Falha FECHADA, e isso e deliberado.** O servico fica no CAMINHO do dado:
  se cair, o redirecionamento continua no firewall e as portas 80 e 443 da
  LAN param. Filtro que falha aberto e filtro em que nao se pode confiar --
  e o buraco apareceria justamente quando o servico estivesse com problema.
  O preco esta escrito no instalador e no aviso da tela, e a saida e uma
  ordem so (`filtro.sh desligar`, ou Parar no painel), que tira o
  redirecionamento junto. O `Restart=always` sem `StartLimit` existe pelo
  mesmo motivo: defeito repetido nao pode virar rede parada ate alguem
  reparar.
- **A porta e 7010, dentro da faixa 7000-7100** que o nftables ja fecha para
  fora da LAN. Nao e arrumacao: um proxy transparente alcancavel da internet
  e um proxy aberto.
- **O redirecionamento so pega o que ENTRA pela LAN e vai para endereco
  publico.** Trafego nascido no proprio lojmIt nao passa por `prerouting`,
  entao o filtro nunca redireciona a propria saida -- o laco nao existe por
  construcao, e nao por cuidado. E conexao de um cliente para outro, ou para
  o lojmIt, fica de fora: rede interna nao e "para fora", que e a mesma
  regra do coletor.
- **Registra SO o que bloqueou** (quando, cliente, nome, porta, regra), pelo
  mesmo motivo do resolvedor: negar e acao, e acao tem de deixar rastro. O
  que PASSOU nao e registrado nome a nome em lugar nenhum -- o coletor ja
  responde quem falou com quem, e um segundo registro nome a nome na mesma
  maquina seria o oposto do "so sumariza".
- **As regras sao do painel; o lojmIt so aplica.** Molde do `monitorar`:
  estado inteiro, nao delta (comando `filtrar`). Ao contrario do `lista` do
  resolvedor, aqui nao ha nenhuma outra fonte de regra na maquina, entao
  mandar tudo nao apaga o que veio de outro lugar. Um conjunto so para a
  infra: duas politicas de saida sao duas coisas para manter em sincronia, e
  na primeira divergencia ninguem sabe qual esta valendo.
- **Campos, nunca texto de regra**, como no `firewall`: tipo, valor, acao e
  nota, cada um conferido contra lista fechada ou contra uma expressao de
  nome de host. O que chega ao disco e DADO em JSON.
- **A ORDEM das regras e semantica.** A primeira que casa decide, inclusive
  quando permite -- e assim que se abre excecao dentro de um bloqueio largo.
  A tela poe excecao no topo por padrao, porque `permitir` no fim, embaixo do
  bloqueio que deveria abrir, nao faz nada: e o erro que se comete na
  primeira vez.
- **Sem regex, ao contrario das listas branca e negra.** Aquelas rodam na
  LEITURA, no painel, sobre dado ja coletado; estas rodam no CAMINHO DO
  DADO, a cada conexao da LAN. Expressao regular ali e latencia
  imprevisivel na rede inteira e um jeito de o operador travar a propria
  saida sem entender por que. Casa-se por sufixo (que e por ROTULO:
  `exemplo.com` nao pega `naoexemplo.com`), exato, prefixo ou pedaco.
- **Teto de 500 regras, e o teto e do caminho do dado**, nao do protocolo. O
  filtro percorre a lista a cada conexao. Lista publica de cem mil nomes
  continua sendo assunto do resolvedor, que tem arquivo e indice proprios
  para isso.
- **A tela diz quando o painel e o no discordam.** Regra escrita no painel so
  vale depois do "Enviar ao no", e sem esse aviso o operador ve a tabela
  mudar e sai supondo que a maquina mudou junto.
- **Bloquear continua sendo escolha regra a regra**, e nao a lista negra
  inteira: a decisao de "negar e marcar sao coisas diferentes", da secao do
  DNS, vale igual aqui. Quer-se VER quem fala com um dominio ruim antes de
  cega-lo.

### Balanceador de saida (`ghop-balanceador`)

- **O papel NAO se chama `saida`, e o motivo e namespace.** `saida` ja e uma
  VISAO (`nucleo.VISOES`, a "Analise de saida") e ja tem classe no `gui.py`.
  Papel e visao sao dois namespaces, mas a mesma palavra nos dois seria o tipo
  de ambiguidade que este projeto nao se permite justamente em nome -- entao o
  papel se chama como o dono o chamou: `balanceador`.
- **Dois estagios, e a ordem e a especificacao**: `ENVIO PARA IP FORA -> lista
  da placa A -> lista da placa B -> ... -> balanceamento`. A primeira lista
  que casa decide, como no `ghop-filtro` e pelo mesmo motivo -- e assim que se
  prende um destino a uma placa sem ter de descrever todo o resto. O que nao
  casa em lista nenhuma cai no balanceamento. Sao os dois algoritmos pedidos:
  afinidade explicita por lista, e distribuicao no que sobra.
- **A decisao e POR CONEXAO, nunca por pacote.** Pacote a pacote, o mesmo
  fluxo sai por duas placas, com dois IPs de origem: o outro lado descarta e o
  TLS reseta. O sintoma seria "a internet esta instavel", nao "o balanceador
  esta errado" -- defeito que se paga caro para diagnosticar. Por isso a marca
  escolhida e gravada na conexao (`ct mark`) e **restaurada antes de qualquer
  decisao**: a primeira regra da cadeia devolve a escolha ja tomada e encerra a
  travessia. Fluxo em curso nunca e redecidido, nem quando a lista muda.
- **Dois algoritmos, e a diferenca nao e de gosto.** `rodizio` (`numgen inc`)
  distribui melhor e aceita **peso**, que e o que acomoda placas de velocidades
  diferentes -- uma USB 2.0 nao segura o que uma gigabit de barramento segura.
  `afinidade` (`jhash` do IP de origem) distribui pior, porque cliente pesado
  nao se divide, mas mantem o IP publico de um cliente estavel enquanto a placa
  estiver de pe: e o que portal que prende login a endereco exige. O peso vira
  **quantidade de slots** num mapa do nftables, que e o unico jeito de pesar
  sem o kernel precisar saber o que e peso.
- **So o que ENTRA pela LAN e vai para endereco publico.** Trafego nascido no
  lojmIt nao passa por `prerouting`, entao a resposta do agente ao painel sai
  pelo caminho normal e nao por placa sorteada -- se saisse, voltaria por outra
  placa e o canal do painel morreria. Conexao de cliente para cliente, ou para
  o proprio lojmIt, tambem fica fora: rede interna nao e "para fora". Mesma
  regra do coletor e do filtro, e a mesma lista de faixas privadas, de
  proposito: "ir para fora" tem de querer dizer a mesma coisa nos tres.
- **IPv6 nao e balanceado, e isso esta escrito na tela.** A cadeia devolve o
  que nao for IPv4 antes de decidir. Marcar pacote v6 para uma tabela de rota
  v4 nao e cobertura parcial, e defeito: o buraco a vista e melhor que a
  cobertura inventada -- a mesma conta do "sem nome legivel" do filtro.
- **Nao escolhe por nome.** Rota decide por IP, e o nome pedido so existe
  dentro da conexao -- quem o le e o `ghop-filtro`. Lista aqui e IP ou CIDR.
  Um dia o filtro podera escolher a placa ao emendar os dois lados; sao
  camadas diferentes, e misturar as duas numa lista so faria o operador
  escrever regra que nao vale onde ele pensa que vale.
- **O comando do painel ainda nao existe.** Hoje se edita
  `/etc/ghop/balanceador/regras.json` a mao e se roda `balanceador.sh recarregar` -- o
  mesmo degrau em que a lista do resolvedor ficou antes do comando `lista`.
  Quando entrar, e **um de leitura** (`saida`: placas, pesos, quem esta no ar,
  regras) e **um de escrita** (`rotear`: estado inteiro, nao delta, no molde do
  `filtrar`), e o de escrita e decisao a tomar aqui -- comando de escrita
  amplia o que o painel pode causar.
- **Nome de interface e gateway NUNCA vem do painel.** O painel mandara nome de
  placa, peso e lista; o mapa nome -> interface, gateway vive em
  `/etc/ghop/balanceador/placas`, que e fato da maquina. Interface entra em regra de
  nft e em linha de comando do `ip`: aceita-la do painel seria aceitar shell
  por outro caminho. E a mesma razao de o `firewall` receber campos e nunca
  texto de regra.
- **Placa sem carrier sai da rotacao, E PERDE A LISTA DELA.** O que estava
  preso a uma placa caida cai no balanceamento, em vez de ir para uma tabela de
  rota sem default -- que seria buraco negro silencioso. Degradar e obrigatorio;
  o painel ve a placa fora e o operador decide se era essa placa ou nada.
  Quando nenhuma esta no ar, o fragmento sai VAZIO e a maquina volta a sair
  pelo caminho normal.
- **A SONDA existe, e ela revoga em parte "o agente nunca faz pedido para
  fora".** Decisao do dono em 12/10/2026, depois de a casa ficar sem internet:
  link e gateway NAO provam que a placa passa trafego, e sem conferir isso o
  balanceador manda a fatia dela para um buraco negro -- o sintoma e "a
  internet funciona pela metade", que e das coisas mais caras de diagnosticar.
  O padrao e `sonda=nexthop`: pinga o gateway da PROPRIA placa, um salto, na
  rede local dela -- isso nao e pedido para fora, e pega o caso comum (roteador
  do provedor morto). Um IPv4 explicito prova a internet de verdade e e
  **opt-in**, justamente porque ai a maquina passa a falar com terceiro por
  conta propria. `sonda=nao` volta ao comportamento anterior.
- **Failover e imediato; a QUARENTENA atrasa so a volta.** Caiu uma, a que
  sobrou leva tudo na mesma aplicacao -- sem sorteio, porque nao se sorteia
  entre uma. O que espera X minutos (`quarentena=`, padrao 5) e o RETORNO da
  que caiu. Sem isso, placa instavel entra e sai a cada ciclo da sonda: a USB
  desta casa caiu sozinha (`r8152 ... status -71`) depois de tres minutos de
  uso, e cada entrada e saida remexe firewall e conntrack. Estabilidade vale
  mais que aproveitar a placa trinta segundos antes. Recaida REINICIA o
  relogio, e nao continua de onde parou.
- **Reavaliar e de minuto em minuto, e so reaplica quando MUDA.** O
  temporizador tem unidade propria, porque mandar `start` numa oneshot com
  `RemainAfterExit=yes` e no-op silencioso -- a sonda nunca rodaria. E a
  aplicacao compara uma assinatura do que esta no kernel: sem isso seriam 1440
  reescritas de ruleset por dia a troco de nada, e cada reescrita e uma janela.
- **Regra de ORIGEM (`ip saddr`) prende uma maquina a uma placa**, e e o unico
  tipo que olha para dentro da LAN. Serve para o que o dono pediu: a estacao
  dele sempre pela saida estavel, para o trabalho nao depender de qual placa o
  rodizio sorteou.
- **A ordem das REGRAS decide, nao a ordem das placas.** Isto foi um defeito:
  juntando todos os destinos de uma placa num `set` so, quem decidia era a
  ordem das placas, enquanto a tela e o `--testar` respondiam pela ordem das
  regras. Painel e kernel discordando em silencio e o pior defeito possivel
  aqui. Agora cada GRUPO de regras consecutivas da mesma placa e do mesmo
  campo vira um set, emitido na ordem -- e ha teste que falha se a ordem se
  perder.
- **Tirar placa caida nao e decidir politica**, e e por isso que o agente pode
  fazer sozinho: nao se manda trafego para cabo desligado. Qualquer coisa alem
  disso -- preferir a placa mais rapida, fugir de perda, medir latencia -- e
  decisao, e decisao mora no painel. Em particular, **nao ha verificacao
  ATIVA** de link (ping no proximo salto): ela faria o agente mandar pacote
  para fora por conta propria, contra "o agente nunca faz pedido para fora" e
  contra "o agente e burro". Se um dia valer a pena, e decisao a tomar aqui, e
  nao detalhe de implementacao.
- **Reaplicar e evento, nao laco.** O servico e `oneshot`: aplica e sai. Quem
  manda reaplicar quando placa cai ou volta e uma regra de udev -- nada fica
  vigiando em laco, o que tambem quer dizer que este papel nao fica no caminho
  do dado. Se ele morrer, nada para: as regras ja estao no kernel.
- **`rp_filter` frouxo (2) e condicao de funcionar, nao arrumacao.** Com rota
  por politica a resposta volta pela placa por onde a conexao saiu, que nao e a
  da rota default; com `rp_filter` estrito o kernel a descarta, e o sintoma e
  "a segunda placa nao funciona". Fica em `/etc/sysctl.d/`, com o porque
  escrito la.
- **Placa USB tem o nome preso ao MAC.** Nome por caminho de barramento
  (`enp0s20f0u2`) muda quando se troca a porta, e toda regra deste papel
  aponta por NOME: trocar de porta mandaria parte do trafego para uma interface
  que nao existe, sem erro na tela. O `.link` em `/etc/systemd/network/` resolve
  isso, e ate a placa ser replugada ela aparece fora da rotacao -- nao se manda
  trafego para placa que nao se sabe nomear. O arquivo **nao** e apagado no
  desinstalar: apagar faria a placa voltar a trocar de nome.
- **O fragmento e conferido depois de aplicado, e desfeito se o nft recusar.**
  Kernel sem `numgen`, versao de nft antiga: o `ligar` confere se a cadeia
  existe e, se nao, remove rotas e fragmento. Deixar regra de politica em pe
  com marca que ninguem poe seria o pior dos mundos -- trafego marcado para uma
  tabela vazia. Aqui degradar quer dizer voltar ao que a maquina fazia antes.
- **A marca e deste papel.** Nada mais no GHop usa `meta mark`/`ct mark` hoje;
  quem for usar tem de combinar a divisao aqui, porque a marca e um numero so
  por pacote. Tabela de rota e prioridade de regra sao DERIVADAS da ordem das
  placas, nao configuraveis: numero de tabela e detalhe de implementacao, e
  deixar o operador escolher so cria colisao com o que ja existe na maquina.

### Wi-Fi (`ghop-wifi`)

- **O radio entra em bridge com o cabo; nao e uma rede nova.** Uma sub-rede
  so para o Wi-Fi isolaria cabo de radio, mas custaria segunda faixa de
  DHCP, segunda captura no coletor e regras a mais -- e o que se quer e
  justamente o contrario: que celular e tablet sejam clientes da MESMA LAN,
  com IP e MAC proprios, visiveis no DNS e na monitoracao como qualquer
  maquina de cabo. A bridge (`br0`) passa a ser a LAN, e todos os outros
  papeis apontam para ela.
- **Liga e desliga so o radio.** A bridge fica mesmo com o Wi-Fi desligado,
  porque o cabo passa por ela; desfaze-la seria reinstalar tudo de novo.
- **WPA2-PSK, CCMP, um SSID.** Sem TKIP, que e quebrado; sem WPA3 por ora,
  porque o SAE em modo AP no driver `rtw88` nao e confiavel. Clientes do
  radio se enxergam entre si (`ap_isolate=0`), como no cabo: e uma LAN so.
- **O hostapd e quem poe o radio na bridge**, nao o ifupdown: interface
  sem fio so aceita entrar em bridge depois de virar AP.
- **A bridge herda o MAC do cabo.** Assim o ARP de quem ja falava com o
  lojmIt nao muda, e a troca de interface passa despercebida.
- **Dominio regulatorio fixado** (`cfg80211 ieee80211_regdom`), senao o
  driver fica no minimo de potencia e sem canais de 5 GHz.

### Firewall (`ghop-nftables`)

- **Um dono so para o ruleset.** As regras moravam dentro do `lojmIt.sh`,
  junto com interface e encaminhamento. O firewall e a unica coisa da
  maquina que se reescreve INTEIRA a cada aplicacao (`nft flush ruleset`):
  com dois scripts escrevendo, o ultimo apaga o outro e ninguem descobre.
  Desde 2026-09-05 o papel `nftables` e o dono; o `lojmIt` ficou com
  interfaces e `ip_forward`, e chama o nftables passando WAN e LAN.
- **Fragmentos em `/etc/ghop/nft.d/*.sh`**, aplicados DEPOIS das regras
  base. E o que deixa cada papel abrir a sua porta (53 do dns, 67 do dhcp)
  sem conhecer o arquivo de regras e sem que a reinstalacao do firewall
  apague o que ele fez.
- **`counter` em toda regra.** Sem contador nao ha como distinguir regra que
  protege de regra que sobra: a tela Roteamento mostra o que cada uma pegou,
  e regra zerada aparece em cinza.
- **O painel escreve regra, mas manda CAMPOS, nunca texto de regra**
  (comando `firewall`: tabela, cadeia, regra, remover). O que ele envia vai
  para `/etc/ghop/nftables/regras.json`, que e DADO, e de la o agente gera
  `/etc/ghop/nft.d/painel.sh`, montando cada linha do nft com valores que
  ele mesmo conferiu contra expressoes estreitas. Aceitar a regra pronta
  seria aceitar shell: o fragmento roda como root. Nenhuma string do painel
  chega a um shell sem passar por essa validacao.
- **So se apaga daqui o que o painel escreveu.** Regras base e fragmentos
  dos outros papeis sao de quem os instalou; duas maos escrevendo o mesmo
  arquivo e o problema que este papel veio resolver.
- **O canal do painel nao se corta sozinho**, e isso e estrutural, nao
  cuidado: os fragmentos entram DEPOIS das regras base, e o nftables decide
  na primeira que casa. Como a base ja aceita SSH e a faixa 7000-7100 vindos
  da LAN, uma regra de bloqueio escrita pelo painel nao alcanca o proprio
  agente.
- **Desligar este papel APAGA o firewall**, e e o unico cujo desligar piora
  a seguranca da maquina. O painel avisa isso antes do clique.

### Rede

- Faixa **7000-7100** reservada aos servicos internos, ja fechada para fora da
  LAN no nftables (TCP e UDP). A **53** abre so na LAN quando o `ghop-dns`
  esta ligado.
- **A LAN e uma interface so**, a do cabo ou a bridge quando ha Wi-Fi. E o
  que `LAN_IF` significa em todos os instaladores, e o `install.sh` a troca
  pela bridge assim que o papel `wifi` a cria.
- **A WAN, essa, pode ser mais de uma** (papel `balanceador`). A assimetria e
  deliberada: juntar duas placas na LAN e uma bridge, que o Wi-Fi ja faz e que
  nao muda quem decide nada; ter duas saidas e escolher, conexao por conexao,
  por onde sair -- e escolha precisa de dono, de ordem e de registro. `WAN_IF`
  continua sendo a saida PRINCIPAL, a da rota default e a que o nftables
  mascara na regra base; as demais vivem em `/etc/ghop/balanceador/placas` e ganham
  masquerade pelo fragmento.
- SSH so pela interface da LAN.
- Firewall **e** mTLS, nunca um ou outro: sao camadas distintas. O nftables
  reduz quem pode tentar; o mTLS responde quem esta falando.

## O que o NAT aninhado impoe

Uma sub-rede mascarada dentro de outra -- inclusive a que o Qubes ja cria --
tem tres consequencias que sao caras de corrigir depois:

1. **Cega-se a cada NAT.** Atras de um masquerade, todos os clientes colapsam em
   um endereco so. Nenhum filtro conserta: a informacao e destruida, nao
   escondida. Por isso **cada fronteira de NAT precisa do seu proprio coletor**,
   e quem junta as visoes e o painel.
2. **IP nao identifica maquina.** A chave primaria de tudo e o **nome do
   agente**; IP e atributo que muda.
3. **A direcao da conexao vira gargalo.** Painel -> agente exige encaminhar porta
   em cada nivel de aninhamento. Agente -> painel atravessa qualquer profundidade
   sem configuracao, porque sair sempre e permitido e entrar nunca e.

Decisao pragmatica: **manter o agente escutando na 7000 agora**, porque resolve
o presente e comando sincrono e melhor de usar. Mas tratar como revogavel --
comando e resposta devem ser mensagens autocontidas, para que inverter a direcao
depois seja trocar o transporte, e nao reescrever o agente.

## Qubes

O operador usa Qubes, entao o aninhamento ja existe: `sys-net` -> `sys-firewall`
-> AppVMs, com NAT em cada salto.

- O lugar certo do coletor e o **`sys-firewall`**: ali o trafego ainda nao foi
  mascarado e cada AppVM tem seu proprio `10.137.x.x`. A origem deixa de ser um
  IP e passa a ser **o nome do qube** -- informacao que so existe la dentro.
- `apt install` na VM em execucao **nao persiste**: instala-se no TemplateVM.
- So o `/rw` sobrevive ao reboot, e `sys-firewall` reinicia com frequencia. Ou
  bind-dirs em `/rw/config`, ou -- melhor, e coerente com o principio -- o dado
  sai rapido da maquina e o banco local vira buffer.
- A YubiKey chega pelo `sys-usb` e precisa ser atribuida ao qube do painel.
- **Hoje a CA mora no qube `pessoal`**, em `~/.ghop/ca`. E provisorio, e esta
  abaixo do que o principio pede: `pessoal` e qube de uso diario, e a chave da
  CA vale por toda a infra. O destino e um **qube dedicado, sem netvm**, so
  para CA e painel. Quando ele existir, **todas as chaves serao trocadas** --
  CA, agentes e paineis --, porque chave que ja viveu no qube de uso geral nao
  volta a ser confiavel so por mudar de lugar. A YubiKey e o unico caso em que
  a troca e opcional -- a chave privada dela nunca esteve no qube, so a CSR
  passou por ali --, entao da para reemitir so o certificado ou rematricular
  do zero; a decisao fica para a hora.

## Em aberto

- Separacao privilegio/rede dentro do agente.
- Como o painel alcanca elementos fora da LAN.
- Encadeamento por hash dos registros (adulteracao hoje nao deixa rastro).
- Auditoria dos comandos emitidos, guardada fora da maquina auditada.
- Perfis de acesso: hoje quem tem a chave faz tudo. Um `ghop-leitor-*` que so le
  e barato agora, caro depois que o agente existir.
- Migrar CA e painel para um qube dedicado e trocar as chaves (ver Qubes).
- Lembrar de renovar o painel antes dos 90 dias. Hoje nao ha nada que avise --
  `ca.sh listar` mostra o vencimento, mas so para quem for olhar.

## Ordem sugerida

1. YubiKeys resetadas, PIN definido, as duas matriculadas. -- **parado**: a
   chave em maos e uma Security Key, sem PIV (ver `evolucao.md`). Enquanto
   isso o painel usa chave em arquivo.
2. CA propria criada, offline. -- **feito**, com senha de teste; refazer na
   reinstalacao.
3. Agente minimo: mTLS na 7000, um unico comando de leitura. -- **feito**
   (`projects/ghop-agente`, comando `resumo`).
4. Painel minimo: conecta, autentica, le. -- **feito**
   (`projects/ghop-painel`, uma conexao e um comando por vez).
5. Listas branca e negra no painel.
6. Coletor no `sys-firewall` do Qubes. -- hoje ele roda so no lojmIt.
7. Comandos de acao, um a um, sempre enumerados.
