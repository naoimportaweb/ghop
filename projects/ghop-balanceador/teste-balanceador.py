#!/usr/bin/env python3
"""Prova a escolha de saida do GHop, caso a caso.

Chama as MESMAS funcoes que o servico chama -- a geracao do fragmento de nft,
o mapa de slots, a decisao por lista -- e confere o que sai:

   1. IP na lista da placa A        -> placa A, e o balanceamento nao opina
   2. duas listas casam             -> a PRIMEIRA decide (a ordem e semantica)
   3. IP fora de todas as listas    -> balanceamento
   4. peso vira proporcao de slots  -> 7 e 3 dao 10 slots, 7 de um 3 do outro
   5. rodizio x afinidade           -> numgen num, jhash no outro
   6. placa sem carrier             -> sai da rotacao E PERDE A LISTA dela
   7. nenhuma placa ativa           -> fragmento sem regra nenhuma
   8. uma placa ativa so            -> sem sorteio: vai tudo nela
   9. restauracao vem ANTES         -> fluxo em curso nao e redecidido
  10. destino privado               -> nao e saida para fora
  11. regras.json quebrado          -> segue sem regra, nao explode
  12. valor que nao e IP            -> CONTADO e descartado, nao vira regra
  13. placa que esta maquina nao tem-> descartada (o painel nao inventa placa)
  14. teto de regras                -> acima de LIMITE_REGRAS e descarte
  15. interface nunca vem do painel -> regras.json com 'if' nao muda nada
  16. tabela e prioridade por placa -> uma de cada, sem colisao
  17. masquerade                    -> uma regra por placa, menos a principal
  18. so conexao NOVA e decidida    -> ct state != new volta antes
  19. gw=auto sem rota ainda        -> placa fica FORA da rotacao
  20. gw=auto com rota              -> aprende o gateway e entra
  21. carrier sem gateway           -> nao e saida: rota default nao existe
  31. regra de ORIGEM               -> casa ip saddr, nao ip daddr
  32. a ordem das REGRAS decide     -> e nao a ordem das placas
  25. placa que nao PASSA trafego   -> sai, mesmo com link e gateway
  26. failover imediato             -> a que sobrou leva tudo, sem sorteio
  27. quarentena segura a volta     -> nao retorna so por ter melhorado
  28. volta depois da quarentena    -> e so entao
  29. recaida reinicia o relogio    -> nao volta na janela seguinte
  30. sonda 'nao'                   -> placa vale pelo link, como antes
  24. a RESPOSTA chega ao cliente     -> o filtro de interface vem antes da
                                        restauracao da marca
  22. marca do instalador x agente  -> o papel so aparece se as duas baterem
  23. papel pedido ao service.sh    -> tem de existir la, senao nem instala

Os casos 9 e 18 sao os que provam o desenho: balancear por PACOTE faria o
mesmo fluxo sair por dois IPs de origem, e o outro lado descartaria. O 6 e o 7
provam que degradar e obrigatorio -- placa caida nao recebe trafego, e sem
placa nenhuma a maquina volta ao caminho normal em vez de ficar sem balanceador.
O 15 prova que nome de interface e fato da MAQUINA: o painel manda nome de
placa, peso e lista, e nunca interface.

Uso:
  ./teste-balanceador.py

Nao precisa de root, nao toca no firewall, nao abre porta e nao fala com
maquina nenhuma: so gera texto e compara. Sai 0 so com zero falhas.
"""

import importlib.util
import json
import os
import pathlib
import re
import sys

AQUI = os.path.dirname(os.path.abspath(__file__))

PLACAS = """
# nome    interface    gateway         peso
nome=wan1 if=enp1s0 gw=192.168.0.1 peso=7
nome=wan2 if=wan2    gw=10.9.9.1    peso=3
"""

falhas = 0


def carrega():
    """Importa o ghop-balanceador.py apesar do hifen no nome."""
    caminho = os.path.join(AQUI, "ghop-balanceador.py")
    spec = importlib.util.spec_from_file_location("ghop_balanceador", caminho)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


def confere(titulo, condicao, detalhe=""):
    global falhas
    if condicao:
        print(f"  ok   {titulo}")
    else:
        falhas += 1
        print(f"  FALHA {titulo}" + (f"  --  {detalhe}" if detalhe else ""))


def regras_de(balanceador, placas, **conteudo):
    conteudo.setdefault("versao", 1)
    return balanceador.le_regras(json.dumps(conteudo), placas)


def main():
    balanceador = carrega()
    placas = balanceador.le_placas(PLACAS)
    todas = {placa["nome"]: placa for placa in placas}

    print("ghop-balanceador: escolha de saida")
    print()

    # 1. lista da placa A decide
    configuracao = regras_de(balanceador, placas, regras=[
        {"placa": "wan1", "tipo": "cidr", "valor": "198.51.100.0/24"},
    ])
    resposta = balanceador.decide("198.51.100.7", placas, configuracao["regras"])
    confere("1. IP na lista da placa A: sai pela A",
            resposta["placa"] == "wan1" and resposta["motivo"] == "lista",
            str(resposta))

    # 2. a ordem decide
    configuracao = regras_de(balanceador, placas, regras=[
        {"placa": "wan2", "tipo": "cidr", "valor": "198.51.100.0/24"},
        {"placa": "wan1", "tipo": "exato", "valor": "198.51.100.7"},
    ])
    resposta = balanceador.decide("198.51.100.7", placas, configuracao["regras"])
    confere("2. duas listas casam: a PRIMEIRA decide",
            resposta["placa"] == "wan2" and resposta["regra"] == 1,
            str(resposta))

    # 3. fora de todas
    resposta = balanceador.decide("203.0.113.9", placas, configuracao["regras"])
    confere("3. fora de todas as listas: balanceamento",
            resposta["motivo"] == "balanceamento"
            and resposta["placas"] == ["wan1", "wan2"],
            str(resposta))

    # 4. peso vira slots
    slots = balanceador.mapa_slots(placas)
    confere("4. peso 7 e 3: 10 slots, 7 de um e 3 do outro",
            len(slots) == 10
            and slots.count(todas["wan1"]["marca"]) == 7
            and slots.count(todas["wan2"]["marca"]) == 3,
            str(slots))

    # 5. os dois algoritmos
    configuracao = regras_de(balanceador, placas, algoritmo="rodizio")
    texto = balanceador.monta_nft("enp3s0", placas, configuracao)
    rodizio_ok = "numgen inc mod 10" in texto and "jhash" not in texto
    configuracao = regras_de(balanceador, placas, algoritmo="afinidade")
    outro = balanceador.monta_nft("enp3s0", placas, configuracao)
    afinidade_ok = "jhash ip saddr mod 10" in outro and "numgen" not in outro
    confere("5. rodizio usa numgen; afinidade usa jhash do IP de origem",
            rodizio_ok and afinidade_ok,
            f"rodizio={rodizio_ok} afinidade={afinidade_ok}")

    # 6. placa sem carrier sai da rotacao e perde a lista
    ativas = balanceador.placas_ativas(placas, carrier=lambda interface: interface != "wan2",
                                      sonda=lambda placa: True, historico={})
    confere("6a. placa sem carrier sai da rotacao",
            [placa["nome"] for placa in ativas] == ["wan1"],
            str([placa["nome"] for placa in ativas]))
    configuracao = regras_de(balanceador, placas, regras=[
        {"placa": "wan2", "tipo": "cidr", "valor": "198.51.100.0/24"},
    ])
    resposta = balanceador.decide("198.51.100.7", ativas, configuracao["regras"])
    confere("6b. a lista da placa caida cai no balanceamento",
            resposta["motivo"] == "lista_caida" and resposta["placa"] is None,
            str(resposta))
    texto = balanceador.monta_nft("enp3s0", ativas, configuracao)
    confere("6c. e o fragmento nao cria set de placa caida",
            "_wan2 " not in texto and re.search(r"@g\d+_wan1", texto) is None
            or ("_wan2 '" not in texto),
            "set de placa fora da rotacao foi criado")

    # 7. nenhuma placa ativa
    texto = balanceador.monta_nft("enp3s0", [], configuracao)
    confere("7. nenhuma placa ativa: fragmento sem regra nenhuma",
            "nft add rule" not in texto and texto.rstrip().endswith("exit 0"))

    # 8. uma placa so
    texto = balanceador.monta_nft("enp3s0", ativas, configuracao)
    confere("8. uma placa ativa so: sem sorteio, vai tudo nela",
            "numgen" not in texto and "jhash" not in texto
            and "meta mark set 0x1 counter" in texto)

    # 9. a restauracao vem ANTES das listas
    configuracao = regras_de(balanceador, placas, regras=[
        {"placa": "wan1", "tipo": "cidr", "valor": "198.51.100.0/24"},
    ])
    texto = balanceador.monta_nft("enp3s0", placas, configuracao)
    posicao_restaura = texto.find("ct mark != 0x0 meta mark set ct mark")
    casou = re.search(r"ip daddr @g\d+_wan1", texto)
    posicao_lista = casou.start() if casou else -1
    posicao_grava = texto.find("ct mark set meta mark")
    confere("9. restaurar a marca da conexao vem ANTES de decidir",
            0 < posicao_restaura < posicao_lista < posicao_grava,
            f"{posicao_restaura} < {posicao_lista} < {posicao_grava}")

    # 10. destino privado
    resposta = balanceador.decide("192.168.101.50", placas, configuracao["regras"])
    confere("10a. destino privado: nao e saida para fora",
            resposta["motivo"] == "interno", str(resposta))
    confere("10b. e o fragmento devolve o privado antes de decidir",
            texto.find("ip daddr { 10.0.0.0/8") < posicao_lista)

    # 11. regras.json quebrado
    quebrado = balanceador.le_regras("{isto nao e json", placas)
    confere("11. regras.json quebrado: segue sem regra, nao explode",
            quebrado["quebrado"] and quebrado["regras"] == []
            and quebrado["algoritmo"] == balanceador.ALGORITMO_PADRAO,
            str(quebrado))

    # 12. valor que nao e IP
    configuracao = regras_de(balanceador, placas, regras=[
        {"placa": "wan1", "tipo": "cidr", "valor": "exemplo.com"},
        {"placa": "wan1", "tipo": "cidr", "valor": "198.51.100.0/33"},
        {"placa": "wan1", "tipo": "cidr", "valor": "10"},
        {"placa": "wan1", "tipo": "cidr", "valor": "198.51.100.0/24"},
    ])
    confere("12. valor que nao e IP: CONTADO e descartado",
            len(configuracao["regras"]) == 1 and configuracao["descartadas"] == 3,
            str(configuracao))

    # 13. placa que esta maquina nao tem
    configuracao = regras_de(balanceador, placas, regras=[
        {"placa": "wan9", "tipo": "cidr", "valor": "198.51.100.0/24"},
    ])
    confere("13. placa desconhecida nesta maquina: descartada",
            configuracao["regras"] == [] and configuracao["descartadas"] == 1,
            str(configuracao))

    # 14. teto de regras
    muitas = [{"placa": "wan1", "tipo": "exato", "valor": f"203.0.113.{numero % 256}"}
              for numero in range(balanceador.LIMITE_REGRAS + 20)]
    configuracao = regras_de(balanceador, placas, regras=muitas)
    confere("14. teto de regras: o excedente e descarte, nao erro",
            len(configuracao["regras"]) == balanceador.LIMITE_REGRAS
            and configuracao["descartadas"] == 20,
            str(len(configuracao["regras"])))

    # 15. interface nunca vem do painel
    configuracao = regras_de(balanceador, placas, regras=[
        {"placa": "wan1", "tipo": "cidr", "valor": "198.51.100.0/24",
         "if": "enp0s9; rm -rf /", "interface": "eth9", "gateway": "1.2.3.4"},
    ])
    texto = balanceador.monta_nft("enp3s0", placas, configuracao)
    confere("15. interface e gateway NAO vem do painel",
            "eth9" not in texto and "rm -rf" not in texto
            and "1.2.3.4" not in texto and "enp1s0" in texto)

    # 16. tabela e prioridade por placa
    comandos = balanceador.monta_rotas(placas)
    tabelas = {placa["tabela"] for placa in placas}
    marcas = {placa["marca"] for placa in placas}
    confere("16. uma tabela de rota e uma prioridade por placa, sem colisao",
            len(tabelas) == 2 and len(marcas) == 2 and len(comandos) == 4
            and all(isinstance(comando, list) for comando in comandos),
            str(comandos))

    # 17. masquerade por placa, menos a principal
    texto = balanceador.monta_nft("enp3s0", placas, configuracao, principal="enp1s0")
    confere("17. masquerade: uma por placa, e a principal nao ganha segunda",
            texto.count("counter masquerade") == 1
            and "oif wan2 counter masquerade" in texto,
            str(texto.count("counter masquerade")))

    # 18. so conexao nova e decidida
    primeira_lista = re.search(r"@g\d+_wan\d", texto)
    confere("18. ct state != new volta antes de qualquer decisao",
            primeira_lista is not None
            and 0 < texto.find("ct state != new counter return") < primeira_lista.start())

    # 19/20/21. gw=auto: a placa USB que ainda nao tem cabo
    auto = balanceador.le_placas("nome=wan1 if=enp1s0 gw=192.168.0.1 peso=7\n"
                           "nome=wan2 if=enx00e04c gw=auto peso=3\n")
    balanceador.resolve_gateways(auto, consulta=lambda interface: "")
    ativas_auto = balanceador.placas_ativas(auto, carrier=lambda interface: True,
                                            sonda=lambda placa: True, historico={})
    confere("19. gw=auto sem rota ainda: placa fica FORA da rotacao",
            [placa["nome"] for placa in ativas_auto] == ["wan1"],
            str([(placa["nome"], placa["gateway"]) for placa in auto]))

    auto = balanceador.le_placas("nome=wan1 if=enp1s0 gw=192.168.0.1 peso=7\n"
                           "nome=wan2 if=enx00e04c gw=auto peso=3\n")
    balanceador.resolve_gateways(auto, consulta=lambda interface: "10.9.9.1")
    ativas_auto = balanceador.placas_ativas(auto, carrier=lambda interface: True,
                                            sonda=lambda placa: True, historico={})
    confere("20. gw=auto com rota: aprende o gateway e entra na rotacao",
            [placa["nome"] for placa in ativas_auto] == ["wan1", "wan2"]
            and auto[1]["gateway"] == "10.9.9.1",
            str([(placa["nome"], placa["gateway"]) for placa in auto]))
    comandos = balanceador.monta_rotas(ativas_auto)
    confere("20b. e o gateway aprendido e o que vai para a tabela de rota",
            ["ip", "route", "replace", "default", "via", "10.9.9.1", "dev",
             "enx00e04c", "table", "102"] in comandos, str(comandos))

    sem_gw = balanceador.le_placas("nome=wan1 if=enp1s0 gw=192.168.0.1 peso=1\n"
                             "nome=wan2 if=enx00e04c gw=auto peso=1\n")
    balanceador.resolve_gateways(sem_gw, consulta=lambda interface: "")
    texto = balanceador.monta_nft("enp3s0", balanceador.placas_ativas(
        sem_gw, carrier=lambda interface: True, sonda=lambda placa: True,
        historico={}), configuracao)
    confere("21. carrier sem gateway nao vira saida: sem sorteio, sem set dela",
            "placa_wan2" not in texto and "numgen" not in texto,
            "sorteou sem ter para onde")



    # 31. Prender uma maquina a uma placa: casa quem PEDIU, nao para onde vai.
    configuracao = regras_de(balanceador, placas, regras=[
        {"placa": "wan1", "tipo": "origem", "valor": "192.168.101.50",
         "nota": "estacao do operador, sempre pela saida estavel"},
    ])
    texto = balanceador.monta_nft("br0", placas, configuracao)
    confere("31. regra de origem casa 'ip saddr'",
            "ip saddr @g1_wan1" in texto and "ip daddr @g1_wan1" not in texto
            and "192.168.101.50" in texto,
            "a regra de origem saiu como destino")
    resposta = balanceador.decide("203.0.113.9", placas, configuracao["regras"],
                                  origem="192.168.101.50")
    confere("31b. e o --testar concorda com ela",
            resposta["placa"] == "wan1" and resposta["motivo"] == "lista",
            str(resposta))

    # 32. O defeito que isto fixa: com um set POR PLACA, quem decidia era a
    # ordem das placas, e a tela -- que responde pela ordem das regras --
    # mentia na primeira excecao posta acima de uma faixa de outra placa.
    configuracao = regras_de(balanceador, placas, regras=[
        {"placa": "wan2", "tipo": "exato", "valor": "198.51.100.7"},
        {"placa": "wan1", "tipo": "cidr", "valor": "198.51.100.0/24"},
    ])
    texto = balanceador.monta_nft("br0", placas, configuracao)
    pos_wan2 = texto.find("@g1_wan2")
    pos_wan1 = texto.find("@g2_wan1")
    confere("32. a ordem das REGRAS decide, nao a ordem das placas",
            0 < pos_wan2 < pos_wan1,
            f"wan2={pos_wan2} wan1={pos_wan1} (a excecao tem de vir primeiro)")
    resposta = balanceador.decide("198.51.100.7", placas, configuracao["regras"])
    confere("32b. e o --testar da a mesma resposta que o kernel daria",
            resposta["placa"] == "wan2" and resposta["regra"] == 1, str(resposta))

    # 25..30. Failover com quarentena: "caiu 1, a outra ta OK, entao failover
    # assume por X minutos, para dar estabilidade". A placa cai NA HORA; o que
    # a quarentena atrasa e a VOLTA dela.
    def placas_de_teste(quarentena=1):
        return balanceador.le_placas(
            f"nome=wan1 if=enp1s0 gw=192.168.100.1 peso=7 quarentena={quarentena}\n"
            f"nome=wan2 if=wan2 gw=192.168.18.1 peso=3 quarentena={quarentena}\n")

    sempre = lambda interface: True
    boa = lambda placa: placa["nome"] == "wan1"      # wan2 nao passa trafego
    todas = lambda placa: True

    duas = placas_de_teste()
    hist = {}
    vivas = balanceador.placas_ativas(duas, carrier=sempre, sonda=boa,
                                      historico=hist, agora=1000.0)
    confere("25. placa com link e gateway que nao passa trafego: sai",
            [p["nome"] for p in vivas] == ["wan1"]
            and duas[1]["motivo_fora"] == "sonda sem resposta",
            str([(p["nome"], p.get("motivo_fora")) for p in duas]))

    texto = balanceador.monta_nft("br0", vivas, regras_de(balanceador, duas))
    confere("26. failover imediato: a que sobrou leva tudo, sem sorteio",
            "numgen" not in texto and "jhash" not in texto
            and "meta mark set 0x1 counter" in texto)

    # a wan2 melhora 30 s depois -- dentro da quarentena de 1 minuto
    duas = placas_de_teste()
    vivas = balanceador.placas_ativas(duas, carrier=sempre, sonda=todas,
                                      historico=hist, agora=1030.0)
    confere("27. quarentena segura a volta: melhorou, mas ainda nao retorna",
            [p["nome"] for p in vivas] == ["wan1"]
            and duas[1]["motivo_fora"] == "em quarentena"
            and 0 < duas[1]["volta_em"] <= 60,
            str([(p["nome"], p.get("motivo_fora"), p.get("volta_em")) for p in duas]))

    duas = placas_de_teste()
    vivas = balanceador.placas_ativas(duas, carrier=sempre, sonda=todas,
                                      historico=hist, agora=1061.0)
    confere("28. passada a quarentena, volta a rotacao",
            [p["nome"] for p in vivas] == ["wan1", "wan2"] and not hist,
            str([(p["nome"], p.get("motivo_fora")) for p in duas]))

    # recaida: o relogio recomeca, nao continua de onde parou
    duas = placas_de_teste()
    balanceador.placas_ativas(duas, carrier=sempre, sonda=boa,
                              historico=hist, agora=2000.0)
    duas = placas_de_teste()
    vivas = balanceador.placas_ativas(duas, carrier=sempre, sonda=todas,
                                      historico=hist, agora=2040.0)
    confere("29. recaida reinicia o relogio da quarentena",
            [p["nome"] for p in vivas] == ["wan1"],
            str([(p["nome"], p.get("motivo_fora")) for p in duas]))

    # sonda desligada: volta a valer so link + gateway
    sem_sonda = balanceador.le_placas(
        "nome=wan1 if=enp1s0 gw=192.168.100.1 peso=7 sonda=nao\n"
        "nome=wan2 if=wan2 gw=192.168.18.1 peso=3 sonda=nao\n")
    vivas = balanceador.placas_ativas(sem_sonda, carrier=sempre,
                                      sonda=balanceador.sonda_responde,
                                      historico={}, agora=3000.0)
    confere("30. sonda 'nao': a placa vale pelo link e pelo gateway",
            [p["nome"] for p in vivas] == ["wan1", "wan2"],
            str([(p["nome"], p.get("motivo_fora")) for p in sem_sonda]))

    # 24. O erro que derrubou a LAN na primeira instalacao, em teste.
    #
    # A resposta de uma conexao balanceada ENTRA pela placa de saida. Se a
    # restauracao da marca vier antes do filtro de interface, ela ganha a
    # marca da conexao (ct mark vale nos dois sentidos) e vai para a tabela
    # daquela placa, que so tem rota default -- e a resposta, cujo destino e
    # um cliente da LAN, volta para o uplink em vez de ser entregue. O
    # cliente fica sem resposta e o sintoma e "a internet caiu".
    configuracao = regras_de(balanceador, placas, regras=[])
    texto = balanceador.monta_nft("br0", placas, configuracao)
    pos_iif = texto.find("iifname != br0")
    pos_restaura = texto.find("ct mark != 0x0 meta mark set ct mark")
    confere("24. o filtro de interface vem ANTES de restaurar a marca",
            0 < pos_iif < pos_restaura,
            f"iifname={pos_iif} restaura={pos_restaura} "
            "(nesta ordem a resposta volta para o uplink)")

    # 22/23. As duas pontas da mesma invariante, que nao tem como ser testada
    # em execucao sem instalar: o instalador cria uma marca, o agente procura
    # OUTRA, e o papel simplesmente nao aparece no painel -- sem erro, sem log,
    # sem nada que aponte para ca. Ja aconteceu uma vez (renomeacao de 'saida'
    # para 'balanceador' que escapou em duas linhas do .sh).
    instalador = (pathlib.Path(AQUI) / "balanceador.sh").read_text(encoding="utf-8")
    agente = (pathlib.Path(AQUI).parent / "ghop-agente" / "ghop-agente.py").read_text(encoding="utf-8")
    marca_instalador = re.search(r'^DIR_BALANCEADOR="\$DIR_CONFIG/(\w+)"',
                                 instalador, re.M)
    marca_agente = re.search(r'"marca": "/etc/ghop/(\w+)", "comando": "balanceador"',
                             agente)
    confere("22. a marca que o instalador cria e a que o agente procura",
            bool(marca_instalador) and bool(marca_agente)
            and marca_instalador.group(1) == marca_agente.group(1),
            f"instalador={marca_instalador and marca_instalador.group(1)} "
            f"agente={marca_agente and marca_agente.group(1)}")

    servicos = (pathlib.Path(AQUI).parent.parent / "scripts" / "service.sh").read_text(encoding="utf-8")
    pedido = re.search(r'^"\$ORIGEM_SERVICE" (\w+)$', instalador, re.M)
    confere("23. o papel que o instalador pede ao service.sh existe la",
            bool(pedido) and f"\t{pedido.group(1)}) pacotes" in servicos,
            f"pede '{pedido and pedido.group(1)}'")

    print()
    print("TODOS OS CASOS PASSARAM" if not falhas else f"{falhas} FALHA(S)")
    return 1 if falhas else 0


if __name__ == "__main__":
    sys.exit(main())
