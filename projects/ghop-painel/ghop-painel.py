#!/usr/bin/env python3
"""Painel do GHop, casca de linha de comando.

Casca fina: tudo o que o painel *faz* mora em nucleo.py, que nao tem Qt nem
imprime nada. Aqui so ha leitura de argumento, senha e formatacao de saida --
a casca PySide6 vai nascer ao lado desta, sobre o mesmo nucleo, e esta aqui
continua servindo para script e para depurar sem abrir janela.

Um "no" e uma maquina observada. Quem conhece os nos e o painel: o agente nao
sabe da existencia de nenhum outro. A chave primaria de um no e o NOME, nunca
o endereco -- recadastrar o mesmo nome so troca o endereco.

Uso:
  ./ghop-painel.py nos                            lista os nos cadastrados
  ./ghop-painel.py nos adicionar <no> <endereco>  cadastra ou atualiza
  ./ghop-painel.py nos remover <no>
  ./ghop-painel.py resumo <no> [chave=valor ...]  le os contadores do no
  ./ghop-painel.py listas                         mostra a whitelist
  ./ghop-painel.py listas adicionar <especie> <tipo> <valor> [nota]
  ./ghop-painel.py listas remover <especie> <indice>
  ./ghop-painel.py filtro <no>                    le o filtro de camada de aplicacao
  ./ghop-painel.py vizinhos <no>                  tabela ARP/NDP crua do no
  ./ghop-painel.py conexoes <no>                  mapa de quem falou com quem
  ./ghop-painel.py topologia <no>                 quem esta na rede dele, cruzado

Le, so. Escrever regra do filtro e pela janela: e comando que corta trafego
da LAN, e a confirmacao que diz o que cai junto e da tela.

Exemplos:
  ./ghop-painel.py nos adicionar gateway 192.168.101.1
  ./ghop-painel.py nos adicionar gateway 192.168.101.1:7000
  ./ghop-painel.py resumo gateway
  ./ghop-painel.py resumo gateway limite=50 dia=02_09_2026
  ./ghop-painel.py --json resumo gateway

Opcoes:
  --json          imprime a resposta crua, para script
  --sem-testar    cadastra sem conferir o handshake (maquina desligada)
  --tudo          mostra tambem o que a whitelist cobre

Variaveis de ambiente:
  GHOP_PAINEL        nome do painel (padrao: o unico emitido, se houver so um)
  GHOP_CA_DIR        diretorio da CA (padrao: ~/.ghop/ca)
  GHOP_PAINEL_SENHA  senha da chave do painel (senao, pergunta no terminal)
"""

import getpass
import json
import os
import sys

import nucleo
from nucleo import (ORIGENS_PAPEL, PREFIXO_AGENTE, ErroGHop, Listas, Painel,
                    leitura_das_fontes)
from textos import T


def abre_painel():
    """Monta o Painel do nucleo, pedindo a senha se preciso."""
    senha = os.environ.get("GHOP_PAINEL_SENHA")
    nome = os.environ.get("GHOP_PAINEL")
    if senha is None:
        alvo = nome or T("cli.do_painel")
        senha = getpass.getpass(T("cli.senha_da_chave").format(alvo))
    return Painel(nome_painel=nome, senha=senha)


def separa_argumentos(pares):
    """chave=valor da linha de comando. Numero vira numero; o resto e texto."""
    argumentos = {}
    for par in pares:
        chave, igual, valor = par.partition("=")
        if not igual:
            raise ErroGHop(T("cli.argumento_formato").format(par))
        if valor.lstrip("-").isdigit():
            argumentos[chave] = int(valor)
        elif valor in ("true", "false"):
            argumentos[chave] = valor == "true"
        else:
            argumentos[chave] = valor
    return argumentos


def mostra_nos(painel):
    nos = painel.nos()
    if not nos:
        print(T("cli.nenhum_no"))
        print("  ./ghop-painel.py nos adicionar <no> <endereco>")
        return 0
    print(f"{T('cli.col.no'):<24} {T('cli.col.endereco'):<28} {T('cli.col.agente')}")
    for nome in sorted(nos):
        registro = nos[nome]
        endereco = f"{registro['endereco']}:{registro['porta']}"
        print(f"{nome:<24} {endereco:<28} {PREFIXO_AGENTE}{nome}")
    return 0


def mostra_listas(listas):
    """As duas listas inteiras, com indice -- e o indice que 'remover' usa."""
    tudo = listas.tudo()
    for lista in nucleo.LISTAS:
        for especie in ("dominios", "ips"):
            regras = tudo[lista][especie]
            print(T("cli.lista_especie").format(lista, especie, len(regras)))
            if not regras:
                print(T("cli.vazia"))
            for indice, regra in enumerate(regras):
                nota = f"   # {regra['nota']}" if regra.get("nota") else ""
                print(f"  {indice:>3}  {regra['tipo']:<7} {regra['valor']}{nota}")
            print()
    print(T("cli.nota_listas"))
    return 0


def mostra_resumo(nome, dados):
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  dia {dados.get('dia')}")
    print()
    print(f"{T('cli.col.dominio'):<44} {T('cli.col.total'):>7}  {T('cli.col.ultimo')}")
    for linha in dados.get("dominios", []):
        print(f"{linha['dominio'][:44]:<44} {linha['total']:>7}  {linha['ultimo']}")
    print()
    print(f"{T('cli.col.ip'):<40} {T('cli.col.porta'):>6} {T('cli.col.total'):>7}  {T('cli.col.ultimo')}")
    for linha in dados.get("ips", []):
        print(f"{linha['ip'][:40]:<40} {linha['porta']:>6} {linha['total']:>7}  {linha['ultimo']}")


def mostra_interfaces(nome, dados):
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  em {dados.get('quando')}")
    rota = dados.get("rota_padrao") or {}
    if rota:
        print(T("cli.rota_padrao").format(rota.get("via"), rota.get("por")))
    print()
    print(f"{T('cli.col.interface'):<10} {T('cli.col.tipo'):<9} {T('cli.col.estado'):<8} {T('cli.col.mac'):<18} {T('cli.col.enderecos_detalhe')}")
    for i in dados.get("interfaces", []):
        detalhe = ", ".join(i.get("enderecos") or []) or "-"
        if i.get("membros"):
            detalhe += f"  [bridge: {' '.join(i['membros'])}]"
        elif i.get("bridge"):
            detalhe += f"  [em {i['bridge']}]"
        sem_fio = i.get("sem_fio") or {}
        if sem_fio:
            detalhe += "  [" + " ".join(f"{k}={v}" for k, v in sem_fio.items()) + "]"
        print(f"{i['nome']:<10} {i['tipo']:<9} {i['estado']:<8} {i['mac']:<18} {detalhe}")


def mostra_rotas(nome, dados):
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  em {dados.get('quando')}")
    print()
    print(f"{T('cli.col.destino'):<22} {T('cli.col.via'):<16} {T('cli.col.por'):<8} {T('cli.col.origem'):<16} {T('cli.col.proto'):<7} {T('cli.col.metr'):>5}  {T('cli.col.tabela')}")
    for r in dados.get("rotas", []):
        print(f"{r['destino']:<22} {r['via'] or '-':<16} {r['por']:<8} {r['origem'] or '-':<16} "
              f"{r['protocolo']:<7} {r['metrica'] if r['metrica'] is not None else '-':>5}  {r['tabela']}")
    regras = dados.get("regras", [])
    if regras:
        print()
        print(f"{T('cli.col.prio'):>6}  {T('cli.col.de'):<18} {T('cli.col.para'):<18} {T('cli.col.marca'):<8} {T('cli.col.tabela')}")
        for r in regras:
            print(f"{r['prioridade']:>6}  {r['de']:<18} {r['para'] or '-':<18} {r['marca'] or '-':<8} {r['tabela']}")


def mostra_vizinhos(nome, dados):
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  em {dados.get('quando')}  "
          f"{dados.get('total', 0)} entrada(s)")
    print()
    print(f"{T('cli.col.ip'):<40} {T('cli.col.mac'):<18} {T('cli.col.por'):<8} {T('cli.col.estado')}")
    for v in dados.get("vizinhos", []):
        marca = T("cli.marca_roteador") if v.get("roteador") else ""
        print(f"{v['ip'][:40]:<40} {v['mac'] or '-':<18} {v['interface']:<8} "
              f"{v['estado']}{marca}")


def mostra_conexoes(nome, dados):
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  em {dados.get('quando')}")
    print(T("cli.acumulado_desde").format(
        dados.get("desde"), dados.get("intervalo"), dados.get("vivas"), dados.get("total")))
    print()
    print(f"{T('cli.col.origem'):<40} {T('cli.col.destino'):<40} {T('cli.col.porta'):>6} {T('cli.col.proto'):<6} {T('cli.col.amostras'):>8}  {T('cli.col.ultimo')}")
    for par in dados.get("pares", []):
        print(f"{par['origem'][:40]:<40} {par['destino'][:40]:<40} "
              f"{par['porta'] or '-':>6} {par['protocolo'] or '?':<6} "
              f"{par['amostras']:>8}  {par['ultimo']}")
    print()
    print(T("cli.nota_amostras"))


def mostra_topologia(nome, dados):
    rota = dados.get("rota_padrao") or {}
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  em {dados.get('quando')}")
    if rota:
        print(T("cli.saida_via").format(rota.get("via"), rota.get("por")))
    for interface in dados.get("interfaces", []):
        if interface["tipo"] == "loopback" or not interface.get("enderecos"):
            continue
        detalhe = ", ".join(interface["enderecos"])
        if interface.get("membros"):
            detalhe += f"  [bridge: {' '.join(interface['membros'])}]"
        print(f"  {interface['nome']:<8} {interface['tipo']:<9} {detalhe}")
    for comando, falha in (dados.get("faltas") or {}).items():
        print(T("cli.sem_comando").format(comando, falha))
    print()
    print(f"{T('cli.col.mac'):<18} {T('cli.col.ip'):<16} {T('cli.col.por'):<8} {T('cli.col.nome'):<14} {T('cli.col.fontes'):<22} {T('cli.col.leitura')}")
    for h in dados.get("hosts", []):
        marcas = []
        if h.get("saida"):
            marcas.append("SAIDA")
        if h.get("no"):
            marcas.append(f"no? {h['no']}")
        leitura = " ".join(marcas) or leitura_das_fontes(h["fontes"])
        print(f"{h["mac"] or T("cli.sem_mac"):<18} {(h['ips'][0] if h['ips'] else '-')[:16]:<16} "
              f"{h['interface'] or '-':<8} {h['nome'][:14] or '-':<14} "
              f"{'+'.join(h['fontes']):<22} {leitura}")
    print()
    print(T("cli.nota_topologia"))


def executa(argumentos, so_json, sem_testar, tudo=False):
    verbo, resto = argumentos[0], argumentos[1:]

    nome_painel = os.environ.get("GHOP_PAINEL")

    if verbo == "nos":
        # Listar e remover mexem so no cadastro local: nao pedem a senha.
        if not resto:
            return mostra_nos(Painel(nome_painel=nome_painel))
        acao = resto[0]
        if acao == "adicionar":
            if len(resto) != 3:
                raise ErroGHop(T("cli.uso").format("nos adicionar <no> <endereco[:porta]>"))
            nome, endereco = resto[1], resto[2]
            # A senha so faz falta para conferir o handshake antes de gravar.
            painel = Painel(nome_painel=nome_painel) if sem_testar else abre_painel()
            if not sem_testar:
                print(T("cli.conferindo").format(endereco))
            antes, agora = painel.adiciona_no(nome, endereco, testar=not sem_testar)
            if antes:
                print(T("cli.no_atualizado").format(nome, antes, agora))
            else:
                print(T("cli.no_cadastrado").format(nome, agora))
            return 0
        if acao == "remover":
            if len(resto) != 2:
                raise ErroGHop(T("cli.uso").format("nos remover <no>"))
            Painel(nome_painel=nome_painel).remove_no(resto[1])
            print(T("cli.no_removido").format(resto[1]))
            return 0
        raise ErroGHop(T("cli.subcomando_desconhecido").format("nos", repr(acao),
                                                              "adicionar, remover"))

    if verbo == "listas":
        # Nao pede senha nem certificado: e arquivo local do painel.
        listas = Listas()
        if not resto:
            return mostra_listas(listas)
        if resto[0] == "adicionar":
            if len(resto) not in (5, 6):
                raise ErroGHop(
                    T("cli.uso").format(
                        "listas adicionar <branca|negra> <dominios|ips> "
                        "<tipo> <valor> [nota]")
                    + T("cli.tipos_de").format(", ".join(nucleo.TIPOS_DOMINIO),
                                               ", ".join(nucleo.TIPOS_IP)))
            lista, especie, tipo, valor = resto[1], resto[2], resto[3], resto[4]
            nota = resto[5] if len(resto) == 6 else ""
            listas.adiciona(lista, especie, tipo, valor, nota)
            print(T("cli.regra_acrescentada").format(tipo, valor, lista, especie))
            return 0
        if resto[0] == "remover":
            if len(resto) != 4 or not resto[3].isdigit():
                raise ErroGHop(T("cli.uso").format(
                    "listas remover <branca|negra> <dominios|ips> <indice>"))
            removida = listas.remove(resto[1], resto[2], int(resto[3]))
            print(T("cli.regra_removida").format(
                resto[1], resto[2], removida["tipo"], removida["valor"]))
            return 0
        raise ErroGHop(T("cli.subcomando_desconhecido").format(
            "listas", repr(resto[0]), "adicionar, remover"))

    if verbo == "resumo":
        if not resto:
            raise ErroGHop(T("cli.uso").format("resumo <no> [chave=valor ...]"))
        nome = resto[0]
        extras = separa_argumentos(resto[1:])
        dados = abre_painel().resumo(nome, dia=extras.get("dia"),
                                     limite=extras.get("limite"),
                                     ocultar_brancos=not tudo)
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_resumo(nome, dados)
        return 0

    if verbo == "interfaces":
        if len(resto) != 1:
            raise ErroGHop(T("cli.uso").format("interfaces <no>"))
        dados = abre_painel().interfaces(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_interfaces(resto[0], dados)
        return 0

    if verbo == "rotas":
        if len(resto) != 1:
            raise ErroGHop(T("cli.uso").format("rotas <no>"))
        dados = abre_painel().rotas(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_rotas(resto[0], dados)
        return 0

    if verbo == "vizinhos":
        if len(resto) != 1:
            raise ErroGHop(T("cli.uso").format("vizinhos <no>"))
        dados = abre_painel().vizinhos(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_vizinhos(resto[0], dados)
        return 0

    if verbo == "conexoes":
        if len(resto) != 1:
            raise ErroGHop(T("cli.uso").format("conexoes <no>"))
        dados = abre_painel().conexoes(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_conexoes(resto[0], dados)
        return 0

    if verbo == "topologia":
        if len(resto) != 1:
            raise ErroGHop(T("cli.uso").format("topologia <no>"))
        dados = abre_painel().topologia(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_topologia(resto[0], dados)
        return 0

    if verbo == "trafego":
        if len(resto) != 1:
            raise ErroGHop(T("cli.uso").format("trafego <no>"))
        dados = abre_painel().trafego(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            print(f"{resto[0]}  em {dados.get('quando')}  janela {dados.get('janela')}s, "
                  f"amostra a cada {dados.get('intervalo')}s")
            print()
            print(f"{T('cli.col.interface'):<10} {T('cli.col.pontos'):>6} {T('cli.col.rx_agora'):>12} {T('cli.col.tx_agora'):>12} {T('cli.col.rx_medio'):>12} {T('cli.col.tx_medio'):>12}  (kB/s)")
            for nome, pontos in sorted(dados.get("interfaces", {}).items()):
                if not pontos:
                    continue
                rx_m = sum(p[1] for p in pontos) / len(pontos)
                tx_m = sum(p[2] for p in pontos) / len(pontos)
                print(f"{nome:<10} {len(pontos):>6} {pontos[-1][1] / 1000:>12.1f} "
                      f"{pontos[-1][2] / 1000:>12.1f} {rx_m / 1000:>12.1f} {tx_m / 1000:>12.1f}")
        return 0

    # Leituras de papel: a casca so pede e imprime, e o agente recusa o que
    # nao existir naquela maquina.
    if verbo in ("papeis", "dhcp", "dns", "wifi", "filtro"):
        if len(resto) != 1:
            raise ErroGHop(T("cli.uso").format(f"{verbo} <no>"))
        dados = getattr(abre_painel(), verbo)(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        elif verbo == "papeis":
            print(f"{resto[0]}  em {dados.get('quando')}")
            print()
            print(f"{T('cli.col.papel'):<10} {T('cli.col.unidade'):<26} {T('cli.col.ativo'):<10} "
                  f"{T('cli.col.habilitado'):<10} {T('cli.col.origem')}")
            for p in dados.get("papeis", []):
                # 'origem' diz quem instalou: 'ghop' tem marca nossa em
                # /etc/ghop, 'sistema' ja estava na maquina (hoje so o
                # isc-dhcp-server chega assim). O texto sai do nucleo, que e
                # de onde a janela tira o mesmo rotulo.
                print(f"{p['rotulo']:<10} {p['unidade']:<26} {p['ativo']:<10} "
                      f"{p['habilitado']:<10} "
                      f"{ORIGENS_PAPEL.get(p.get('origem', ''), '')}")
        elif verbo == "dhcp":
            configuracao = dados.get("configuracao") or {}
            print(T("cli.dhcp_faixa").format(
                configuracao.get("faixa", "?"), configuracao.get("roteador", "?"),
                configuracao.get("resolvedor", "?")))
            print(T("cli.dhcp_concessoes").format(
                dados.get("ativas", 0), dados.get("total", 0)))
            print()
            print(f"{T('cli.col.ip'):<16} {T('cli.col.mac'):<18} {T('cli.col.nome'):<16} {T('cli.col.estado'):<8} {T('cli.col.fim')}")
            for c in dados.get("concessoes", []):
                print(f"{c['ip']:<16} {c['mac']:<18} {c['nome'][:16]:<16} "
                      f"{c['estado']:<8} {c['fim']}")
        elif verbo == "filtro":
            contagem = dados.get("contadores") or {}
            print(T("cli.filtro_estado").format(
                dados.get("ativo"), dados.get("interface") or "-", dados.get("politica"))
                + ("" if dados.get("redirecionando") else T("cli.filtro_sem_redir")))
            print(T("cli.filtro_contagem").format(
                contagem.get("conexoes", 0), contagem.get("bloqueadas", 0),
                contagem.get("sem_nome", 0)))
            print()
            print(f"{'#':>3}  {T('cli.col.acao'):<9} {T('cli.col.casa_por'):<8} {T('cli.col.nome')}")
            for i, regra in enumerate(dados.get("regras") or [], 1):
                print(f"{i:>3}  {regra.get('acao', ''):<9} "
                      f"{regra.get('tipo', ''):<8} {regra.get('valor', '')}")
            print()
            print(f"{T('cli.col.quando'):<21} {T('cli.col.cliente'):<16} {T('cli.col.porta'):>5} {T('cli.col.total'):>6}  {T('cli.col.nome')}")
            for b in dados.get("bloqueios", []):
                print(f"{b['ultimo']:<21} {b['cliente']:<16} {b['porta']:>5} "
                      f"{b['total']:>6}  {b['nome']}")
        elif verbo == "dns":
            print(T("cli.dns_estado").format(
                dados.get("ativo"), ", ".join(dados.get("escuta") or []) or "-",
                dados.get("negados"), dados.get("permitidos")))
            print()
            print(f"{T('cli.col.quando'):<21} {T('cli.col.cliente'):<16} {T('cli.col.nome')}")
            for b in dados.get("bloqueios", []):
                print(f"{b['quando']:<21} {b['cliente']:<16} {b['nome']}")
        else:
            rede = dados.get("rede") or {}
            print(T("cli.wifi_estado").format(
                dados.get("ativo"), rede.get("ssid", "?"), rede.get("channel", "?"),
                dados.get("radio"), dados.get("ponte") or "-"))
            print()
            print(f"{T('cli.col.mac'):<18} {T('cli.col.sinal'):>6} {T('cli.col.conectado'):<16} {T('cli.col.rx_kb'):>10} {T('cli.col.tx_kb'):>10}")
            for c in dados.get("clientes", []):
                print(f"{c['mac']:<18} {c['sinal']:>6} {c['conectado']:<16} "
                      f"{c['rx_bytes'] // 1000:>10} {c['tx_bytes'] // 1000:>10}")
        return 0

    raise ErroGHop(T("cli.comando_desconhecido").format(repr(verbo)))


def main():
    argumentos = sys.argv[1:]
    so_json = "--json" in argumentos
    sem_testar = "--sem-testar" in argumentos
    tudo = "--tudo" in argumentos
    argumentos = [a for a in argumentos
                   if a not in ("--json", "--sem-testar", "--tudo")]

    if not argumentos:
        # A ajuda sai do RECURSO, nao do __doc__. O docstring deste modulo tem
        # dois donos com necessidades diferentes: quem le o codigo (e o quer em
        # portugues, como o resto do repositorio) e quem roda sem argumento (e
        # o quer no idioma dele). Enquanto eram o mesmo texto, um dos dois ia
        # ficar errado -- e o que o usuario ve e o que mais custa estar errado.
        print(T("cli.ajuda"), file=sys.stderr)
        return 2

    try:
        return executa(argumentos, so_json, sem_testar, tudo)
    except ErroGHop as falha:
        print(T("cli.erro"), falha, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
