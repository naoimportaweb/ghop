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


def abre_painel():
    """Monta o Painel do nucleo, pedindo a senha se preciso."""
    senha = os.environ.get("GHOP_PAINEL_SENHA")
    nome = os.environ.get("GHOP_PAINEL")
    if senha is None:
        alvo = nome or "do painel"
        senha = getpass.getpass(f"Senha da chave {alvo}: ")
    return Painel(nome_painel=nome, senha=senha)


def separa_argumentos(pares):
    """chave=valor da linha de comando. Numero vira numero; o resto e texto."""
    argumentos = {}
    for par in pares:
        chave, igual, valor = par.partition("=")
        if not igual:
            raise ErroGHop(f"argumento '{par}' nao esta no formato chave=valor")
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
        print("Nenhum no cadastrado.")
        print("  ./ghop-painel.py nos adicionar <no> <endereco>")
        return 0
    print(f"{'NO':<24} {'ENDERECO':<28} AGENTE")
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
            print(f"[{lista} / {especie}]  {len(regras)} regra(s)")
            if not regras:
                print("    (vazia)")
            for indice, regra in enumerate(regras):
                nota = f"   # {regra['nota']}" if regra.get("nota") else ""
                print(f"  {indice:>3}  {regra['tipo']:<7} {regra['valor']}{nota}")
            print()
    print("Tudo continua sendo COLETADO: as listas so decidem o que aparece.")
    print("Branca esconde o conhecido; negra destaca e nunca esconde. Regra")
    print("nova reclassifica o historico inteiro, sem recoletar nada.")
    return 0


def mostra_resumo(nome, dados):
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  dia {dados.get('dia')}")
    print()
    print(f"{'DOMINIO':<44} {'TOTAL':>7}  ULTIMO")
    for linha in dados.get("dominios", []):
        print(f"{linha['dominio'][:44]:<44} {linha['total']:>7}  {linha['ultimo']}")
    print()
    print(f"{'IP':<40} {'PORTA':>6} {'TOTAL':>7}  ULTIMO")
    for linha in dados.get("ips", []):
        print(f"{linha['ip'][:40]:<40} {linha['porta']:>6} {linha['total']:>7}  {linha['ultimo']}")


def mostra_interfaces(nome, dados):
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  em {dados.get('quando')}")
    rota = dados.get("rota_padrao") or {}
    if rota:
        print(f"rota padrao: via {rota.get('via')} por {rota.get('por')}")
    print()
    print(f"{'INTERFACE':<10} {'TIPO':<9} {'ESTADO':<8} {'MAC':<18} ENDERECOS / DETALHE")
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
    print(f"{'DESTINO':<22} {'VIA':<16} {'POR':<8} {'ORIGEM':<16} {'PROTO':<7} {'METR':>5}  TABELA")
    for r in dados.get("rotas", []):
        print(f"{r['destino']:<22} {r['via'] or '-':<16} {r['por']:<8} {r['origem'] or '-':<16} "
              f"{r['protocolo']:<7} {r['metrica'] if r['metrica'] is not None else '-':>5}  {r['tabela']}")
    regras = dados.get("regras", [])
    if regras:
        print()
        print(f"{'PRIO':>6}  {'DE':<18} {'PARA':<18} {'MARCA':<8} TABELA")
        for r in regras:
            print(f"{r['prioridade']:>6}  {r['de']:<18} {r['para'] or '-':<18} {r['marca'] or '-':<8} {r['tabela']}")


def mostra_vizinhos(nome, dados):
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  em {dados.get('quando')}  "
          f"{dados.get('total', 0)} entrada(s)")
    print()
    print(f"{'IP':<40} {'MAC':<18} {'POR':<8} ESTADO")
    for v in dados.get("vizinhos", []):
        marca = " (roteador)" if v.get("roteador") else ""
        print(f"{v['ip'][:40]:<40} {v['mac'] or '-':<18} {v['interface']:<8} "
              f"{v['estado']}{marca}")


def mostra_conexoes(nome, dados):
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  em {dados.get('quando')}")
    print(f"acumulado desde {dados.get('desde')}, amostrando a cada "
          f"{dados.get('intervalo')}s  -  {dados.get('vivas')} na tabela agora, "
          f"{dados.get('total')} pares ja vistos")
    print()
    print(f"{'ORIGEM':<40} {'DESTINO':<40} {'PORTA':>6} {'PROTO':<6} {'AMOSTRAS':>8}  ULTIMO")
    for par in dados.get("pares", []):
        print(f"{par['origem'][:40]:<40} {par['destino'][:40]:<40} "
              f"{par['porta'] or '-':>6} {par['protocolo'] or '?':<6} "
              f"{par['amostras']:>8}  {par['ultimo']}")
    print()
    print("'amostras' e em quantas leituras o par apareceu -- NAO quantas")
    print("conexoes houve, que amostragem nao sabe dizer.")


def mostra_topologia(nome, dados):
    rota = dados.get("rota_padrao") or {}
    print(f"{nome}  ({PREFIXO_AGENTE}{nome})  em {dados.get('quando')}")
    if rota:
        print(f"saida: via {rota.get('via')} por {rota.get('por')}")
    for interface in dados.get("interfaces", []):
        if interface["tipo"] == "loopback" or not interface.get("enderecos"):
            continue
        detalhe = ", ".join(interface["enderecos"])
        if interface.get("membros"):
            detalhe += f"  [bridge: {' '.join(interface['membros'])}]"
        print(f"  {interface['nome']:<8} {interface['tipo']:<9} {detalhe}")
    for comando, falha in (dados.get("faltas") or {}).items():
        print(f"  (sem {comando}: {falha})")
    print()
    print(f"{'MAC':<18} {'IP':<16} {'POR':<8} {'NOME':<14} {'FONTES':<22} LEITURA")
    for h in dados.get("hosts", []):
        marcas = []
        if h.get("saida"):
            marcas.append("SAIDA")
        if h.get("no"):
            marcas.append(f"no? {h['no']}")
        leitura = " ".join(marcas) or leitura_das_fontes(h["fontes"])
        print(f"{h['mac'] or '(sem mac)':<18} {(h['ips'][0] if h['ips'] else '-')[:16]:<16} "
              f"{h['interface'] or '-':<8} {h['nome'][:14] or '-':<14} "
              f"{'+'.join(h['fontes']):<22} {leitura}")
    print()
    print("Nenhuma varredura: e a tabela ARP/NDP que o kernel ja tinha, cruzada")
    print("com quem pediu endereco e quem esta no radio.")


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
                raise ErroGHop("uso: nos adicionar <no> <endereco[:porta]>")
            nome, endereco = resto[1], resto[2]
            # A senha so faz falta para conferir o handshake antes de gravar.
            painel = Painel(nome_painel=nome_painel) if sem_testar else abre_painel()
            if not sem_testar:
                print(f"==> conferindo quem atende em {endereco}...")
            antes, agora = painel.adiciona_no(nome, endereco, testar=not sem_testar)
            if antes:
                print(f"No '{nome}' atualizado: {antes} -> {agora}")
            else:
                print(f"No '{nome}' cadastrado em {agora}")
            return 0
        if acao == "remover":
            if len(resto) != 2:
                raise ErroGHop("uso: nos remover <no>")
            Painel(nome_painel=nome_painel).remove_no(resto[1])
            print(f"No '{resto[1]}' removido do cadastro.")
            print("O agente naquela maquina continua no ar; isto so apaga o cadastro daqui.")
            return 0
        raise ErroGHop(f"subcomando de 'nos' desconhecido: {acao!r} (adicionar, remover)")

    if verbo == "listas":
        # Nao pede senha nem certificado: e arquivo local do painel.
        listas = Listas()
        if not resto:
            return mostra_listas(listas)
        if resto[0] == "adicionar":
            if len(resto) not in (5, 6):
                raise ErroGHop(
                    "uso: listas adicionar <branca|negra> <dominios|ips> "
                    "<tipo> <valor> [nota]\n"
                    f"      tipos de dominio: {', '.join(nucleo.TIPOS_DOMINIO)}\n"
                    f"      tipos de ip:      {', '.join(nucleo.TIPOS_IP)}")
            lista, especie, tipo, valor = resto[1], resto[2], resto[3], resto[4]
            nota = resto[5] if len(resto) == 6 else ""
            listas.adiciona(lista, especie, tipo, valor, nota)
            print(f"Regra {tipo} '{valor}' acrescentada a {lista}/{especie}.")
            return 0
        if resto[0] == "remover":
            if len(resto) != 4 or not resto[3].isdigit():
                raise ErroGHop(
                    "uso: listas remover <branca|negra> <dominios|ips> <indice>")
            removida = listas.remove(resto[1], resto[2], int(resto[3]))
            print(f"Removida de {resto[1]}/{resto[2]}: "
                  f"{removida['tipo']} {removida['valor']}")
            return 0
        raise ErroGHop(
            f"subcomando de 'listas' desconhecido: {resto[0]!r} (adicionar, remover)")

    if verbo == "resumo":
        if not resto:
            raise ErroGHop("uso: resumo <no> [chave=valor ...]")
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
            raise ErroGHop("uso: interfaces <no>")
        dados = abre_painel().interfaces(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_interfaces(resto[0], dados)
        return 0

    if verbo == "rotas":
        if len(resto) != 1:
            raise ErroGHop("uso: rotas <no>")
        dados = abre_painel().rotas(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_rotas(resto[0], dados)
        return 0

    if verbo == "vizinhos":
        if len(resto) != 1:
            raise ErroGHop("uso: vizinhos <no>")
        dados = abre_painel().vizinhos(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_vizinhos(resto[0], dados)
        return 0

    if verbo == "conexoes":
        if len(resto) != 1:
            raise ErroGHop("uso: conexoes <no>")
        dados = abre_painel().conexoes(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_conexoes(resto[0], dados)
        return 0

    if verbo == "topologia":
        if len(resto) != 1:
            raise ErroGHop("uso: topologia <no>")
        dados = abre_painel().topologia(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            mostra_topologia(resto[0], dados)
        return 0

    if verbo == "trafego":
        if len(resto) != 1:
            raise ErroGHop("uso: trafego <no>")
        dados = abre_painel().trafego(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        else:
            print(f"{resto[0]}  em {dados.get('quando')}  janela {dados.get('janela')}s, "
                  f"amostra a cada {dados.get('intervalo')}s")
            print()
            print(f"{'INTERFACE':<10} {'PONTOS':>6} {'RX agora':>12} {'TX agora':>12} {'RX medio':>12} {'TX medio':>12}  (kB/s)")
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
            raise ErroGHop(f"uso: {verbo} <no>")
        dados = getattr(abre_painel(), verbo)(resto[0])
        if so_json:
            print(json.dumps(dados, ensure_ascii=False, indent=2))
        elif verbo == "papeis":
            print(f"{resto[0]}  em {dados.get('quando')}")
            print()
            print(f"{'PAPEL':<10} {'UNIDADE':<26} {'ATIVO':<10} "
                  f"{'HABILITADO':<10} ORIGEM")
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
            print(f"faixa {configuracao.get('faixa', '?')}  roteador "
                  f"{configuracao.get('roteador', '?')}  resolvedor "
                  f"{configuracao.get('resolvedor', '?')}")
            print(f"{dados.get('ativas', 0)} de {dados.get('total', 0)} concessoes ativas")
            print()
            print(f"{'IP':<16} {'MAC':<18} {'NOME':<16} {'ESTADO':<8} FIM")
            for c in dados.get("concessoes", []):
                print(f"{c['ip']:<16} {c['mac']:<18} {c['nome'][:16]:<16} "
                      f"{c['estado']:<8} {c['fim']}")
        elif verbo == "filtro":
            contagem = dados.get("contadores") or {}
            print(f"{dados.get('ativo')}  interface {dados.get('interface') or '-'}"
                  f"  politica {dados.get('politica')}"
                  + ("" if dados.get("redirecionando")
                     else "  SEM REDIRECIONAMENTO NO FIREWALL (nao ve trafego)"))
            print(f"{contagem.get('conexoes', 0)} conexao(oes), "
                  f"{contagem.get('bloqueadas', 0)} bloqueada(s), "
                  f"{contagem.get('sem_nome', 0)} sem nome legivel")
            print()
            print(f"{'#':>3}  {'ACAO':<9} {'CASA POR':<8} NOME")
            for i, regra in enumerate(dados.get("regras") or [], 1):
                print(f"{i:>3}  {regra.get('acao', ''):<9} "
                      f"{regra.get('tipo', ''):<8} {regra.get('valor', '')}")
            print()
            print(f"{'QUANDO':<21} {'CLIENTE':<16} {'PORTA':>5} {'TOTAL':>6}  NOME")
            for b in dados.get("bloqueios", []):
                print(f"{b['ultimo']:<21} {b['cliente']:<16} {b['porta']:>5} "
                      f"{b['total']:>6}  {b['nome']}")
        elif verbo == "dns":
            print(f"{dados.get('ativo')}  escuta {', '.join(dados.get('escuta') or []) or '-'}"
                  f"  negados {dados.get('negados')}  excecoes {dados.get('permitidos')}")
            print()
            print(f"{'QUANDO':<21} {'CLIENTE':<16} NOME")
            for b in dados.get("bloqueios", []):
                print(f"{b['quando']:<21} {b['cliente']:<16} {b['nome']}")
        else:
            rede = dados.get("rede") or {}
            print(f"{dados.get('ativo')}  SSID '{rede.get('ssid', '?')}'  canal "
                  f"{rede.get('channel', '?')}  radio {dados.get('radio')} em "
                  f"{dados.get('ponte') or '-'}")
            print()
            print(f"{'MAC':<18} {'SINAL':>6} {'CONECTADO':<16} {'RX kB':>10} {'TX kB':>10}")
            for c in dados.get("clientes", []):
                print(f"{c['mac']:<18} {c['sinal']:>6} {c['conectado']:<16} "
                      f"{c['rx_bytes'] // 1000:>10} {c['tx_bytes'] // 1000:>10}")
        return 0

    raise ErroGHop(
        f"comando desconhecido: {verbo!r}. Ha 'nos', 'listas', 'resumo', "
        "'interfaces', 'rotas', 'vizinhos', 'conexoes', 'topologia', "
        "'trafego', 'papeis', 'dhcp', 'dns', 'wifi' e 'filtro'.")


def main():
    argumentos = sys.argv[1:]
    so_json = "--json" in argumentos
    sem_testar = "--sem-testar" in argumentos
    tudo = "--tudo" in argumentos
    argumentos = [a for a in argumentos
                   if a not in ("--json", "--sem-testar", "--tudo")]

    if not argumentos:
        print(__doc__.strip(), file=sys.stderr)
        return 2

    try:
        return executa(argumentos, so_json, sem_testar, tudo)
    except ErroGHop as falha:
        print("Erro:", falha, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
