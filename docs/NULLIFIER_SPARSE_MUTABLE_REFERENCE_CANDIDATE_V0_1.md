# Estado mutável da árvore esparsa de nullifiers — candidato v0.1

`noxis-nullifier-tree-state` é uma implementação em memória, isolada e
verificável do estado mutável da candidata `NXSM v1`. Ele transforma a
referência de hashing em algo que pode responder “este nullifier já foi gasto?”
e produzir um caminho verificável para essa resposta, sem atribuir valor a uma
nota nem aceitar uma transferência privada.

## Separação para auditoria

O crate foi separado por responsabilidade:

- `noxis-nullifier-tree-reference` calcula a folha, os nós, os vazios e
  verifica uma prova a partir do manifesto `NXSM`;
- `noxis-nullifier-tree-state` representa somente os nós não vazios, deriva
  caminhos do estado e prepara/efetiva a mudança de um gasto; e
- nenhum dos dois depende de ledger, consenso, armazenamento, rede, carteira
  ou verificador de prova.

Isso permite revisar a regra de mutação sem precisar confiar no restante do
protocolo: um nó omitido do mapa vale exatamente `E[altura]`, e uma posição é
sempre derivada dos 64 bytes canônicos do `NullifierV2`. Não existe API pública
para escrever um nó arbitrário, escolher índice ou fornecer bitmap de direção.

## Operações candidatas

`NullifierSparseTreeStateV1` oferece:

- `new_candidate`: carrega e valida toda a cadeia de parâmetros antes de criar
  uma árvore vazia;
- `root`: obtém a raiz esparsa atual, distinta da raiz de notas;
- `prove`: produz os 512 irmãos para inclusão ou ausência de um nullifier;
- `verify_inclusion` e `verify_absence`: delegam a checagem à referência;
- `mark_spent`: muda uma folha vazia para a folha gasta canônica uma única vez;
  e
- `spent_count` e `stored_node_count`: expõem limites observáveis para testes
  e futuras decisões de armazenamento.

O caminho continua sendo lido bit a bit, do menos significativo ao mais
significativo, nos 64 bytes do nullifier. Como cada elemento BabyBear canônico
tem o bit 31 zerado, a moldura conserva 512 níveis mas somente 496 bits podem
variar hoje. Isso não cria colisão entre encodings canônicos; é uma propriedade
que uma AIR futura deve reproduzir explicitamente.

## Atomicidade da mutação

Antes de tocar no mapa, `mark_spent` calcula a folha gasta e os 512 pais em
memória. Só então instala o caminho completo e incrementa a contagem. Um
nullifier já presente falha antes dessa preparação. Portanto, todo erro de
hash, parâmetro ou duplicata retorna sem mudar a raiz, os nós armazenados ou a
contagem observável.

Os testes cobrem raiz vazia e ausência, primeira inserção comparada à
reconstrução pela referência, ordens diferentes de inserção, inserções nos bits
0, 8 e 510, reutilização indevida de caminho e duplicata atômica.

## Limites intencionais

Esta é uma estrutura de pesquisa em memória, não uma implementação pronta para
produção. Ela ainda não possui corpus externo específico de `NXSM`, serialização
canônica de estado ou prova, limite de memória/persistência, backend STARK/AIR,
integração com `H_STATE`, transição de notas, consenso nem autorização de
liquidação. Em especial, a âncora privada `NXPS v1` continua usando seu
compromisso ordenado `H_NFSET`; ela não é reinterpretada como esta raiz.

O próximo passo seguro é obter evidência externa de interoperabilidade da
árvore e especificar uma nova versão de âncora que comprometa, de forma tipada,
a raiz `NXSM`, a contagem de gastos e a identidade dos parâmetros. Só depois
uma transição privada poderá considerar essa estrutura como entrada.
