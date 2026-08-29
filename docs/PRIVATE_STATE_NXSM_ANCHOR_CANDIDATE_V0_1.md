# Âncora privada com raiz `NXSM` — candidata v0.1 (`NXPS v2`)

`NXPS v2` é uma nova âncora candidata para o domínio privado de pesquisa. Ela
não altera `NXPS v1`, não substitui o estado do ledger e não autoriza uma
transferência. Sua única finalidade é representar, de modo explícito e tipado,
uma raiz de árvore esparsa de nullifiers (`NXSM`) junto da raiz de notas que uma
prova privada futura deverá consumir.

## O problema que ela resolve

`NXPS v1` registra a quantidade de gastos e um resumo SHA-256 ordenado do
conjunto de nullifiers (`H_NFSET`). Isso é útil para a primeira fronteira de
estado, mas não é uma raiz que uma AIR/STARK possa reutilizar como prova de
ausência ou inclusão.

`NXPS v2` troca somente esse resumo por três informações inseparáveis:

- o ID exato da candidata `NXSM`;
- a raiz tipada de 64 bytes da árvore esparsa; e
- a quantidade de folhas gastas.

Antes de criar a âncora, a implementação reconstrói uma árvore `NXSM` a partir
da lista canônica de nullifiers do snapshot. A construção falha se a quantidade
ou a raiz da árvore fornecida forem diferentes. Assim, não é possível juntar a
raiz de um conjunto A com as notas e nullifiers de um conjunto B apenas porque
ambos têm o mesmo tamanho.

## Frame canônico

O `StateId` candidato é SHA-256, com domínio
`NOXIS/PRIVATE-STATE-ID/V2\0`, sobre os 288 bytes abaixo:

```text
magic NXPS | version:u16be=2 | reserved[2]
| genesis_id[32] | validation_context_id[32] | note_tree_parameters_id[32]
| note_depth:u8=32 | note_arity:u8=2 | note_encoding:u8=1
| nxsm_candidate_id[32] | nxsm_depth:u16be=512
| nullifier_encoding:u8=1 | nxsm_root_encoding:u8=1 | reserved:u8=0
| next_leaf_index:u64be | note_root[64]
| spent_nullifier_count:u64be | nxsm_nullifier_root[64]
```

As codificações `1` significam os valores BabyBear canônicos de 16 elementos
em `u32` little-endian. A raiz de notas continua representando a árvore de
commitments de profundidade 32; a raiz `NXSM` é outra raiz, de profundidade
512, e não pode ser trocada por ela.

## Uso atual e fronteiras

`PrivateStateAnchorV2::assert_matches_intent` exige que uma intenção privada
coincida em gênese, contexto de validação, parâmetros da árvore de notas, raiz
de notas e `StateId`. O `StateId` resultante ainda é somente uma embalagem de
32 bytes usada pela intenção candidata; não é o `StateId` do ledger v1,
identidade de consenso, checkpoint ou autorização de liquidação.

A candidata `NXSM` também permanece não selecionada. O ID no frame registra
exatamente qual construção foi usada, mas não cria uma allowlist criptográfica
nem uma promessa de segurança pós-quântica.

## Próximo requisito real

O passo seguinte não é conectar isto ao ledger. Primeiro é necessário definir
a relação AIR/prova que use a raiz `NXSM`, prove a ausência dos nullifiers de
entrada, atualize a raiz para os nullifiers de saída e vincule esse antes/depois
à intenção. Persistência, consenso e liquidação só podem considerar essa âncora
após uma implementação de prova selecionada e revisão independente.
