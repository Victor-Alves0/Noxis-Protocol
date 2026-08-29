# Âncora de estado privado candidata v0.1 (`H_STATE`)

Este marco elimina a ambiguidade anterior entre a raiz privada e o campo
`pre_state_id` de uma intenção. O novo tipo `PrivateStateAnchorV1` calcula um
identificador de estado somente para o domínio privado candidato e pode rejeitar
uma intenção que não aponte exatamente para esse estado.

## Frame canônico

`H_STATE` é SHA-256 com o domínio
`NOXIS/PRIVATE-STATE-ID/V1\0` aplicado aos 220 bytes de `NXPS v1`:

```text
magic NXPS | version:u16be | reserved[2] | genesis_id[32]
| validation_context_id[32] | tree_parameters_id[32]
| depth:u8=32 | arity:u8=2 | commitment_encoding:u8=1
| nullifier_encoding:u8=1 | next_leaf_index:u64be | note_root[64]
| spent_nullifier_count:u64be | H_NFSET[32]
```

`H_NFSET` é SHA-256 de `NOXIS/PRIVATE-NULLIFIER-SET/V1\0`, da quantidade de
nullifiers em `u64be` e de cada nullifier canônico de 64 bytes, já ordenado e
sem duplicatas. Portanto, uma raiz de notas não pode ser reutilizada com uma
lista diferente de gastos.

O `next_leaf_index` é a quantidade de commitments no snapshot: a árvore é
append-only e as posições ocupadas são exatamente o intervalo a partir de zero,
sem buracos. Ele impede interpretar a mesma raiz como se a próxima nota tivesse
uma posição diferente.

## Uso seguro atual

O resultado usa a embalagem existente de 32 bytes `StateId` porque o intento
privado já reserva esse campo. Isto não o transforma no `StateId` do ledger
SHA-256 v1: a API tipada `PrivateStateAnchorV1` deixa esse limite explícito e
não possui conversão para ledger, consenso, armazenamento ou rede.

Antes de qualquer prova ou transição, `assert_matches_intent` exige igualdade
de gênese, contexto de validação, parâmetros de árvore, raiz e `H_STATE`.
Parâmetros de árvore ainda são apenas registrados — esta camada candidata não
tem allowlist nem escolhe uma implantação criptográfica.

## O que ainda falta

Há uma árvore esparsa autenticada em memória, ainda candidata e isolada, mas
`NXPS v1` não a usa: ele continua comprometendo `H_NFSET`. A candidata separada
`NXPS v2` já registra uma raiz `NXSM` tipada e verifica que ela corresponde ao
snapshot; veja
[`PRIVATE_STATE_NXSM_ANCHOR_CANDIDATE_V0_1.md`](PRIVATE_STATE_NXSM_ANCHOR_CANDIDATE_V0_1.md).
Não há backend de prova, persistência nem transição atômica. O próximo marco é
fazer uma AIR/STARK verificar a atualização dessa raiz, antes de qualquer uso
fora do domínio de pesquisa.
