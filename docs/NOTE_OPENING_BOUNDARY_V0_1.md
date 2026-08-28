# Fronteira de abertura de nota v2 — v0.1

## Estado e objetivo

Este documento fixa a fronteira de dados privados que a futura AIR de
`PrivateTransferV2` deverá provar. Ele não define uma função de hash, não cria
uma nota utilizável, não escolhe chaves, não habilita o ledger e não autoriza
liquidação. Seu propósito é evitar que carteira, circuito e nó inventem
preimages incompatíveis antes da seleção criptográfica.

O protocolo v1 permanece inalterado. Seus `Commitment` e `Nullifier` têm 32
bytes, usam outra árvore e não podem ser convertidos para estes tipos v2.

## Abertura local de uma nota

Uma abertura é mantida somente pelo dono/prover local:

| Campo | Bytes | Codificação | Visibilidade |
| --- | ---: | --- | --- |
| `version` | 2 | `u16` big-endian, valor `1` | privada |
| `asset_id` | 32 | `AssetId` canônico | pública na intenção, privada na nota |
| `value` | 16 | `u128` big-endian | privada |
| `recipient_commitment` | 64 | 16 elementos BabyBear canônicos, little-endian | privada; compromisso público futuro |
| `rho` | 32 | bytes uniformes gerados pela carteira | privada |
| `rcm` | 32 | bytes uniformes gerados pela carteira | privada |

O preimage canônico de nota é a concatenação exata da tabela acima, com 178
bytes. Não há campos opcionais, comprimentos variáveis, serialização genérica
nem reordenação. `value = 0` é permitido somente para uma saída de
preenchimento do circuito 2×2; ainda exige `rho` e `rcm` inéditos.

`rho` deve ser único entre notas do mesmo domínio de rede e `rcm` deve ser
novo para cada commitment. A geração, cópia de segurança, rotação e apagamento
seguro de segredos continuam fora deste artefato: nenhuma API deve oferecer
`new_random()` até que essas políticas sejam especificadas e auditadas.

## Testemunha de gasto local

Para gastar uma nota, o prover combina a abertura com dados que nunca entram
no pacote de rede:

| Campo | Forma | Regra |
| --- | --- | --- |
| `nullifier_key` | 32 bytes secretos | pertence ao destinatário da nota |
| `leaf_position` | `u32` | índice zero-base em árvore de profundidade 32 |
| `merkle_siblings` | 32 valores BabyBear de 64 bytes | irmão 0 é adjacente à folha |

A direção no nível `h` vem do bit `h` de `leaf_position`, do menos para o mais
significativo. Não há bitmap, índice alternativo ou caminho de tamanho variável.
O circuito deverá recusar uma raiz diferente, caminho incompleto, posição fora
do intervalo ou abertura incompatível com o commitment da folha.

## Funções candidatas ainda não selecionadas

Depois de selecionar e revisar uma extensão de parâmetros, a AIR deverá usar
estas relações, sem mudar o preimage acima:

```text
recipient_commitment = H_ADDR(nullifier_key)
note_commitment     = H_NOTE(note_preimage)
nullifier           = H_NULLIFIER(nullifier_key, rho, note_commitment, leaf_position)
```

`H_ADDR` recebe a mesma `nullifier_key` secreta usada pela terceira relação.
Assim, a AIR deverá provar que o dono da chave comprometida pelo destinatário é
o mesmo que deriva o nullifier; chaves de cifragem híbrida continuam separadas.

`H_ADDR`, `H_NOTE` e `H_NULLIFIER` existem somente como referência isolada da
candidata `NXPH` P24. Ela tem manifesto, ID e corpus próprios e não reutiliza
silenciosamente os domínios de árvore `LEAF`, `NODE` e `EMPTY`. A referência
local não é um backend criptográfico selecionado, não habilita carteira nem
autoriza liquidação. Antes de uso em AIR, prover ou rede, a candidata ainda
precisa de seleção e revisão criptográfica independente.

Para esta candidata, a ponte explícita para a árvore também é fixa:

```text
tree_leaf = H_LEAF(note_commitment)
root      = H_NODE(...tree_leaf, siblings[0..32], leaf_position...)
```

Ou seja, `note_commitment` não entra diretamente como raiz ou nó interno. A
abertura local candidata calcula essa ponte apenas para conferir um caminho de
32 níveis; ela não demonstra inclusão nem autorização perante o protocolo.

## Codificação candidata bytes→campo

Quando essa candidata for avaliada, bytes arbitrários são convertidos por
`BytePack3LE`: cada grupo de até três octetos consecutivos vira um elemento
`b0 + 256*b1 + 65_536*b2`; o grupo final é completado com zeroes. O maior
resultado é `2^24 - 1`, portanto sempre é BabyBear canônico sem redução
modular. Como cada função possui tamanho fixo, o complemento final não cria
ambiguidade entre mensagens.

## Ligação obrigatória à intenção pública

A futura AIR recebe `PrivateTransferIntentV2::encode()` como fonte pública
canônica. Para cada transferência 2×2, ela deve provar que:

1. os dois `asset_id` das entradas e os dois das saídas são exatamente o
   `asset_id` público da intenção;
2. os dois commitments de saída calculados são, na mesma ordem, os dois
   `output_commitments` públicos;
3. os dois nullifiers calculados são, na mesma ordem, os dois `nullifiers`
   públicos e são distintos;
4. cada commitment de entrada está incluído em `pre_state_root` na posição e
   caminho privados fornecidos;
5. a conservação `value_in[0] + value_in[1] = value_out[0] + value_out[1]`
   ocorre sem overflow e cada valor cabe em `u128`;
6. os dois digests de envelope públicos pertencem às duas saídas na mesma
   ordem; a AIR não precisa executar KEM ou AEAD;
7. a prova é vinculada ao hash de intenção derivado de todos os 640 bytes com
   `NOXIS/PRIVATE-TRANSFER-INTENT/V2\0`.

As regras acima descrevem uma declaração que uma prova deverá demonstrar. Elas
não tornam `PrivateTransferIntentV2`, `NXPT`, uma prova opaca ou qualquer
`ProofVerifier` existente em autorização de gasto.

## Limites de implementação

- `NoteOpeningV2` e a testemunha futura são estruturas locais: sem `Debug`,
  `Display`, codec de rede, persistência automática ou inclusão em logs.
- Nenhum crate v1 (`noxis-ledger`, `noxis-storage`, `noxis-consensus`, ABCI,
  checkpoint ou record-chain) recebe esses segredos ou valores v2.
- A árvore SHA-256 v1 não é uma alternativa temporária para a prova v2.
- Não há redução/truncamento de valores BabyBear de 64 bytes para identificadores
  v1 de 32 bytes.
- Um caminho de teste no índice `u32::MAX` é KAT de orientação, não prova de
  que uma árvore append-only com poucas inserções tenha tido esse estado.

## Critérios para uma integração de prova ou protocolo

Uma integração de abertura em AIR, prover ou protocolo só poderá ser iniciada
quando a extensão de parâmetros contiver os domínios `ADDR`, `NOTE` e
`NULLIFIER` e passar por:

1. manifesto, ID candidato e checksums congelados;
2. vetores externos reproduzíveis para cada função e preimage;
3. teste diferencial entre referência isolada, gerador externo e futura AIR;
4. testes negativos de mutação para todos os campos, caminho, posição e
   vínculo à intenção;
5. revisão criptográfica independente.

Até esses critérios, o formato de 178 bytes e a referência candidata local são
artefatos de engenharia e evidência; nenhuma função criptográfica selecionada
ou abertura segura de produção é reivindicada.
