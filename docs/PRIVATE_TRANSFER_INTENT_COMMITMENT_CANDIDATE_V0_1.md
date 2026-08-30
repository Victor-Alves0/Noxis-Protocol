# Compromisso da intenção privada 2×2 — candidata v0.1

## Problema resolvido

`PrivateTransferIntentV2::encode()` já fixa todos os 640 bytes públicos de
uma transferência 2×2. A pré-validação local consegue conferir raiz, ativo,
nullifiers e commitments, mas não pode demonstrar aritmeticamente que uma AIR
recebeu exatamente os mesmos `circuit_id`, gênese, contexto, estado anterior e
digests de envelope. Um compromisso único da intenção resolve essa lacuna sem
adicionar o digest à própria intenção — o que criaria autorreferência.

O tipo público separado `PrivateTransferIntentCommitmentV2` representa um
digest BabyBear canônico de 16 elementos (64 bytes). Ele não é
`TransactionIntentId` v1, não é um hash selecionado, não tem codec de rede
próprio e ainda não é aceito pelo ledger.

## Relação candidata proposta

Uma extensão P24 futura, com manifesto, ID e corpus próprios, deverá definir:

```text
intent_commitment = H_INTENT(PrivateTransferIntentV2::encode()[640])
```

`H_INTENT` terá somente uma aridade: 640 bytes, exatamente na ordem já
canônica do `encode`. A conversão é `BytePack3LE`, resultando em 214 elementos
BabyBear; não existe API de bytes livres, prefixo de comprimento ou campo
opcional. O digest terá os mesmos 16 elementos da candidata P24, todos em
`u32le` canônico.

O rótulo candidato reservado é:

```text
NOXIS/POSEIDON2-PRIVACY/V1/INTENT-COMMITMENT\0
```

Ele deve receber um IV próprio, derivado por rejeição do ID da candidata pai
`NXPH` e prefixo exclusivo
`NOXIS/POSEIDON2-INTENT-COMMITMENT-IV/V1\0`. Ele não pode reutilizar `ADDR`,
`NOTE`, `NULLIFIER`, `LEAF`, `NODE` ou `EMPTY`. O artefato será um manifesto
filho distinto, provisoriamente `NXIC v1`, contendo integralmente o manifesto
NXPH e seu ID; trocar esse domínio não altera `NXPH`, `NXTV` ou `NXNV`.

## O que a AIR deverá vincular

A entrada pública candidata passa a conter o commitment de intenção e a AIR
deverá recomputá-lo a partir dos 640 bytes canônicos que já expressam:

- `circuit_id`, gênese, contexto e `pre_state_id`;
- identificador/parâmetros de árvore e raiz pré-estado;
- ativo, os dois nullifiers e os dois commitments de saída;
- os dois digests de envelope.

Assim, trocar um único byte da intenção torna o compromisso incompatível. A
AIR continua sem executar KEM/AEAD: ela só liga o digest público ao commitment
da intenção.

## Ordenação canônica de slots

Os dois nullifiers devem estar em ordem estritamente crescente dos seus 64
bytes canônicos, comparados como octetos unsigned em ordem lexicográfica. Os
dois commitments de saída seguem a mesma regra. Isso é ordem dos bytes, não
ordem numérica dos elementos BabyBear em `u32le`.

Cada saída é o tipo estrutural `PrivateTransferOutputV2`, que carrega o par
`(commitment, ciphertext_digest)`. Ao ordenar por commitment, o digest viaja
com o mesmo slot; a codificação ainda preserva o layout de 640 bytes
(`commitment[2]` seguido de `digest[2]`). Construção e decodificação rejeitam
ordem inversa e duplicatas. O codec ainda não recalcula o digest do envelope:
isso permanece uma obrigação do futuro verificador híbrido.

## Estado da primeira implementação

`NXIC`, o IV, os KATs externos `NXIV` e a referência local estão congelados.
Uma fatia STARK que reavalia o sponge sobre os 214 elementos públicos já é
confrontada com os dois vetores externos; ver
[`STARK_INTENT_COMMITMENT_RESEARCH_V0_1.md`](STARK_INTENT_COMMITMENT_RESEARCH_V0_1.md).
Ela não deve ser confundida com a AIR completa: a fatia já aritmetiza a
decomposição/recomposição dos 640 bytes, mas a ligação às witnesses, a seleção
criptográfica e a revisão independente ainda faltam.

O verificador futuro deverá recalcular o commitment a partir da intenção NXPT
estritamente decodificada e comparar com a entrada pública da prova; receber
somente um digest do chamador não basta.
