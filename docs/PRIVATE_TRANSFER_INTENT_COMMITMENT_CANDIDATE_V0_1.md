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

## Ordenação ainda a congelar

A intenção atual preserva posições: trocar os dois nullifiers ou os dois pares
`(commitment de saída, digest de envelope)` produz outra intenção canônica para
a mesma transferência econômica. Antes de congelar `NXIC`, o protocolo deve
escolher uma regra única: ordenar inputs por nullifier e outputs por commitment
(mantendo o digest pareado), ou declarar e justificar que a posição é parte
semântica. A implementação de `H_INTENT` fica deliberadamente bloqueada até
essa escolha, para não perpetuar maleabilidade no compromisso.

## Portões antes de implementação

Antes de expor `H_INTENT`, é obrigatório congelar `NXIC`, rederivar e conferir
o IV, executar KATs em implementação externa independente, criar corpus
canônico separado, confrontar uma referência local e testar mutação em cada um
dos 640 bytes. O verificador futuro deverá recalcular o commitment a partir da
intenção NXPT estritamente decodificada e comparar com a entrada pública da
prova; receber somente um digest do chamador não basta. Ainda faltam a AIR,
uma prova STARK, escolha criptográfica e revisão independente.
