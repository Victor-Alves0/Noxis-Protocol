# Relação AIR candidata para transferência privada 2×2 — v0.1

## Estado e fronteira

Esta é a especificação verificável da relação que uma prova futura deverá satisfazer. A implementação atual fornece apenas a moldura pública e a revalidação local da testemunha; **não há AIR executável, STARK, chave verificadora, prova ou aceitação pelo ledger**.

Ela permanece deliberadamente isolada do ledger v1: aquele usa raízes, commitments e nullifiers SHA-256 de 32 bytes; a candidata privada usa valores Poseidon2/BabyBear de 64 bytes. Uma transferência privada precisará de estado, transição e gênese v2 próprios — nunca de conversão implícita para `TransferStatement` v1.

## Instância pública canônica

A instância tem 230 elementos BabyBear, nesta ordem:

```text
M[0..214)  = BytePack3LE(PrivateTransferIntentV2::encode()[640])
H[0..16)  = H_INTENT(intent[640])
```

`M[0]` até `M[212]` devem ser menores que `2^24`; `M[213]` deve ser menor que `2^8`. A AIR decompõe os elementos em bytes, recompõe exatamente os 640 bytes, faz o range-check e reavalia `H_INTENT`. Assim, `H` não pode ser apresentado como compromisso de outra intenção.

Os bytes recompostos carregam, na ordem já congelada: circuito, gênese, contexto de validação, estado anterior, parâmetros da árvore, raiz privada, ativo, dois nullifiers, dois commitments de saída e dois digests de envelopes. A moldura [`CandidatePrivateTransferAirPublicInputsV1`](../crates/noxis-note-opening/src/statement.rs) só pode ser construída de uma `PrivateTransferIntentV2` canônica e rederiva `H_INTENT`.

## Testemunha privada e restrições

Para cada entrada, a testemunha contém abertura da nota, chave de nullifier, posição e 32 irmãos Merkle. Para cada saída, contém abertura da nota. A AIR deverá impor:

1. `circuit_id` e `tree_parameters_id` públicos são as constantes exatas do deployment candidato.
2. Para cada entrada: `recipient = H_ADDR(key)`, `cm = H_NOTE(...)`, `nf = H_NULLIFIER(key || rho || cm || position)`, caminho Merkle de 32 níveis e `root == pre_state_root`.
3. Para cada saída: `cm_out = H_NOTE(...)` coincide com seu slot público, usando o ativo público.
4. Ambas as entradas têm ativo público e valor não nulo; saídas podem ser zero apenas como padding.
5. Valores são representados sem overflow em 128 bits e `in_0 + in_1 = out_0 + out_1`.
6. A ordem byte-léxica de nullifiers e commitments, notas/posições distintas, `cm_out` diferente de qualquer `cm_in`, e `rho`/`rcm` distintos nas quatro aberturas.

As comparações de ordem devem usar os 64 bytes canônicos, não comparação informal de elementos do campo.

## Constantes que o deployment deverá fixar

O deployment AIR precisa comprometer os IDs e bytes completos de P24, NXPH e NXIC, além de BabyBear `p = 2_013_265_921`, Poseidon2 largura 24/taxa 15/capacidade 9, `x^7`, 8 rounds completos, 21 parciais, IVs e as funções `H_ADDR`, `H_NOTE`, `H_NULLIFIER`, `H_INTENT`, `LEAF` e `NODE`.

## Lacunas que bloqueiam uma prova utilizável

- Não há especificação de cifra/envelope que prove que cada digest de ciphertext corresponde à nota, slot, AAD e chave do destinatário.
- A chave ligada por `H_ADDR` ainda não está ligada a uma chave de recebimento X25519/ML-KEM.
- Não existe estado privado persistente v2, política de raízes, conjunto global de nullifiers ou inserção atômica das saídas.
- A relação transparente [`NXNT v1`](PRIVATE_TRANSFER_NXSM_TRANSITION_CANDIDATE_V0_1.md) já vincula `NXPS v2`, ausência dos dois nullifiers e raiz `NXSM` posterior, mas ainda não há AIR que demonstre essa relação em zero conhecimento nem que atualize a raiz de notas.
- `CircuitId`, `ProofVerifierId`, digest do programa AIR e backend STARK permanecem não selecionados.

Essas lacunas são bloqueios de segurança, não detalhes de implementação. O próximo artefato deve ser um manifesto de deployment de prova que as represente e continue falhando fechado até existir backend auditado.
