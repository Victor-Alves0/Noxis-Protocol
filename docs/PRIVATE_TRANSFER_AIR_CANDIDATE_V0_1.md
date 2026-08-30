# Relação AIR candidata para transferência privada 2×2 — v0.1

## Estado e fronteira

Esta é a especificação verificável da relação que uma prova futura deverá satisfazer. A implementação atual fornece a moldura pública, a revalidação local da testemunha e uma fatia AIR/STARK isolada para o sponge público `H_INTENT`; **não há AIR completo de transferência, chave verificadora selecionada, prova utilizável ou aceitação pelo ledger**.

Ela permanece deliberadamente isolada do ledger v1: aquele usa raízes, commitments e nullifiers SHA-256 de 32 bytes; a candidata privada usa valores Poseidon2/BabyBear de 64 bytes. Uma transferência privada precisará de estado, transição e gênese v2 próprios — nunca de conversão implícita para `TransferStatement` v1.

## Instância pública canônica

A moldura original de 230 elementos continua sendo a parte da relação de
notas. A relação completa também tem uma declaração unificada local
[`NXPU v1`](PRIVATE_TRANSFER_PUBLIC_STATEMENT_CANDIDATE_V0_1.md), que vincula
essa moldura à âncora `NXPS v2` e à transição `NXNT v1`. `NXPU` ainda não é uma
lista de entradas AIR selecionada: essa tradução exige backend e revisão.

A instância tem 230 elementos BabyBear, nesta ordem:

```text
M[0..214)  = BytePack3LE(PrivateTransferIntentV2::encode()[640])
H[0..16)  = H_INTENT(intent[640])
```

`M[0]` até `M[212]` devem ser menores que `2^24`; `M[213]` deve ser menor que `2^8`. A fatia AIR atual já decompõe cada um dos 640 bytes privados do traço em oito bits Booleanos, recompõe os bytes e força cada `M` público a ser o `BytePack3LE` correspondente antes de reavaliar `H_INTENT`. Ela ainda não conecta esses bytes às witnesses de posse, abertura, valor ou nullifier; portanto não pode ser tratada como a relação completa.

Os bytes recompostos carregam, na ordem já congelada: circuito, gênese, contexto de validação, estado anterior, parâmetros da árvore, raiz privada, ativo, dois nullifiers, dois commitments de saída e dois digests de envelopes. A moldura [`CandidatePrivateTransferAirPublicInputsV1`](../crates/noxis-private-proof-contract/src/public_inputs.rs) só pode ser construída de uma `PrivateTransferIntentV2` canônica e rederiva `H_INTENT`.

O preflight local já rejeita witnesses cujas quatro notas não tenham o ativo
público, entradas de valor zero, overflow em qualquer soma `u128` ou
conservação inválida. Isso reduz a superfície de erros antes do prover, mas
não transforma a regra em zero conhecimento: a AIR única ainda precisa impor
esses mesmos limbs e carries.

## Testemunha privada e restrições

Para cada entrada, a testemunha contém abertura da nota, chave de nullifier, posição e 32 irmãos Merkle. Para cada saída, contém abertura da nota. A declaração `NXNT` exige ainda dois caminhos `NXSM` de 512 irmãos na sequência prévia → intermediária → posterior, conforme a [interface de witness](PRIVATE_TRANSFER_WITNESS_CONSTRAINT_INTERFACE_CANDIDATE_V0_1.md). A AIR deverá impor:

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

- Uma fronteira local já redecodifica o pacote e confere a frame candidata que compromete slot, commitment e `NXRE` canônico, mas ainda não há vetores externos, AAD de transação selecionada ou AIR que recompute cada digest de ciphertext. Portanto ela ainda não prova correspondência com chave do destinatário ou dentro da própria AIR.
- A chave ligada por `H_ADDR` ainda não está ligada a uma chave de recebimento X25519/ML-KEM.
- Não existe estado privado persistente v2, política de raízes, conjunto global de nullifiers ou inserção atômica das saídas.
- A declaração [`NXPU v1`](PRIVATE_TRANSFER_PUBLIC_STATEMENT_CANDIDATE_V0_1.md) já une a moldura de notas, `NXPS v2` e `NXNT v1`, mas ainda não há AIR que demonstre a relação em zero conhecimento nem que atualize a raiz de notas.
- `CircuitId`, `ProofVerifierId`, digest do programa AIR e backend STARK permanecem não selecionados.

Essas lacunas são bloqueios de segurança, não detalhes de implementação. O perfil [`NXAR v1`](PRIVATE_TRANSFER_AIR_PROFILE_CANDIDATE_V0_1.md) já congela a forma e as famílias de restrição existentes; o próximo artefato deve juntar a fatia `H_INTENT` a uma primeira família de witness, continuando a falhar fechado até existir backend auditado.
