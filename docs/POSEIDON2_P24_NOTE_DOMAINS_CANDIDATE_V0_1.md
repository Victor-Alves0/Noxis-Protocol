# Candidata de domínios privados Poseidon2 P24 — v0.1

## Estado e dependência

Esta é uma candidata de extensão de hash privada, ainda não implementada e não
selecionada. Ela depende, sem alterá-la, da candidata P24 de árvore com ID
`96d8c394fc3eca456b918b96bc532a3395d53b677d7989e77914314c077dfa3b`.
Essa separação preserva os bytes, vetores e corpus `NXTV v2` já congelados para
`LEAF`, `NODE` e `EMPTY`.

Ela não cria `TreeParametersId`, nota utilizável, carteira, prova, anonimato,
resistência pós-quântica ou integração com ledger/consenso.

## Relações candidatas

Usando a mesma permutação BabyBear P24, taxa 15, capacidade 9 e digest de 16
elementos da candidata-pai, a futura referência deverá avaliar somente:

```text
recipient_commitment = H_ADDR(nullifier_key[32])
note_commitment = H_NOTE(note_preimage[178])
nullifier = H_NULLIFIER(nullifier_key[32] || rho[32] || note_commitment[64] || leaf_position:u32be)
```

A igualdade entre a chave de `H_ADDR` e de `H_NULLIFIER` é uma restrição da
AIR: ela une propriedade da nota e gasto. A chave de gasto não é uma chave
X25519, ML-KEM, Ed25519 ou ML-DSA; o envelope de cifragem do destinatário fica
fora desses hashes e só é vinculado à intenção pelo seu digest público.

## Domínios e IVs

Os únicos rótulos ASCII aceitos, todos terminados por NUL, são:

```text
NOXIS/POSEIDON2-PRIVACY/V1/ADDR\0
NOXIS/POSEIDON2-PRIVACY/V1/NOTE\0
NOXIS/POSEIDON2-PRIVACY/V1/NULLIFIER\0
```

Cada função inicia com nove lanes de capacidade derivadas por amostragem por
rejeição, sem redução modular:

```text
candidate = u32be(SHA-256(
  "NOXIS/POSEIDON2-PRIVACY-HASH-IV/V1\0" ||
  parent_candidate_id[32] || domain_label || counter:u32be
)[4*word..4*word+4])
```

Os contadores começam em zero e as palavras são consumidas em ordem. Aceitar
somente valores estritamente menores que `2_013_265_921` até formar nove
elementos. A ligação ao ID pai impede que o mesmo rótulo seja reutilizado com
outros parâmetros P24 por acidente.

## Codificação e aridades fixas

`BytePack3LE` converte três octetos `b0,b1,b2` em um elemento
`b0 + 256*b1 + 65_536*b2`; o último grupo recebe zeroes. Isso é injetivo para
os comprimentos estabelecidos abaixo e todo valor cabe no campo BabyBear.

| Função | Bytes de entrada | Elementos | Aridade fixa |
| --- | ---: | ---: | ---: |
| `H_ADDR` | 32 | 11 | 11 |
| `H_NOTE` | 178 | 60 | 60 |
| `H_NULLIFIER` | 132 | 44 | 44 |

`note_preimage` é exatamente o formato de 178 bytes definido em
[`NOTE_OPENING_BOUNDARY_V0_1.md`](NOTE_OPENING_BOUNDARY_V0_1.md). A posição no
preimage de nullifier usa quatro bytes big-endian e não um único elemento de
campo: `u32::MAX` ultrapassa o módulo BabyBear.

Depois do packing, o sponge é precisamente o da candidata de árvore: taxa
zerada, IV nas nove lanes de capacidade, absorção aditiva por blocos de 15,
zero-complemento do bloco final porque a aridade é fixa, uma permutação para
entrada vazia e squeezing de 15 lanes seguido da lane zero após outra
permutação. Nenhuma função aceita bytes livres ou tamanho escolhido pelo
chamador.

## Artefato que deverá ser congelado

Antes de implementar, `noxis-tree-params` deverá introduzir um manifesto
separado `NXPH v1` contendo: ID e bytes do manifesto pai, perfil do sponge,
perfil `BytePack3LE`, três labels, três IVs (27 elementos `u32le`), checksum e
um ID de candidata próprio, derivado com domínio diferente do ID da árvore.
Uma mudança no artefato cria candidata nova; não altera a candidata P24 pai.

O corpus também será separado (`NXNV v1`), preso ao manifesto `NXPH` e aos
preimages artificiais públicos. Ele exigirá ao menos dois KATs externos por
domínio, packing explícito, digest esperado e rejeições de mutação. `NXTV`
nunca poderá ser reinterpretado como corpus de abertura de nota.

## Portões antes de código de nota

1. materializar e revisar os bytes/IVs `NXPH` contra a derivação acima;
2. executar o sponge em um wrapper externo independente e congelar KATs;
3. implementar referência isolada e comparar byte a byte com os KATs;
4. testar cada alteração de preimage, chave, posição e caminho;
5. passar por revisão criptográfica independente antes de expor uma API de
   carteira, prover, pacote de rede ou ledger.

Esta candidata deixa as regras verificáveis, mas deliberadamente não afirma
que essas verificações, AIR ou primitivas foram implementadas.
