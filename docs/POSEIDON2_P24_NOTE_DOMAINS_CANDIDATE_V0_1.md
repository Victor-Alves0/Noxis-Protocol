# Candidata de domínios privados Poseidon2 P24 — v0.1

## Estado e dependência

Esta é uma candidata de extensão de hash privada, implementada somente como
artefato congelado, avaliador de referência e relações STARK de pesquisa; ela
continua não selecionada. Depende, sem alterá-la, da candidata P24 de árvore com ID
`96d8c394fc3eca456b918b96bc532a3395d53b677d7989e77914314c077dfa3b`.
Essa separação preserva os bytes, vetores e corpus `NXTV v2` já congelados para
`LEAF`, `NODE` e `EMPTY`.

Ela não cria `TreeParametersId` selecionado, nota utilizável, carteira,
anonimato, resistência pós-quântica ou integração com ledger/consenso. As
provas de pesquisa existentes não são uma ativação de protocolo.

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

## Artefato congelado

`noxis-tree-params` materializa o manifesto separado `NXPH v1`. Ele contém os
7.660 bytes e o ID do manifesto pai, perfil do sponge, perfil `BytePack3LE`,
descritores explícitos dos três labels, os 27 IVs `u32le`, checksum e ID de
candidata próprio. Uma mudança no artefato cria candidata nova; não altera a
candidata P24 pai.

| Propriedade | Valor |
| --- | --- |
| Comprimento do payload de IVs | 108 bytes |
| SHA-256 do payload | `d1ec18bc78ac13aad2edd6a0e99918a1ffb8964b0ead257730fabda2fa8df09c` |
| Comprimento do manifesto NXPH | 7.980 bytes |
| SHA-256 do manifesto | `bbcb4adab8627816a277247a4721a87f85167a1b8c4175b5a32fb4815a9d3e4c` |
| ID candidato NXPH | `57e227fd9d4cbcc697190372b8983d2bdc5e3394177510eea54f9f90f3634b8e` |

O checksum cobre, com domínio próprio, todos os bytes do manifesto antes do
campo de checksum. O ID cobre o manifesto completo; nenhum deles é um
`TreeParametersId` ou autorização de uso.

O corpus separado `NXNV v1` já está preso ao manifesto `NXPH` e aos preimages
artificiais públicos. Ele contém dois KATs externos por domínio, packing
explícito e digest esperado; testes recusam mutações. `NXTV` nunca poderá ser
reinterpretado como corpus de abertura de nota.

## Evidência existente e portões antes de produção

Já existem: wrapper externo e KATs congelados, referência isolada comparada
byte a byte, testes de mutação e relações STARK executáveis para `H_ADDR`,
`H_NOTE` e seu vínculo de posse chave→nota→nullifier. A relação de posse ainda
não inclui caminho Merkle ou estado.

Antes de expor uma API de carteira, prover, pacote de rede ou ledger, ainda é
obrigatória revisão criptográfica independente, seleção explícita de
parâmetros/backend e uma prova de transferência inteira com estado e política
de privacidade.

Esta candidata deixa as regras verificáveis, mas deliberadamente não afirma
segurança de produção ou ativação das primitivas.
