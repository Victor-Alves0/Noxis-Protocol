# Corpus de vetores dos domínios privados — NXNV v1

## Propósito e separação

`NXNV v1` transportará a evidência externa dos três hashes privados candidatos
P24. Ele é diferente de `NXTV`: `NXTV` valida a construção de árvore ligada ao
manifesto P24 de árvore, enquanto `NXNV` valida `ADDR`, `NOTE` e `NULLIFIER`
ligados ao manifesto `NXPH`. Nenhum parser deve aceitar um formato como se
fosse o outro.

O corpus é evidência de interoperabilidade, não seleção de hash, prova de
posse, carteira, ZK, anonimato ou autorização de ledger.

## Cabeçalho canônico

Todos os inteiros estruturais são big-endian:

```text
"NXNV" | version:u16be(1) | flags:u16be(0)
| nxph_length:u16be(7980) | nxph_manifest[7980]
| nxph_candidate_id[32] | profile:u16be(1) | record_count:u16be(6)
```

O decoder deve validar `NXPH` inteiro e recalcular seu ID antes de ler os
registros. Assim não é possível trocar somente um ID, um IV ou parte do
manifesto. O limite de arquivo é 16 KiB; seis é o único número de registros
aceito pelo perfil `ExternalKatSet`.

## Registros

```text
domain_tag:u8 | flags:u8(0) | payload_length:u32be
| input_bytes | packed_elements:u32le[] | digest:u32le[16]
```

| Tag | Domínio | Entrada | Elementos packed |
| --- | --- | ---: | ---: |
| 1 | `ADDR` | 32 bytes | 11 |
| 2 | `NOTE` | 178 bytes | 60 |
| 3 | `NULLIFIER` | 132 bytes | 44 |

O decoder rejeita tag/flag/tamanho desconhecido, elemento não canônico,
truncamento, bytes finais, registros duplicados e ordem não canônica. Ele deve
recalcular `BytePack3LE(input_bytes)` e exigir igualdade com os elementos
armazenados. O digest não é recalculado pelo framing: sua confirmação pertence
à referência isolada e ao teste diferencial externo.

## Cobertura fechada do perfil 1

O perfil contém exatamente dois casos artificiais por domínio:

- `ADDR`: bytes ascendentes `00..1f` e descendentes `ff..e0`;
- `NOTE`: bytes ascendentes `00..b1` e sequência `17 + 31i mod 256`;
- `NULLIFIER`: preimage estruturado com posição zero e com `u32::MAX`.

O validador deve exigir esses seis preimages, além de dois registros por
domínio. Isso impede que uma amostra mais fraca seja apresentada como este
corpus fechado. Os digests continuam conferidos pela referência em
[`POSEIDON2_P24_NOTE_DOMAINS_REFERENCE_EVALUATION_V0_1.md`](POSEIDON2_P24_NOTE_DOMAINS_REFERENCE_EVALUATION_V0_1.md).

## Artefato congelado e parser

O fixture canônico está em
[`poseidon2_babybear_p24_private_domain_vectors_v1.base64`](../crates/noxis-tree-params/fixtures/poseidon2_babybear_p24_private_domain_vectors_v1.base64).
Ao decodificá-lo de Base64, ele mede 10.050 bytes e tem SHA-256
`7d59452e61c2245b7c8f9e81279734fcb7ce51bdd8fe01e7764095f13d2b5827`.

O parser isolado `note_corpus_v1` em `noxis-tree-params` reencoda cada corpus
aceito e exige igualdade byte a byte com a entrada. Isso fixa também ordem,
framing e todas as regras de validação descritas acima, sem importar a
referência de hash nem qualquer módulo do protocolo ativo.

## Próximo passo

Implementar a abertura local de nota como crate independente, consumindo a
referência já confrontada com o corpus. Os tipos de segredo não terão codec,
`Clone`, `Debug` ou integração com o ledger nesta etapa.
