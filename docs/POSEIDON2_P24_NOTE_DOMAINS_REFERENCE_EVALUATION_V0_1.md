# Avaliação de referência dos domínios privados P24 — v0.1

## Resultado

A referência isolada `noxis-poseidon2-privacy-reference` reproduz seis vetores
gerados fora do workspace Noxis: dois para cada domínio fixo `ADDR`, `NOTE` e
`NULLIFIER`. Ela depende somente da referência densa da permutação P24 e do
manifesto `NXPH`; não importa ledger, consenso, carteira, codec de rede ou
tipos de segredo.

O arquivo de evidência está em
[`p24-private-domain-kats-v1.json`](../crates/noxis-poseidon2-privacy-reference/fixtures/p24-private-domain-kats-v1.json).
Sua cópia externa original tinha 6.692 bytes e SHA-256
`87b3a5cb910aaa736386e16f118c9c4af12b438b861026fe0f2ffaaf6200c61f`.
A cópia versionada tem uma quebra de linha final normalizada, 6.693 bytes e
SHA-256 `c99521ac2c154de6e1212a617c5bbcd6c2f20523acf97631fed2ad3ed099cf30`;
o teste fixa deliberadamente esta cópia exata.

## Fonte externa e procedimento

Os vetores foram gerados no clone de
[HorizenLabs/poseidon2](https://github.com/HorizenLabs/poseidon2), commit
`055bde3f4782731ba5f5ce5888a440a94327eaf3`, por um wrapper temporário que usa
a permutação P24 upstream, os IVs NXPH rederivados, `BytePack3LE` e o sponge
de taxa 15/capacidade 9 especificado pela candidata. O comando executado foi:

```text
cargo test writes_noxis_p24_private_domain_kats -- --nocapture
```

Ele passou no clone externo. O wrapper de geração não foi adicionado ao
workspace Noxis, para não confundir gerador de auditoria com implementação de
protocolo.

## Cobertura registrada

| Domínio | Casos externos |
| --- | --- |
| `ADDR` | bytes ascendentes `00..1f`; bytes descendentes `ff..e0` |
| `NOTE` | bytes ascendentes `00..b1`; sequência afim `17 + 31i mod 256` |
| `NULLIFIER` | preimage estruturado com posição zero; preimage estruturado com `u32::MAX` |

Cada caso contém bytes de entrada, elementos packed, IV e digest de 16
elementos. Os testes Rust verificam os seis digests, o packing e uma mutação
isolada do preimage de nullifier. O caso `u32::MAX` confirma que a posição é
serializada em quatro bytes big-endian, não reduzida para um elemento BabyBear.

## Limites

Isto valida a referência e o formato da candidata, não uma implementação
selecionada de hash, uma AIR, uma prova de posse, sigilo de chave ou uma
transferência privada. O corpus canônico `NXNV` e seu parser estrito agora
congelam essa evidência. Ainda é obrigatório testar a construção semântica da
abertura de nota e obter revisão independente antes de expor carteira, prover
ou serviço.
