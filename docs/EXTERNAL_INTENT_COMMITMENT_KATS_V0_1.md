# Vetores externos de `H_INTENT` — v0.1

## Evidência reproduzível

Os dois vetores aceitos pela referência foram calculados fora do workspace Noxis, com a implementação P24 de [HorizenLabs/poseidon2](https://github.com/HorizenLabs/poseidon2) no commit `055bde3f4782731ba5f5ce5888a440a94327eaf3`.

O gerador independente usa somente os valores públicos congelados por `NXIC v1`: estado zero, IV nas lanes 15–23, `BytePack3LE`, taxa 15, uma permutação por bloco e o squeeze de 16 elementos. Ele não importa a implementação Noxis.

O JSON original produzido pelo gerador tem SHA-256 `fae1a66c0e51f82eb5189833d6291d5709385b2e18924064afc6307daf6c4ca5`. Para reproduzi-lo no clone externo usado nesta auditoria:

```text
cd C:\Users\Victor\AppData\Local\Temp\noxis-poseidon2-horizen-20260828\plain_implementations
cargo run --quiet --example nxic_intent_kat
```

O artefato contém `candidate_id` NXIC `fec73e2b8238b749357042bdba55470d674fb12ca498c47bb761854ca85b20e5`, IV `[1819200036, 1876339393, 1398038240, 209277844, 1313667583, 1517749525, 1941790785, 769299377, 68669752]` e payload SHA-256 `cf8283c18dd1ac74ae1eb9b1d05e4bb89ea419960dd6fff4270aa59f5274c469`.

## Casos fechados

| Caso | Entrada SHA-256 | Digest de 16 elementos BabyBear |
|---|---|---|
| `StructuralBaseline` | `c6ddd091560fe04e41bed807c12c3d776d851ff72e0961a0a99e268d146a8292` | `[1098549077, 1235522076, 1478424652, 1481381536, 528608958, 1330079375, 362586605, 1738919005, 1916043278, 1954911332, 1841702528, 1249444496, 400154715, 294159042, 1980980091, 376305720]` |
| `BoundaryElements` | `d72349e7aa1ce9bf49d791807205d80b1c7101b8f8bd345f30a55b782b3e6c27` | `[1434497478, 1681194821, 1869074451, 1023130484, 560801581, 1937059648, 540867581, 1942987663, 730711795, 1218251084, 43830160, 533681248, 971936176, 1743410686, 1304665704, 981526481]` |

Os dois 640-byte inputs passam por `PrivateTransferIntentV2::decode` e reencodam sem alteração. O segundo inclui `0`, `1`, `p-2` e `p-1` em vetores BabyBear. Os testes locais também alteram um a um os 640 bytes do primeiro caso e exigem digest diferente.

Isto valida uma referência candidata contra um oráculo externo; não equivale a uma auditoria criptográfica, seleção de parâmetros, prova de conhecimento zero ou ativação no consenso.
