# Manifesto candidato de compromisso da intenção — NXIC v1

## Estado

`NXIC v1` congela a moldura do futuro `H_INTENT`: uma função Poseidon2-BabyBear-P24 que receberá **exatamente** os 640 bytes canônicos de `PrivateTransferIntentV2`. Isto é uma candidata técnica, não uma seleção de consenso, não uma prova e não autoriza transferências.

O ID da candidata é `fec73e2b8238b749357042bdba55470d674fb12ca498c47bb761854ca85b20e5`. O SHA-256 dos 8.162 bytes do manifesto é `7d8395b7134ead94e15a65a59e856afacf3dc2e9add882c1a2eee00be30e2950`.

## O que fica fixo

- A cadeia de proveniência é `NXIC -> NXPH -> NXTM`: o manifesto inclui os 7.980 bytes completos do pai `NXPH`, além de seu ID.
- Há um único domínio: `NOXIS/POSEIDON2-PRIVACY/V1/INTENT-COMMITMENT\0`.
- A entrada tem 640 bytes; `BytePack3LE` produz 214 elementos; a taxa é 15 e a capacidade é 9. Portanto são 15 absorções, sem tamanho variável ou padding ambíguo.
- O IV de nove elementos vem de SHA-256 com amostragem por rejeição, usando o ID do pai **NXPH**, o label acima e o domínio próprio `NOXIS/POSEIDON2-INTENT-COMMITMENT-IV/V1\0`.
- O checksum cobre cada byte anterior do manifesto; a decodificação aceita apenas os bytes idênticos à codificação canônica.

## Limites deliberados

Ainda não existe uma implementação pública de `H_INTENT`, corpus externo nem AIR/prova. O manifesto não deve ser adicionado a allowlists, mensagens de rede, ledger ou IDs ativos. A próxima entrega precisa produzir e verificar vetores externos antes de expor a função hash.
