# Corpus candidato de vetores de intenção — NXIV v1

`NXIV v1` é o arquivo binário canônico de evidência para `H_INTENT`. Ele não calcula hashes e não depende da referência: transporta dois resultados produzidos externamente e obriga quem o lê a aceitar somente aqueles bytes.

## Formato fixo

- Cabeçalho de 8.208 bytes: `NXIV`, versão 1, flags zero, os 8.162 bytes completos do manifesto `NXIC`, seu ID e o perfil externo de dois casos.
- Cada registro tem 1.566 bytes: tag do caso, flags zero, tamanho fixo 1.560, intenção canônica de 640 bytes, 214 elementos `BytePack3LE` em `u32le` e digest de 16 elementos BabyBear em `u32le`.
- O corpus totaliza 11.340 bytes e tem SHA-256 `732a2607da61d26b233150b7b288508d0226a9e53d6bbc471b85abfa4899cc2e`.

Os casos são `StructuralBaseline` e `BoundaryElements`. Ambos passam pelo decoder de `PrivateTransferIntentV2`; o segundo exercita `0`, `1`, `p-2` e `p-1`.

O parser rejeita tamanho, cabeçalho, pai NXIC, ID, perfil, tags, ordem, packing, digest não canônico, entradas não canônicas, truncamento e bytes extras. A crate de referência verifica separadamente que o seu cálculo de `H_INTENT` coincide com cada digest do corpus; isso evita tornar o parser um segundo hash duplicado ou introduzir dependência circular.

`NXIV` é evidência candidata, não autorização de consenso, prova ZK, seleção criptográfica ou proteção de anonimato por si só.
