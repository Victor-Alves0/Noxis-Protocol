# Deployment candidato de prova privada — NXPD v1

`NXPD v1` é um manifesto de **candidata não selecionada**, não um deployment ativo. Ele congela os artefatos já verificáveis que uma AIR de transferência 2×2 deverá herdar: o manifesto `NXIC` completo, o corpus externo `NXIV` completo, a forma de 640 bytes da intenção, os 214 elementos `BytePack3LE`, os 16 elementos de digest e a instância pública de 230 elementos.

O arquivo tem 19.598 bytes, SHA-256 `c2bedaaa24a6ed12818e731ee038bbaaa8b2fb5862907ed3a297808c49ca73df` e identidade candidata `bb7705a3a872342c2b217fc87a7a60bbc2e6ecc92a187a6e539d8acfabeaf2f0`.

O parser valida o checksum, `NXIC`, `NXIV` e, por consequência, toda a cadeia `NXPD → NXIC → NXPH → P24/NXTM`. Também fixa campo, largura/taxa/capacidade, rounds e funções requeridas da relação. Qualquer mudança no cabeçalho, em um ancestral ou no checksum é recusada.

`NXPD v1` antecede a declaração pública unificada
[`NXPU v1`](PRIVATE_TRANSFER_PUBLIC_STATEMENT_CANDIDATE_V0_1.md). Por isso,
ele não compromete `NXPS v2`, `NXSM`, `NXNT` ou o frame de 1.440 bytes. Um
futuro `NXPD v2` deverá fazer isso explicitamente; não é permitido ampliar o
significado de `NXPD v1` por compatibilidade informal.

## O que ele não é

- Não escolhe STARK, FRI, transcript, parâmetros, chave verificadora, `CircuitId` ou `ProofVerifierId`.
- Não produz ou verifica provas; `require_selected_backend()` sempre falha.
- Não altera `ValidationContext`, codec, ledger, consenso ou a autorização de serviço.
- Não resolve o estado privado v2, os envelopes híbridos nem a incompatibilidade com a árvore SHA-256 do ledger v1.

Quando uma AIR executável e um backend auditado existirem, eles precisarão de um **novo** artefato de seleção, nova identidade de verificador e nova gênese. Não é permitido reinterpretar `NXPD v1` como seleção de produção.
