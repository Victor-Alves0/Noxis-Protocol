# Manifesto de árvore esparsa de nullifiers — candidato v0.1 (`NXSM`)

`NXSM v1` é a base criptográfica candidata para provar que uma nota ainda não
foi gasta. Ele é filho do manifesto privado `NXPH`, mas possui três domínios
Poseidon2 e IVs próprios; não reutiliza a árvore de notas, `H_NOTE`,
`H_NULLIFIER` ou `H_INTENT`.

## Estrutura congelada

- árvore binária esparsa, com profundidade 512;
- a posição de um nullifier é a sequência completa de seus 64 bytes canônicos,
  lida bit a bit do menos significativo para o mais significativo em cada byte;
- folha gasta: `H_NF_LEAF(nullifier[64])`;
- folha vazia: `H_NF_EMPTY()`;
- pai ordenado: `H_NF_NODE(left[64] || right[64])`;
- valores vazios são obtidos por `E0 = H_NF_EMPTY()` e
  `E(n+1) = H_NF_NODE(E(n), E(n))`.

Usar todos os bits evita mapear dois nullifiers para uma chave truncada. Uma
árvore de 512 níveis é mais cara que uma estrutura reduzida, mas neste candidato
prioriza ausência de ambiguidade antes de otimizações ou alegações de produção.

O artefato contém o manifesto pai completo, descritores, IVs rederiváveis e
checksum. Seu ID é de candidato e não é um `TreeParametersId` allowlisted, uma
chave de rede, nem uma autorização para aceitar gastos.

## Limites atuais

Ainda não existe referência executável da árvore, provas de inclusão/ausência,
corpus externo, backend STARK ou transição de estado. O `H_STATE` atual continua
comprometendo o conjunto ordenado com SHA-256; ele só será migrado para a raiz
`NXSM` depois que a referência e os vetores independentes verificarem a árvore.
