# Corpus de vetores de árvore v2 — NXTV v1

## Estado

`NXTV` v1 é o formato binário canônico para transportar **evidência de teste** da futura árvore privada v2. O leitor/escritor está isolado em `noxis-tree-params`; ele não calcula Poseidon2, raiz, prova ou caminho e não autoriza nenhum `TreeParametersId`.

Este documento permanece imutável para a candidata rascunho de largura 16. A
candidata P24 usa framing separado em
[`TREE_VECTOR_CORPUS_P24_V2.md`](TREE_VECTOR_CORPUS_P24_V2.md), pois seu estado
de permutação tem 24 elementos e seu manifesto completo não cabe no cabeçalho
v1.

Em linguagem simples: é uma folha de respostas com formato rígido. Ela diz qual saída uma futura implementação precisa obter, mas não entrega uma calculadora que possa entrar no ledger.

O corpus congelado nesta versão contém apenas os dois vetores de permutação BabyBear-16 já validados entre Rust e Zig. Os formatos de folha, nó, vazio, árvore pequena e caminho já existem para receber evidência externa posterior, mas ainda não carregam resultados criptográficos Noxis. O motivo e as condições de desbloqueio estão em [`TREE_VECTOR_GENERATION_BLOCKER_V0_1.md`](TREE_VECTOR_GENERATION_BLOCKER_V0_1.md).

## Cabeçalho canônico

Todo corpus inicia com exatamente 70 bytes:

```text
"NXTV" | version=u16be(1) | flags=u16be(0)
| manifest_length=u16be(24) | NXTM_canonical_bytes[24]
| CandidateTreeManifestId[32] | record_count=u32be
```

O `NXTM` precisa ser os bytes exatos do manifesto rascunho atual, com `kind=unselected` e payload vazio. O parser confere o ID de candidata correspondente a esse único manifesto rascunho; portanto, um cabeçalho que troca o manifesto ou apenas o ID é recusado. Isso não cria um `TreeParametersId` aprovado. Um futuro corpus de seleção precisará de nova versão ligada a um manifesto completo; `NXTV` v1 não pode ser reinterpretado como tal corpus.

O arquivo completo tem limite de 1 MiB e no máximo 4.096 registros. Esses limites são verificados antes de alocações proporcionais ao conteúdo declarado.

## Registros

Cada registro é delimitado de modo inequívoco:

```text
kind=u8 | flags=u8(0) | payload_length=u32be | payload[payload_length]
```

Os registros são ordenados lexicograficamente pelos próprios bytes e duplicatas são recusadas. Qualquer flag, tipo, tamanho ou byte final desconhecido também é recusado. Todo valor matemático tem exatamente 64 bytes: 16 inteiros BabyBear `u32` little-endian, cada um menor que `2_013_265_921`.

| Tipo | Payload canônico | Finalidade futura |
| --- | --- | --- |
| `1` Permutation | `input[64] | output[64]` | Validar uma permutação width-16. |
| `2` Leaf | `note[64] | leaf[64]` | Fixar a futura transformação `LEAF`. |
| `3` Node | `left[64] | right[64] | parent[64]` | Fixar `NODE(left,right)` e sua ordem. |
| `4` Empty | `level:u8 | value[64]` | Fixar um futuro `EMPTY[level]`, com nível `0..32`. |
| `5` SmallTree | `leaf_count:u8 | leaves[64×count] | root[64]` | Árvore append-only com 0 a 4 folhas, iniciada no índice zero. |
| `6` Path | `leaf_index:u32be | leaf[64] | siblings[32×64] | root[64]` | Caminho de profundidade 32; sibling 0 é vizinho da folha. |

Para um caminho, a direção não é declarada duas vezes: ela será derivada pelo bit `i` (do menos significativo ao mais significativo) de `leaf_index`. Isso evita que um bitmap contraditório possa fazer o mesmo caso ter duas interpretações.

Os tipos são os próprios domínios de evidência: não há nomes textuais livres nem aliases para `LEAF`, `NODE` ou `EMPTY`. A especificação completa de absorção, padding e domínios de Poseidon2 ainda pertence ao manifesto futuro; até ela existir, os registros só podem ser evidência, nunca uma regra de cálculo.

## Validação feita pelo código

`TreeVectorCorpusV1` valida:

- identidade do manifesto rascunho e do seu ID de candidata;
- limites de arquivo, número de registros, nível vazio e número de folhas pequenas;
- valores fora do campo, truncamento, bytes adicionais, flags e tags desconhecidas;
- ordem canônica e duplicatas; e
- round-trip byte a byte do corpus inicial de permutação e de cada formato de registro.

Não valida se uma raiz, um nó ou um caminho é matematicamente correto. Essa validação exige parâmetros Poseidon2 completos, domínio, árvore e referência independente — justamente os itens que permanecem bloqueados pelo [gate de seleção](TREE_BACKEND_SELECTION_GATE_V0_1.md).

## Próximo micro-objetivo

Definir e revisar uma construção completa de árvore antes de pedir resultados de `LEAF` e `NODE` às referências. A avaliação atual demonstrou que as bibliotecas de permutação não oferecem essa construção por conta própria; detalhes em [`TREE_VECTOR_GENERATION_BLOCKER_V0_1.md`](TREE_VECTOR_GENERATION_BLOCKER_V0_1.md). Antes disso não haverá backend, raiz ou transação privada v2.
