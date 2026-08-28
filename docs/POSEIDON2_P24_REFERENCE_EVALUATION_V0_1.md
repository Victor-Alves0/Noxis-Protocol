# Avaliação da referência Poseidon2 P24 — v0.1

## Resultado

O crate isolado `noxis-poseidon2-reference` lê o artefato candidato P24
congelado e executa uma segunda implementação, simples e propositalmente lenta:
ele multiplica as matrizes externas e internas densas literalmente, em vez de
reutilizar as otimizações da referência Horizen.

Dois estados públicos de 24 elementos foram executados no código Horizen do
commit `055bde3f4782731ba5f5ce5888a440a94327eaf3` e coincidem exatamente com a
referência Noxis. O mesmo foi feito para a construção `Hash16` candidata,
`LEAF`, `EMPTY[0]` e raízes de profundidade 32 com zero, uma e duas notas.

Isso é evidência forte de que a leitura literal do artefato, o fluxo de rounds,
a convenção de lanes, a derivação de IV, o sponge e a recursão de árvore são
compatíveis entre os dois programas. Não é uma auditoria criptográfica, uma
seleção de parâmetros, nem uma ativação em consenso.

## Separação de responsabilidades

`noxis-poseidon2-reference` depende somente de `noxis-tree-params`. Ele não é
dependência de ledger, estado Merkle v1, ABCI, nó ou consenso. Sua API aceita
apenas elementos BabyBear canônicos, permite somente as aridades fixas da
construção candidata e limita a raiz de árvore pequena a quatro notas para
teste.

O código da Horizen é a execução externa; o código Noxis não copia sua camada
de mistura otimizada. A origem dos parâmetros continua sendo a mesma candidata
congelada, portanto essa comparação **não substitui** revisão independente da
instância criptográfica.

## Vetores congelados

Os testes no crate verificam os vetores abaixo contra saídas executadas na
clone temporária da Horizen. As chamadas externas foram:

```text
cargo test prints_p24_noxis_candidate_vectors -- --nocapture
cargo test prints_p24_noxis_candidate_tree_vectors -- --nocapture
```

no diretório `plain_implementations` do commit indicado. Os testes auxiliares
ficaram somente nessa clone de auditoria, fora do repositório Noxis.

| Caso | Resultado verificado |
| --- | --- |
| Permutação P24, estado `[0; 24]` | 24 lanes congeladas no teste `matches_independently_executed_horizen_p24_vectors` |
| Permutação P24, estado `[0, 1, ..., 23]` | 24 lanes congeladas no mesmo teste |
| `LEAF([0, 1, ..., 15])` | 16 lanes congeladas no teste de árvore |
| `EMPTY[0]` | 16 lanes congeladas no teste de árvore |
| raiz vazia, profundidade 32 | 16 lanes congeladas no teste de árvore |
| raiz com uma nota crescente | 16 lanes congeladas no teste de árvore |
| raiz com nota crescente seguida de `[42; 16]` | 16 lanes congeladas no teste de árvore |

Além da igualdade com os vetores externos, os testes recusam inputs fora do
campo, aridades erradas, mais de quatro notas no helper de árvore pequena e
verificam que `NODE(left, right)` não pode ser trocado por `NODE(right, left)`.

## Limites restantes

Estes vetores vivem em testes de referência; ainda não são um corpus `NXTV v2`
serializado e não definem uma abertura de nota ou circuitos de prova. O próximo
artefato será um corpus canônico versionado, vinculado ao manifesto P24 e
contendo folha, nó nas duas ordens, vazios, raízes e caminhos. Só depois dele a
candidata poderá avançar para a revisão de seleção descrita no gate da árvore.
