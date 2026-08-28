# Limite para geração de vetores de árvore v2 — v0.1

## Decisão baseada em evidência

Os vetores de `LEAF`, `NODE`, `EMPTY`, árvore e caminho **não serão inventados ou preenchidos** nesta etapa. As duas referências usadas para validar a permutação BabyBear-16 não definem a mesma construção de hash/Merkle; portanto elas não podem confirmar um vetor de árvore Noxis.

Isso não é uma pausa sem resultado: o repositório agora contém o framing `NXTV` e a evidência que mostra exatamente qual definição ainda falta. Produzir números antes de fechar essa definição criaria uma falsa impressão de interoperabilidade.

## Evidência verificada

| Referência | O que ela oferece | Por que não é oráculo de árvore Noxis |
| --- | --- | --- |
| HorizenLabs/poseidon2, commit `055bde3f4782731ba5f5ce5888a440a94327eaf3` | Permutação BabyBear-16 (`t=16`, `x^7`, 8 rounds externos, 13 internos) e constantes explícitas. | Não possui sponge, absorção, padding, serialização de bytes, domínios `LEAF`/`NODE`/`EMPTY` nem árvore BabyBear-16 com profundidade 32. A interface Merkle genérica usa `P([left,right,0])[0]`; para a instância de largura 16 ela passa três elementos para uma permutação que exige 16, não tem domínio e preenche folhas repetindo a última. |
| blockblaz/zig-poseidon, commit `47083065b6d2eb0f14ee514995e61139bda8a10c` | Mesma permutação BabyBear-16 e KATs de permutação usados para a validação cruzada. | Só oferece `permutation` e `compress` de estado completo com feed-forward `P(input)+input`; não há sponge, Merkle, domínios, `EMPTY` ou caminho. Além disso, sua reexportação pública BabyBear em `src/root.zig` aponta para um símbolo não público, e `zig test src/root.zig` falha; os testes internos não exercitam essa interface de consumidor. |

As diferenças de compressão não são detalhes de implementação. Elas mudam cada nó da árvore. Assim, não se pode derivar `NODE` de uma e pedir que a outra o confirme sem antes definir a função Noxis completa.

## O que permanece válido

- Os dois vetores de **permutação**, congelados em [`POSEIDON2_BABYBEAR16_REFERENCE_EVALUATION_V0_1.md`](POSEIDON2_BABYBEAR16_REFERENCE_EVALUATION_V0_1.md), continuam como evidência de que as duas implementações concordam na primitiva de 16 elementos.
- O `NXTV` v1 continua sendo um formato seguro e limitado de evidência pré-seleção; ele não seleciona parâmetros, não calcula árvores e não aceita transações.
- O manifesto `NXTM` atual continua vazio e explicitamente não selecionado.

## Condições para desbloquear vetores de árvore

Uma próxima proposta deve satisfazer todas as condições abaixo antes de gerar números de `LEAF`/`NODE`:

1. publicar um candidato completo de construção: representação de nota, taxa/capacidade, absorção, padding, conversão bytes-para-campo, posição de saída e bytes de domínio para `NOTE`, `LEAF`, `NODE` e `EMPTY`;
2. publicar regra exata de árvore: `EMPTY[0]`, recorrência de `EMPTY[h+1]`, ordem esquerda/direita, altura 32, folhas append-only, padding e semântica dos caminhos;
3. registrar constantes e todas essas regras em um manifesto completo, com novo ID de candidata; o `NXTM` vazio não pode ser promovido nem reinterpretado;
4. criar `NXTV` v2 ligado byte a byte a esse manifesto completo e com perfil de cobertura obrigatório, incluindo unicidade semântica dos casos;
5. executar o mesmo harness contra duas implementações independentes funcionais, corrigindo ou substituindo a interface Zig antes de contar sua saída como evidência; e
6. obter revisão criptográfica independente antes de integrar qualquer backend, AIR, raiz ou operação de ledger.

## Próximo micro-objetivo

Transformar essas condições em uma especificação de seleção revisável, com alternativas de construção e critérios de segurança. Ela será uma candidata de design, não uma ativação do protocolo.
