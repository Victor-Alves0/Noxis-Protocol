# Gate de seleção da árvore v2 — v0.1

## Estado

Este documento impede uma decisão implícita de criptografia. A representação de bytes da árvore v2 usa 16 elementos BabyBear little-endian por valor público, mas **não existe backend de árvore aprovado, `TreeParametersId` reconhecido, raiz calculada, prova verificada ou transação privada aceita**.

Uma biblioteca candidata não é uma especificação. Em particular, uma função de parâmetros-padrão de dependência não será chamada pelo protocolo até que o seu conteúdo esteja registrado, reproduzível e revisado.

## Manifesto que deve ser congelado

Antes de adicionar o backend ao workspace, um arquivo canônico versionado deve registrar, no mínimo:

- framing binário canônico `NXTM` v1, começando por `"NXTM"`, versão `u16` big-endian e perfil `"NOXIS/POSEIDON2-TREE/V2\0"`; JSON, TOML e texto livre não identificam os parâmetros;
- campo BabyBear, módulo `2_013_265_921`, representação de cada elemento e regra bytes-para-campo;
- variante exata de Poseidon2, largura do estado, taxa, capacidade, expoente S-box, número de rounds completos/parciais, matrizes e constantes;
- absorção, padding, posição de saída e domínios distintos para `NOTE`, `LEAF`, `NODE` e `EMPTY`;
- profundidade 32, árvore binária append-only, capacidade lógica e operacional, ordem esquerda/direita, codificação de posição, folha vazia e política de inserção de duas saídas;
- versão, fonte, checksum e licença da implementação de referência; e
- cálculo canônico de `TreeParametersId` como `SHA-256("NOXIS/TREE-PARAMETERS-ID/V2\0" || NXTM_bytes)` e o identificador resultante.

O manifesto precisa conter as constantes matemáticas completas como elementos BabyBear little-endian, não somente uma versão de biblioteca ou checksum externo. O checksum de dependência ajuda a reproduzir a revisão, mas não é a identidade dos parâmetros. Sem todos os itens acima, o código não pode calcular nem comparar raízes v2.

## Evidência exigida para a seleção

1. Vetores separados em framing canônico `NXTV` v1: manifesto/ID, conversão bytes-para-campo, `EMPTY[0..32]`, folhas, nós nas duas ordens, raiz vazia, árvores com 1 a 4 folhas, caminhos nos índices `0`, `1`, `2` e `2^32 - 1`, e rejeições. O framing e os vetores iniciais de permutação já existem em [`TREE_VECTOR_CORPUS_FRAMING_V0_1.md`](TREE_VECTOR_CORPUS_FRAMING_V0_1.md); os vetores de árvore ainda devem vir de implementação independente ou do gerador oficial de parâmetros — nunca somente dos próprios testes da implementação Noxis.
2. Teste diferencial que compare a referência Rust, os vetores e, depois, a AIR/STARK; cada um deve gerar a mesma raiz para os mesmos bytes.
3. Casos negativos para encodings fora do campo, ordem de filhos invertida, domínio trocado, posição trocada, caminho truncado e raiz divergente.
4. Dependência presa no `Cargo.lock`, verificada com Rust 1.85, e testes de parser/fuzzing e benchmark de memória/CPU com entradas adversariais.
5. Revisão criptográfica independente dos parâmetros, da referência e de sua integração com a AIR antes de qualquer ativo transferível.

O resolvedor futuro de parâmetros aceitará somente `TreeParametersId` presente em allowlist de manifestos verificáveis. Enquanto essa allowlist não existir, qualquer ID continua não reconhecido para cálculo de raiz ou validação de transação.

## Próxima decisão limitada

A avaliação inicial rejeitou os candidatos Plonky3 que não compilam no Rust 1.85 e a linha antiga que não fecha testes publicados; detalhes em [`POSEIDON2_CANDIDATE_EVALUATION_V0_1.md`](POSEIDON2_CANDIDATE_EVALUATION_V0_1.md). A referência Rust Horizen e a implementação Zig independente já reproduziram dois vetores de permutação, registrados em [`POSEIDON2_BABYBEAR16_REFERENCE_EVALUATION_V0_1.md`](POSEIDON2_BABYBEAR16_REFERENCE_EVALUATION_V0_1.md). A próxima entrega é completar o corpus de árvore em `NXTV`, ainda sem introduzir backend no ledger. O artigo [Poseidon2](https://eprint.iacr.org/2023/323.pdf) orienta a família de construção, mas não fornece os parâmetros próprios do Noxis.

Enquanto este gate não for satisfeito, o serviço permanece fechado pela [`CRYPTO_SERVICE_GATE_V0_1.md`](CRYPTO_SERVICE_GATE_V0_1.md).
