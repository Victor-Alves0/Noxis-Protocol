# Gate de seleção da árvore v2 — v0.1

## Estado

Este documento impede uma decisão implícita de criptografia. A representação de bytes da árvore v2 usa 16 elementos BabyBear little-endian por valor público, mas **não existe backend de árvore aprovado, `TreeParametersId` reconhecido, raiz calculada, prova verificada ou transação privada aceita**.

Uma biblioteca candidata não é uma especificação. Em particular, uma função de parâmetros-padrão de dependência não será chamada pelo protocolo até que o seu conteúdo esteja registrado, reproduzível e revisado.

## Manifesto que deve ser congelado

Antes de adicionar o backend ao workspace, um arquivo canônico versionado deve registrar, no mínimo:

- campo BabyBear, módulo `2_013_265_921`, representação de cada elemento e regra bytes-para-campo;
- variante exata de Poseidon2, largura do estado, taxa, capacidade, expoente S-box, número de rounds completos/parciais, matrizes e constantes;
- absorção, padding, posição de saída e domínios distintos para `NOTE`, `LEAF`, `NODE` e `EMPTY`;
- profundidade 32, ordem esquerda/direita, codificação de posição, folha vazia e política de inserção;
- versão, fonte, checksum e licença da implementação de referência; e
- cálculo canônico de `TreeParametersId` a partir desse manifesto e o identificador resultante.

Sem todos os itens acima, o código não pode calcular nem comparar raízes v2.

## Evidência exigida para a seleção

1. Vetores de folha, nó, árvore vazia e caminhos Merkle, produzidos por uma implementação independente ou pelo gerador oficial de parâmetros — nunca somente pelos próprios testes da implementação Noxis.
2. Teste diferencial que compare a referência Rust, os vetores e, depois, a AIR/STARK; cada um deve gerar a mesma raiz para os mesmos bytes.
3. Casos negativos para encodings fora do campo, ordem de filhos invertida, domínio trocado, posição trocada, caminho truncado e raiz divergente.
4. Dependência presa no `Cargo.lock`, verificada com Rust 1.85, e testes de parser/fuzzing e benchmark de memória/CPU com entradas adversariais.
5. Revisão criptográfica independente dos parâmetros, da referência e de sua integração com a AIR antes de qualquer ativo transferível.

## Próxima decisão limitada

A próxima entrega escolherá uma referência concreta de Poseidon2 que funcione com BabyBear e com a futura AIR/STARK, ou rejeitará as candidatas incompatíveis. Ela produzirá o manifesto e os vetores antes de introduzir uma árvore no ledger. O artigo [Poseidon2](https://eprint.iacr.org/2023/323.pdf) orienta a família de construção, mas não fornece os parâmetros próprios do Noxis.

Enquanto este gate não for satisfeito, o serviço permanece fechado pela [`CRYPTO_SERVICE_GATE_V0_1.md`](CRYPTO_SERVICE_GATE_V0_1.md).
