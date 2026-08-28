# Vetores de referência Poseidon2 BabyBear-16 — v0.1

## Decisão desta entrega

Dois vetores de permutação Poseidon2 BabyBear-16 foram congelados no crate `noxis-tree-params` depois de serem reproduzidos em duas implementações externas independentes. Eles são um **oráculo de interoperabilidade**, não uma seleção de backend criptográfico e não uma árvore privada ativa.

Em termos simples: antes de construir uma árvore, duas calculadoras diferentes chegaram exatamente às mesmas respostas para as mesmas entradas. Isso ajuda a detectar cedo um parâmetro, ordem de bytes ou constante trocada.

## Perfil avaliado

| Propriedade | Valor avaliado |
| --- | --- |
| Campo | BabyBear, módulo `2_013_265_921` |
| Largura da permutação | 16 elementos |
| S-box | `x^7` |
| Rounds externos | 8 |
| Rounds internos | 13 |

Esse perfil descreve apenas a permutação testada. O Noxis ainda não definiu como ela seria usada para folhas, nós, sponge, domínios ou árvore vazia.

## Referências e revisões imutáveis

| Papel | Projeto | Revisão validada |
| --- | --- | --- |
| Implementação Rust e fonte dos parâmetros | [HorizenLabs/poseidon2](https://github.com/HorizenLabs/poseidon2) | commit `055bde3f4782731ba5f5ce5888a440a94327eaf3` |
| Implementação Zig independente | [blockblaz/zig-poseidon](https://github.com/blockblaz/zig-poseidon) | release `v0.2.0`; objeto da tag `1934854bfba47e08b407d64511afdf4ce4e32d07`; commit fonte `47083065b6d2eb0f14ee514995e61139bda8a10c` |
| Compilador Zig | [Zig](https://ziglang.org/download/) | `0.14.0` |
| Compilador Rust | Rust | `1.85.0` |

O teste Noxis adicionou temporariamente, fora deste repositório, um teste de comparação à cópia local da revisão Horizen. Essa alteração não é código de produção nem uma modificação enviada ao upstream.

## Corpus congelado

Cada linha representa os 16 inteiros canônicos de entrada e os 16 inteiros esperados de saída, na ordem semântica da permutação.

| Caso | Entrada | Saída esperada |
| --- | --- | --- |
| zero | `[0; 16]` | `[1337856655, 1843094405, 328115114, 964209316, 1365212758, 1431554563, 210126733, 1214932203, 1929553766, 1647595522, 1496863878, 324695999, 1569728319, 1634598391, 597968641, 679989771]` |
| quarenta e dois | `[42; 16]` | `[1000818763, 32822117, 1516162362, 1002505990, 932515653, 770559770, 350012663, 846936440, 1676802609, 1007988059, 883957027, 738985594, 6104526, 338187715, 611171673, 414573522]` |

O mesmo corpus aparece como constantes tipadas em `Poseidon2BabyBear16ReferenceVectorV1`. O teste local também exige que cada número esteja estritamente abaixo do módulo BabyBear.

## Reprodução executada

As duas verificações abaixo terminaram com sucesso no ambiente de validação:

```text
zig build test
# blockblaz/zig-poseidon v0.2.0, Zig 0.14.0
# resultado: sucesso

cargo +1.85.0 test --manifest-path plain_implementations/Cargo.toml \
  poseidon2::poseidon2::poseidon2_tests_babybear::matches_the_fixed_zig_babybear16_vectors \
  -- --exact
# HorizenLabs/poseidon2 @ 055bde3..., Rust 1.85.0
# resultado: 1 passed; 0 failed
```

Os avisos de macro de uma dependência antiga observados no segundo comando pertencem ao repositório externo e não alteram o resultado do teste; nenhuma dependência dele foi adicionada ao Noxis.

## Limites deliberados

Esta entrega não introduz:

- constantes ou matriz no payload `NXTM`;
- `TreeParametersId` reconhecido, allowlist ou nova gênese;
- função de compressão de folha/nó, raiz, caminho ou árvore Merkle;
- prova ZK/STARK, anonimato ou criptografia híbrida pós-quântica;
- backend de consenso ou código aceitando transferências privadas.

O manifesto atual continua com `kind=unselected` e payload vazio. A concordância dos vetores é condição necessária para avançar, mas não substitui a revisão criptográfica nem o gate de backend.

## Próximo micro-objetivo

Definir um formato de corpus versionado para vetores de folha, nó, árvore vazia e caminho, com domínios explicitamente nomeados. Somente após esse corpus ser reproduzível em referências independentes será possível avaliar um manifesto com payload completo, sem liberar a árvore ao ledger.
