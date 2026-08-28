# Artefato de parâmetros P24 candidato — v0.1

## Estado e limite

Este é um artefato **congelado, porém não selecionado**. Ele permite que
qualquer implementação recupere os mesmos parâmetros completos da candidata
de árvore Poseidon2 descrita em
[`POSEIDON2_TREE_CONSTRUCTION_CANDIDATE_V0_1.md`](POSEIDON2_TREE_CONSTRUCTION_CANDIDATE_V0_1.md).

Ele não cria `TreeParametersId`, não implementa Poseidon2, não calcula raiz ou
prova Merkle, não é aceito pelo ledger e não ativa anonimato, ZK ou proteção
pós-quântica. A identidade abaixo é propositalmente um
`CandidatePoseidon2P24ManifestIdV2`, tipo diferente de qualquer futura
identidade aprovada para consenso.

## Origem reproduzível

Os valores P24 foram extraídos do arquivo
`plain_implementations/src/poseidon2/poseidon2_instance_babybear.rs` do commit
Horizen `055bde3f4782731ba5f5ce5888a440a94327eaf3`. O SHA-256 do blob Git bruto
(UTF-8 com LF, sem conversão local de quebras de linha) é:

```text
b1374c02b1d87aff34180c66cbe422e5493f76ded137b4548461d1dd250fcf1b
```

O perfil é BabyBear `p=2_013_265_921`, largura 24, expoente 7, 8 rounds
externos e 21 internos. A matriz externa foi materializada em ordem de linhas
densa; a matriz interna preserva a forma `J + diag(diag_m_1)` da referência.
Isso remove dependência de geração de constantes em tempo de execução.

## Arquivo canônico

O arquivo
[`poseidon2_babybear_p24_candidate_v1.base64`](../crates/noxis-tree-params/fixtures/poseidon2_babybear_p24_candidate_v1.base64)
contém somente a carga útil base64. Espaços em branco são ignorados pelo leitor
para facilitar revisão; os bytes decodificados são os dados comprometidos.

Ordem exata dos 1.899 elementos BabyBear, todos `u32` little-endian:

1. 24 elementos de `diag_m_1`;
2. 576 elementos da matriz externa densa 24×24 em ordem de linhas;
3. 576 elementos da matriz interna 24×24 em ordem de linhas;
4. 696 constantes de round, 29×24 em ordem de rounds e depois lanes;
5. três IVs de nove elementos: `LEAF`, `NODE`, `EMPTY-BASE`.

O leitor verifica comprimento, SHA-256, canonicidade de cada elemento e a
derivação independente de cada IV antes de devolver os bytes.

| Propriedade | Valor |
| --- | --- |
| Comprimento da carga útil | 7.596 bytes |
| SHA-256 da carga útil | `48f6c25b02a640c06e3bbc8fc49704634f254cd0a77161a59b283e5302a390b0` |
| Comprimento do manifesto | 7.660 bytes |
| SHA-256 do manifesto | `b3887f4fcf0b125646af8a8ebe3bcc48143c1ad7811b208819408afb01673278` |
| ID candidato | `96d8c394fc3eca456b918b96bc532a3395d53b677d7989e77914314c077dfa3b` |

O ID é `SHA-256("NOXIS/TREE-P24-PARAMETERS-CANDIDATE-ID/V1\\0" || manifesto)`.

## Cabeçalho binário de 64 bytes

O manifesto começa com `NXTM`, versão big-endian 2, tipo candidato 1 e flags
zero. Em seguida fixa: perfil 1, profundidade 32, aridade binária, campo e
codificação BabyBear, digest de 16 elementos, largura 24, parâmetros de round,
taxa/capacidade, layouts das matrizes, módulo, dimensões, quantidade de IVs e
comprimento da carga útil. Os últimos 22 bytes do cabeçalho são zero e
reservados; qualquer mudança é rejeitada pelo decoder canônico.

O módulo `noxis-tree-params` só aceita a sequência completa de 7.660 bytes.
Uma alteração em header ou parâmetros não se torna uma "variante compatível":
ela precisa de nova proposta, vetores e revisão.

## Próximo bloqueio

Agora faltam duas implementações independentes da permutação P24 e do sponge
fixo para gerar e comparar vetores `NXTV v2` de folha, nó, vazios, raízes e
caminhos. Só depois disso será possível discutir uma seleção formal — ainda
separada da abertura de nota, circuitos/provas e ativação no ledger.
