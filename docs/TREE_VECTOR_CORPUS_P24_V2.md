# Corpus de vetores P24 — NXTV v2

## Propósito e limite

`NXTV v2` é o formato de evidência para a candidata Poseidon2 BabyBear P24.
Ele é separado de `NXTV v1`: a permutação P24 usa estado de 24 elementos
(`96` bytes), enquanto cada valor público da árvore permanece com 16 elementos
BabyBear (`64` bytes). Não há reinterpretação de registro ou de bytes v1.

O leitor e escritor vivem em `noxis-tree-params`. Eles enquadram evidência,
verificam canonicidade, limites, ordem e vínculo ao manifesto; não calculam
Poseidon2, raízes ou provas, não criam `TreeParametersId` e não alteram
ledger, consenso ou ABCI.

## Cabeçalho fixo

Todo arquivo começa com 7.706 bytes:

| Offset | Tamanho | Campo |
| --- | ---: | --- |
| `0..4` | 4 | ASCII `NXTV` |
| `4..6` | 2 | versão `2`, big-endian |
| `6..8` | 2 | flags zero |
| `8..10` | 2 | tamanho do manifesto P24: `7.660`, big-endian |
| `10..7670` | 7.660 | manifesto candidato P24 canônico completo |
| `7670..7702` | 32 | ID candidato P24 correspondente |
| `7702..7704` | 2 | perfil de cobertura, big-endian |
| `7704..7706` | 2 | quantidade de registros, big-endian |

O decoder reexecuta `CandidatePoseidon2P24ManifestV2::decode`, recalcula o ID e
rejeita qualquer byte diferente. Campos estruturais são big-endian; elementos
BabyBear dentro dos registros são sempre `u32` little-endian e estritamente
menores que `2_013_265_921`.

O teto de arquivo é 1 MiB e o teto de registros é 4.096. Ambos são conferidos
antes de alocação proporcional ao conteúdo anunciado.

## Perfis de cobertura

O perfil `0`, **Initial**, afirma somente que o corpus contém uma amostra
inicial de resultados já confrontados com uma execução externa; não pode ser
apresentado como cobertura suficiente para selecionar parâmetros.

`frozen_initial_candidate_corpus()` contém sete registros externos verificados:
duas permutações P24, uma folha, `EMPTY[0]` e raízes de profundidade 32 para
zero, uma e duas notas. Sua codificação possui exatamente 8.712 bytes.

O perfil `1`, **Complete**, é um contrato de cobertura rígido, não uma mera
etiqueta. Ele exige exatamente 50 registros: duas permutações, quatro folhas,
as duas ordens de um nó, `EMPTY[0..32]`, raízes com 0 a 4 commitments e quatro
caminhos (índices `0`, `1`, `2` e `u32::MAX`). O parser rejeita o corpus se
qualquer uma dessas partes faltar ou for trocada por um índice fora do contrato.

`frozen_complete_candidate_corpus()` fornece esses bytes já confrontados com a
referência externa. A codificação canônica tem 21.116 bytes e SHA-256
`4f3ae2371bb9344f6ecd6b2e1d40945c43b7fa1d6d17de3ea177162de5039ce3`.
Perfil desconhecido é erro, não extensão silenciosa.

## Registros

Cada registro é delimitado de maneira inequívoca:

```text
kind:u8 | flags:u8(0) | payload_length:u32be | payload
```

Os registros são ordenados lexicograficamente pelos bytes completos e
duplicatas literais são rejeitadas. Tags e flags desconhecidas, payloads com
tamanho diferente do tipo, valores não canônicos e bytes finais também são
rejeitados.

| Tag | Registro | Payload |
| --- | --- | --- |
| 1 | `Permutation` | estado P24 de entrada `96` + saída `96` |
| 2 | `Leaf` | commitment `64` + folha `64` |
| 3 | `Node` | esquerdo `64` + direito `64` + pai `64` |
| 4 | `Empty` | nível `u8` + valor `64` |
| 5 | `SmallTree` | número de commitments `u8` + commitments + raiz `64` |
| 6 | `Path` | índice `u32be` + folha `64` + 32 siblings + raiz `64` |

Em `SmallTree`, a entrada chama-se *commitment*, não nota: a abertura de nota
ainda não está especificada. Em `Path`, `leaf` já é o resultado de `LEAF`.
A direção é o bit do índice em cada nível, do menos para o mais significativo;
não há bitmap redundante.

## Próximo passo

A cobertura de construção da árvore agora está congelada, mas ela ainda não é
uma seleção nem uma ativação do protocolo. O próximo passo técnico é definir a
abertura de nota e sua vinculação à intenção privada; depois vêm AIR/provas e
revisão criptográfica independente antes de qualquer uso no ledger ou consenso.
