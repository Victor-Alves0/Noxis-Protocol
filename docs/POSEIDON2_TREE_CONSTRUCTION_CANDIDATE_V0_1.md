# Candidata de construção da árvore Poseidon2 — v0.1

## Escopo e decisão

Este documento registra a **única candidata de design em avaliação** para produzir os vetores de árvore v2. Ela não seleciona parâmetros, não altera `NXTM`, não cria `TreeParametersId`, não entra no ledger e não autoriza prova, anonimato ou transferência privada.

A candidata usa a permutação Poseidon2 BabyBear de largura 24, não a de largura 16. O gerador de parâmetros da Horizen diferencia explicitamente BabyBear `t=24` para sponge e `t=16` para compressão. Isso torna `t=24` uma base mais justificável para uma hash de mensagem/árvore que precisa absorver vetores de 16 elementos e produzir digest de 16 elementos. [Gerador de parâmetros da Horizen](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)

O artigo Poseidon2 define o sponge por uma permutação com `t = rate + capacity`, absorção aditiva e saída somente da taxa; ele não transforma, por si só, uma biblioteca de permutação em uma especificação de árvore. [Poseidon2, seção 3](https://eprint.iacr.org/2023/323.pdf)

## Perfil de permutação proposto para avaliação

| Propriedade | Valor candidato |
| --- | --- |
| Campo | BabyBear, `p = 2_013_265_921` |
| Largura | `t = 24` |
| S-box | `x^7` |
| Rounds externos | `8` (`4 + 4`) |
| Rounds internos | `21` |
| Taxa | `15` elementos |
| Capacidade | `9` elementos |
| Digest público | `16` elementos BabyBear, em 64 bytes canônicos |

A capacidade de nove elementos fornece aproximadamente `9 × log2(p) / 2 ≈ 139` bits na fronteira genérica de sponge. Isso excede 128 bits como margem genérica; **não** é uma prova de segurança da instância, da implementação ou da integração Noxis. O digest de 16 elementos é obtido somente por lanes da taxa (`15 + 1`), sem revelar as nove lanes de capacidade.

## IV por domínio

Cada função começa com um IV de capacidade diferente. Não se aceita texto livre ou tag escolhida por chamador.

Os domínios ASCII exatos, cada um terminado por byte NUL, são:

```text
NOXIS/POSEIDON2-TREE/V2/LEAF\0
NOXIS/POSEIDON2-TREE/V2/NODE\0
NOXIS/POSEIDON2-TREE/V2/EMPTY-BASE\0
```

Para um domínio `D`, os nove elementos de `IV(D)` são derivados assim:

```text
candidate(counter, word) = u32be(
  SHA-256("NOXIS/POSEIDON2-TREE-IV/V2\0" || D || counter:u32be)[4*word..4*word+4]
)

Percorrer counter = 0, 1, 2, ... e word = 0, ..., 7.
Aceitar cada candidate estritamente menor que p até obter nove valores,
mantendo a ordem de aceitação. Descartar os demais valores sem reduzi-los módulo p.
```

Assim, toda lane é canônica e nenhuma redução modular introduz uma regra implícita. Os nove valores derivados serão incluídos como bytes no futuro manifesto, de modo que a AIR ou o nó nunca precisem calcular SHA-256 para construir o IV.

## `Hash16(D, X)` de aridade fixa

`Hash16` **não é uma API genérica para bytes ou tamanhos escolhidos pelo chamador**. Cada domínio desta candidata aceita apenas a aridade indicada abaixo. Essa restrição evita colisões entre mensagens de comprimentos diferentes sem adotar um padding incompleto — uma classe de falha que já afetou uma construção sponge de terceiros. [Advisory GHSA-3g92-f9ch-qjcm](https://github.com/advisories/GHSA-3g92-f9ch-qjcm)

Para entrada fixa `X = [x0, ..., x(n-1)]`, com cada `xi` BabyBear canônico e `n` imposto pelo domínio:

```text
S = [0; 15] || IV(D)                         # 24 elementos
separar X em blocos de até 15 elementos
para cada bloco B:
    completar B com zeroes até 15 elementos  # o tamanho é conhecido pelo domínio
    S[0..15] = S[0..15] + B (no campo)
    S = P24(S)

se n = 0:
    S = P24(S)                               # não expor a taxa inicial zerada

O0 = S[0..15]
S = P24(S)
O1 = S[0]
return O0 || [O1]                            # 16 elementos
```

Não há padding variável, squeezing da capacidade, feed-forward ou truncamento diferente. Uma função de nota com campos variáveis precisa de especificação própria e não pode reutilizar esta candidata silenciosamente.

## Funções da árvore

`V` denota um vetor canônico de 16 elementos BabyBear (`64` bytes).

```text
LEAF(cm: V)           = Hash16(LEAF, cm)                 # aridade 16
NODE(left: V, right: V)= Hash16(NODE, left || right)      # aridade 32, ordem preservada
EMPTY[0]              = Hash16(EMPTY-BASE, [])           # aridade 0
EMPTY[h + 1]          = NODE(EMPTY[h], EMPTY[h])          # 0 <= h < 32
```

`EMPTY[0]` não é o vetor zero e não é `LEAF` de uma nota zerada. Isso mantém slot ausente separado de qualquer commitment válido.

Esta candidata não define ainda a abertura que produz `cm`. O tipo atual `NoteCommitmentV2` continua sendo apenas uma fronteira de serialização canônica; a futura especificação de nota terá de definir destinatário, valor, aleatoriedade, vínculo de envelope e domínio `NOTE` antes de poder alimentar `LEAF`.

## Árvore, inserção e caminho

```text
slot(i) = LEAF(commitment[i]) para i < next_leaf_index
slot(i) = EMPTY[0]           para i >= next_leaf_index

N[0][i] = slot(i)
N[h + 1][i] = NODE(N[h][2i], N[h][2i + 1])
root = N[32][0]
```

A capacidade lógica é `2^32` folhas. A árvore é binária e append-only: `next_leaf_index` é estado consensual persistido; não existe remoção, substituição ou reutilização de slot. Em uma transferência 2×2 futura, as duas saídas entram na ordem canônica `output_commitments[0]`, depois `[1]`; a operação é recusada se faltarem dois slots.

O caminho de uma nota no índice `i` tem 32 siblings, começando pelo vizinho da folha. No nível `h`, o bit `h` de `i` (menos significativo primeiro) decide se `current` é filho esquerdo ou direito. A verificação só aceita `current == root` depois dos 32 níveis.

## Evidência que ainda falta

Esta candidata só pode seguir para um manifesto completo se todos os itens abaixo forem cumpridos:

1. extrair e congelar matriz, constantes e parâmetros completos de P24 em bytes canônicos;
2. reproduzir KATs P24 e o sponge desta especificação em duas implementações independentes funcionais;
3. gerar `NXTV v2`, vinculado a esse manifesto completo, com `LEAF`, as duas ordens de `NODE`, `EMPTY[0..32]`, raízes 0–4 e caminhos `0`, `1`, `2` e `2^32 - 1`;
4. definir a abertura de `NoteCommitmentV2`, incluindo vínculo ao `CiphertextDigestV2` e endereço/chave do destinatário; e
5. obter revisão criptográfica independente da instância, do modo sponge, do AIR e da integração.

Até esses pontos, este documento é uma candidata de engenharia versionada e auditável — não uma alegação de segurança nem uma mudança de rede.
