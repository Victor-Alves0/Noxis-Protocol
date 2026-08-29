# Interface de testemunha e restrições de transferência privada — candidata v0.1

## Finalidade e estado

Esta interface descreve os dados que um futuro provador/AIR deverá receber
para uma transferência privada fixa de duas entradas e duas saídas. Ela une a
verificação local das notas ao caminho sequencial da árvore de nullifiers
`NXSM`, mas **não** cria AIR, STARK, prova, pacote de rede, mutação de ledger
ou autorização de consenso.

O código correspondente é `CandidateNxsmNullifierTransitionWitnessV1`, no
crate `noxis-private-proof-contract`. Ele é um objeto somente local: não tem
codec, não é persistido e não deve ser incluído em logs, telemetria ou
mensagens.

## Partes da relação

| Parte | Origem | Papel |
| --- | --- | --- |
| Aberturas de notas e caminhos de inclusão | `CandidatePrivateTransferWitnessV2` | Testemunha privada das duas entradas, das duas saídas e da conservação de valor. |
| Intenção canônica | `PrivateTransferIntentV2` | Declaração pública fixa de 640 bytes. |
| Moldura pública de notas | `CandidatePrivateTransferAirPublicInputsV1` | 214 elementos `BytePack3LE` da intenção e 16 elementos de `H_INTENT`. |
| Âncora prévia | `PrivateStateAnchorV2` (`NXPS v2`) | Liga gênese, contexto, raiz de notas, `StateId`, raiz e contagem `NXSM`. |
| Declaração de nullifiers | `CandidateNxsmNullifierTransitionV1` (`NXNT v1`) | Liga a intenção, ausência dos dois nullifiers e a raiz/contagem posterior. |
| Caminhos `NXSM` | `CandidateNxsmNullifierTransitionWitnessV1` | Testemunha privada de ausência, em ordem, para as duas inserções. |

Todas as partes devem descrever a mesma intenção: os mesmos 640 bytes,
`H_INTENT`, `pre_state_id`, dois nullifiers, raiz de notas e parâmetros de
árvore. Não é permitido conectar componentes apenas por convenção do
chamador.

## Ordem obrigatória dos caminhos `NXSM`

Os nullifiers já estão ordenados pelos seus 64 bytes canônicos na intenção.
Cada caminho contém 512 irmãos BabyBear de 64 bytes, na ordem folha→raiz; a
direção de cada nível é derivada do bit correspondente do nullifier, nunca de
um bitmap fornecido pelo chamador.

1. O primeiro caminho prova ausência de `nullifier_0` na `pre_root` pública.
2. A AIR calcula a raiz intermediária inserindo `nullifier_0`.
3. O segundo caminho prova ausência de `nullifier_1` nessa raiz
   intermediária, e não novamente na `pre_root`.
4. A AIR insere `nullifier_1`; a raiz resultante deve ser a `post_root` de
   `NXNT`, e a contagem deve ser `pre_spent_count + 2` sem overflow.

Esse passo intermediário é necessário porque os caminhos podem se sobrepor.
Duas provas de ausência independentes contra a raiz antiga não demonstram a
transição atômica completa.

## Limites de recursos e representação

Somente os dois caminhos `NXSM` ocupam `2 × 512 × 64 = 65.536` bytes de
irmãos antes de estruturas do provador. A futura implementação deve declarar
limites de memória e CPU, validar a profundidade fixa antes de alocar e manter
essas estruturas fora de qualquer parser de rede.

As notas usam dois caminhos de inclusão de profundidade 32. Valores devem ser
decompostos de forma definida em limbs para a soma `u128`; elementos BabyBear
devem ser canônicos; comparações de nullifiers e commitments usam os bytes
canônicos, não uma ordenação informal de elementos de campo.

## Limites deliberados

- A interface não revela ou serializa aberturas, chaves, aleatoriedade ou
  caminhos; eles permanecem locais até um backend de prova auditado.
- Ela não estabelece a raiz de notas posterior, o próximo `NXPS`, envelopes
  híbridos nem o vínculo entre digest de ciphertext e conteúdo cifrado.
- Ela não torna `NXPD v1` uma seleção de backend: aquele manifesto ainda fixa
  apenas a moldura pública de 230 elementos e continua não ativável.
- Ela não autoriza uso do `ProofVerifier` do ledger v1, que possui tipos de
  estado incompatíveis.

## Critérios mínimos para a futura AIR

Antes de selecionar backend, os testes devem rejeitar alteração de cada
vínculo cruzado (`H_INTENT`, nullifier, raiz, contagem, `StateId` e parâmetro),
qualquer irmão de ambos os caminhos, inversão da ordem, profundidade diferente
e toda conversão não canônica. Também devem comparar a AIR com a referência
Rust e vetores externos para as raízes prévia, intermediária e posterior.
