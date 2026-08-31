# Conservação de valor privada 2×2 vinculada a `H_NOTE` — pesquisa v0.1

## Garantia executável

`prove_and_verify_p24_value_conservation` constrói e verifica localmente uma
prova STARK hiding-FRI para quatro pré-imagens canônicas privadas de 178 bytes,
na ordem `input_0`, `input_1`, `output_0`, `output_1`.

A relação faz parte de `noxis-stark-experiment` e impõe, no mesmo AIR:

1. cada pré-imagem produz seu commitment exato com `H_NOTE`/Poseidon2-P24;
2. cada nota tem versão canônica `1` e os 32 bytes de ativo iguais ao único
   `asset_id` público;
3. os dois valores de entrada, nos 16 bytes big-endian canônicos, não são
   zero;
4. cada soma de duas entradas ou de duas saídas é feita byte a byte, do byte
   menos significativo ao mais significativo, com carry Booleano explícito;
5. os carries finais são zero — portanto nenhuma soma ultrapassa `u128` — e
   as duas somas são iguais.
6. na variante composta usada pelo preflight, os commitments `H_NOTE` das duas
   saídas são iguais aos dois slots codificados nos bytes canônicos do mesmo
   `H_INTENT`.

Os valores, destinatários, `rho`, `rcm` e o restante das pré-imagens ficam no
traço privado. A prova também range-checka todos os bytes das quatro notas com
decomposição em oito bits e recompõe o packing `BytePack3LE` usado por
`H_NOTE`; não confia em uma representação alternativa de valor.

## Interface pública de pesquisa

O experimento isolado recebe publicamente quatro commitments P24 e o
`asset_id`. A variante composta acrescenta os 230 elementos públicos já
necessários a `H_INTENT`, mas não uma cópia dos slots de saída: ela os lê dos
bytes autenticados desse intent. Isso é necessário para testar a composição
entre quatro aberturas, aritmética e intenção em um único AIR, mas **não é uma
interface de transação Noxis**: revelar os commitments de entrada prejudicaria
a privacidade. A API é apenas in-memory, verifica a prova na mesma execução e
descarta tanto a prova opaca quanto esse resultado de pesquisa.

`prove_and_verify_p24_intent_value_conservation` é a variante composta usada
por `run_candidate_value_conservation_preflight`. Ela coloca, no mesmo traço
de 512 linhas, a AIR de `H_INTENT` e a AIR das quatro notas. Para cada um dos
16 elementos BabyBear de cada saída, recompõe os quatro bytes little-endian do
intent e exige igualdade com o commitment `H_NOTE` privado correspondente.
Assim, não há cópia separada dos slots de saída como entrada pública da AIR:
o vínculo usa os bytes que a própria AIR de `H_INTENT` já autenticou.

As checagens transparentes continuam dando erros claros para versão, ativo,
zero, overflow, desequilíbrio ou slot de saída incorreto antes do provador. O
recibo retornado retém somente o ID da declaração `NXPU`; internamente, os dois
commitments de entrada ficam vivos apenas até a ponte imediata para posse.

No preflight completo, os dois commitments de entrada produzidos por esta
relação não saem do crate: eles são passados diretamente às duas provas de
posse/Merkle. Cada uma agora torna esse commitment um input público **local de
pesquisa** e exige que seja igual ao `H_NOTE` calculado dentro da própria prova
de posse. Assim, a conservação e a posse não podem usar aberturas de entrada
diferentes na mesma execução. Essa ponte ainda é operacional entre duas provas
independentes, não agregação nem uma AIR única.

## Como reproduzir

```powershell
cargo test -p noxis-stark-experiment --release --locked value_conservation::tests::conservation_stark_binds_four_private_notes_and_private_balanced_values -- --exact
```

Em 2026-08-30, na máquina de desenvolvimento de referência, essa prova e sua
verificação terminaram em **8,29 segundos** em release. A medição é evidência
de pesquisa local; não é meta de desempenho nem parâmetro de protocolo.

Também existem testes que rejeitam antes do provador valores desequilibrados,
entrada zero, ativo errado ou commitment de saída incorreto, além de testes
adversariais que alteram bytes de valor/ativo no traço ou um slot público e
observam a rejeição das restrições.

## Limites que permanecem

Esta relação não liga suas duas notas de entrada à prova de posse/Merkle ou aos
nullifiers na mesma AIR. O preflight passa os commitments de entrada às provas
de posse locais para impedir troca de witness entre as duas relações, mas ainda
não há agregação. Ela agora liga as saídas dentro da mesma AIR ao `H_INTENT`,
mas ainda não cobre envelopes `NXRE`, inserção na árvore ou estado `NXSM`.
Não há formato de prova Noxis, verificador selecionado, admissão de consenso ou
ativação de privacidade.

O próximo trabalho correto é acrescentar ao mesmo vínculo as duas relações de
posse/Merkle e os nullifiers, sem publicar commitments de entrada na declaração
final; então incluir o envelope.
