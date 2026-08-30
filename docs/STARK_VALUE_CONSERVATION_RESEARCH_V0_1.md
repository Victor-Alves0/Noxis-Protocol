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
6. na variante usada pelo preflight, os commitments `H_NOTE` das duas saídas
   são iguais aos dois slots públicos de saída fornecidos pela declaração
   `NXPU`.

Os valores, destinatários, `rho`, `rcm` e o restante das pré-imagens ficam no
traço privado. A prova também range-checka todos os bytes das quatro notas com
decomposição em oito bits e recompõe o packing `BytePack3LE` usado por
`H_NOTE`; não confia em uma representação alternativa de valor.

## Interface pública de pesquisa

O experimento recebe publicamente quatro commitments P24, o `asset_id` e, na
variante vinculada, a cópia dos dois commitments de saída esperados. O AIR
exige igualdade entre a cópia e os `H_NOTE` das saídas. Isso é necessário para
testar a composição entre as quatro aberturas, a aritmética e os slots em um
único AIR, mas **não é uma interface de transação Noxis**: revelar os
commitments de entrada prejudicaria a privacidade. A API é apenas in-memory,
verifica a prova na mesma execução e descarta tanto a prova opaca quanto esse
resultado de pesquisa.

`run_candidate_value_conservation_preflight` usa a variante vinculada depois
de suas checagens transparentes de formato. Ele extrai os dois slots esperados
da mesma `NXPU`; essas checagens dão erros claros para versão, ativo, zero,
overflow ou desequilíbrio, e a STARK em seguida confirma as mesmas regras
vinculadas aos quatro `H_NOTE` exatos e aos slots. O recibo retornado retém
somente o ID da declaração `NXPU`, nunca valores, notas ou commitments.

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
nullifiers. Ela liga as saídas aos slots passados pela `NXPU`, mas ainda não
prova dentro do mesmo AIR o `H_INTENT` que autentica a declaração, nem cobre
envelopes `NXRE`, inserção na árvore ou estado `NXSM`. O preflight superior usa
a mesma witness local para as relações restantes, mas isso é composição
operacional sequencial, não uma prova agregada nem uma AIR completa. Não há
formato de prova Noxis, verificador selecionado, admissão de consenso ou
ativação de privacidade.

O próximo trabalho correto é compartilhar a witness e os vínculos públicos com
`H_INTENT`, posse e nullifier dentro de uma composição auditável, sem publicar
commitments de entrada na declaração final; então incluir o envelope.
