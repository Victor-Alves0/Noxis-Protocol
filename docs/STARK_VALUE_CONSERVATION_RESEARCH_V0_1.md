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

Os valores, destinatários, `rho`, `rcm` e o restante das pré-imagens ficam no
traço privado. A prova também range-checka todos os bytes das quatro notas com
decomposição em oito bits e recompõe o packing `BytePack3LE` usado por
`H_NOTE`; não confia em uma representação alternativa de valor.

## Interface pública de pesquisa

O experimento recebe publicamente quatro commitments P24 e o `asset_id`. Isso
é necessário para testar a composição entre as quatro aberturas e a aritmética
em um único AIR, mas **não é uma interface de transação Noxis**: revelar os
commitments de entrada prejudicaria a privacidade. A API é apenas in-memory,
verifica a prova na mesma execução e descarta tanto a prova opaca quanto esse
resultado de pesquisa.

`run_candidate_value_conservation_preflight` usa essa relação depois de suas
checagens transparentes de formato. Essas checagens dão erros claros para
versão, ativo, zero, overflow ou desequilíbrio; a STARK em seguida confirma as
mesmas regras vinculadas aos quatro `H_NOTE` exatos. O recibo retornado retém
somente o ID da declaração `NXPU`, nunca valores, notas ou commitments.

## Como reproduzir

```powershell
cargo test -p noxis-stark-experiment --release --locked value_conservation::tests::conservation_stark_binds_four_private_notes_and_private_balanced_values -- --exact
```

Em 2026-08-30, na máquina de desenvolvimento de referência, essa prova e sua
verificação terminaram em **8,29 segundos** em release. A medição é evidência
de pesquisa local; não é meta de desempenho nem parâmetro de protocolo.

Também existem testes que rejeitam antes do provador valores desequilibrados,
entrada zero e ativo errado, e um teste adversarial que altera bytes de valor ou
ativo no traço já construído e observa a rejeição das restrições.

## Limites que permanecem

Esta relação não liga suas duas notas de entrada à prova de posse/Merkle ou aos
nullifiers, nem seus outputs aos slots `NXPU`, envelopes `NXRE`, inserção na
árvore ou estado `NXSM`. O preflight superior usa a mesma witness local para
essas relações, mas isso é composição operacional sequencial, não uma prova
agregada nem uma AIR completa. Não há formato de prova Noxis, verificador
selecionado, admissão de consenso ou ativação de privacidade.

O próximo trabalho correto é compartilhar a witness e os vínculos públicos com
as relações de posse, nullifier, outputs e envelope dentro de uma composição
auditável, sem publicar commitments de entrada na declaração final.
