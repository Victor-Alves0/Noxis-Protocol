# Vínculo STARK `H_NOTE` ↔ ativo público — pesquisa v0.1

## Garantia executável

`prove_and_verify_p24_note_with_asset` prova a relação P24 `H_NOTE` sobre os
178 bytes privados de uma nota e torna públicos:

1. o commitment de 16 elementos resultante; e
2. os 32 bytes do `asset_id` canônico.

A AIR não aceita o ativo por confiança do prover. Ela range-checka e recompõe
toda a pré-imagem privada como antes e impõe, dentro das restrições, que os
bytes privados nos offsets **2..34** sejam exatamente os 32 valores públicos
do ativo. Esses offsets são o campo `asset_id` definido no formato de abertura
de nota v2.

Uma mutação de qualquer byte público do ativo produz restrições insatisfeitas.
Uma nota que contenha ativo privado diferente também não gera prova verificável
para o ativo declarado.

## Uso no preflight 2×2

O preflight de saídas e o preflight completo de transferência agora usam essa
relação para cada saída. Portanto, cada commitment de saída é ligado tanto à
pré-imagem privada quanto ao único `asset_id` público de `PrivateTransferIntentV2`.
Isso eliminou uma antiga incoerência de fixture: notas artificiais que hashavam
corretamente, mas carregavam bytes de ativo diferentes da intenção, agora são
recusadas pela prova.

## Limites preservados

Esta relação não revela ou valida o valor, destinatário, `rho` ou `rcm`; também
não prova conservação, cifragem, posse, inclusão, transição de estado ou
anonimato. O `asset_id` torna-se público porque a intenção multiativo já o
declara publicamente. Uma transferência privada completa ainda precisa de AIR
única e dos vínculos restantes.

## Verificação

```powershell
cargo test -p noxis-stark-experiment note::tests::note_stark_binds_the_public_asset_to_its_private_preimage_bytes --release --locked
cargo test -p noxis-stark-experiment note::tests::note_with_asset_air_rejects_a_different_public_asset --release --locked
```

O primeiro teste gera e verifica a prova positiva; o segundo altera os bytes
públicos e confirma que a AIR rejeita as restrições.

## Próximo passo

Levar `value` para uma representação aritmética canônica e vinculá-lo às duas
entradas e duas saídas. Essa etapa exige desenho cuidadoso de decomposição de
128 bits, detecção de overflow e padding; não deve ser substituída por uma
comparação de host fora da AIR.
