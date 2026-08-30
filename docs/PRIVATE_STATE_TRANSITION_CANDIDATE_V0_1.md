# Transição local de estado privado 2×2 — candidata v0.1

## O que é executável

`CandidatePrivateStateTransitionV2::apply` aplica, apenas em memória, uma
`PrivateTransferIntentV2` canônica ao estado privado candidato. Ela recebe:

- a âncora prévia `NXPS v2`;
- o snapshot canônico prévio de commitments e nullifiers gastos;
- a árvore esparsa `NXSM` prévia;
- a intenção 2×2; e
- a referência Poseidon2 P24 congelada.

Ela não aceita raiz posterior, índice de folha, lista de gastos ou snapshot
posterior do chamador. Em vez disso, reconstrói a âncora prévia, confere que a
intenção se liga a ela, verifica que ambos nullifiers ainda estão ausentes,
marca ambos na cópia de `NXSM`, acrescenta os dois commitments de saída na
ordem canônica da intenção e deriva um snapshot e `NXPS v2` posteriores novos.

O resultado contém a nova raiz de notas, `next_leaf_index`, raiz e contagem
`NXSM`, além de um novo `StateId` candidato. A revalidação refaz toda a
operação e rejeita qualquer estado posterior alterado.

## Garantias locais

- a âncora de entrada precisa ser reconstruível exatamente a partir de snapshot
  e árvore fornecidos;
- o `pre_state_id`, a raiz de notas, gênese, contexto e parâmetros da intenção
  precisam coincidir com a âncora;
- nullifier repetido/já gasto é rejeitado antes de qualquer output ser aceito;
- outputs são anexados, não reordenados, e duplicar commitment existente falha;
- a árvore `NXSM` e a lista canônica de nullifiers gastos do snapshot posterior
  são derivadas da mesma operação.

## Limites deliberados

Esta é uma transição **transparente, local e de pesquisa**. Ela não aceita uma
prova STARK, não demonstra que o remetente possuía as entradas, não prova
conservação de valor, não persiste estado, não armazena os envelopes/ciphertexts
das novas notas, não resolve concorrência e não autoriza ledger, consenso ou
rede. Um nó não deve chamá-la como regra de liquidação.

O estado de commitments precisa da transição para tornar a próxima âncora
derivável; o armazenamento dos envelopes de destinatário será uma camada
separada, com política de disponibilidade e privacidade própria. Não é correto
inventar esse armazenamento implicitamente dentro da árvore Merkle.

## Verificação

```powershell
cargo test -p noxis-private-state transition_v2::tests::atomically_derives_the_post_note_and_nullifier_state_from_one_intent --locked
cargo test -p noxis-private-state transition_v2::tests::rejects_an_already_spent_intent_nullifier_before_appending_outputs --locked
cargo test -p noxis-private-state transition_v2::tests::rejects_an_output_commitment_that_already_exists_in_the_pre_state --locked
```

Os testes cobrem aplicação, derivação de nova âncora, revalidação, tentativa de
gasto repetido e tentativa de reintroduzir uma nota já existente.

## Próximo passo

Fazer uma prova selecionada autorizar esta mutação — ligando a posse das
entradas, os outputs, conservação de valor e a transição `NXSM` ao mesmo estado
antes/depois. Só depois de tal prova e de persistência revisada uma versão
equivalente poderá ser considerada pelo nó.
