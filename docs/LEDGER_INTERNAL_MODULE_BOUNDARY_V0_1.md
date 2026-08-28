# Fronteiras internas do ledger v0.1

O crate `noxis-ledger` preserva sua API pública, serialização externa e a
fórmula de `StateId`, mas agora divide explicitamente responsabilidades que
antes estavam concentradas em `lib.rs`.

| Módulo | Responsabilidade |
| --- | --- |
| `model` | Transações, operações, contexto e fronteiras de política. Representa um pedido; não muda estado. |
| `state` | Representação em memória, consultas, snapshot canônico, Merkle root e `StateId`. |
| `invariants` | Canonicalização de snapshots e todas as regras que devem ser verdadeiras antes de uma alteração. Produz um plano interno validado. |
| `mutation` | Registro de ativos, restauração e aplicação do plano já validado. |
| `error` | Erros públicos estáveis nas fronteiras de leitura e transição. |

`LedgerState::apply` agora tem uma divisão audível: primeiro chama
`prepare_transition`, que verifica contexto, unicidade, capacidade, política e
prova; somente então `commit_transition` altera commitments, nullifiers,
supply e identificadores de transação. O formato de `Transaction`,
`LedgerSnapshot`, `StateId` e os erros públicos não foi alterado.

Antes de publicar novos commitments, a mutação monta uma nova árvore Merkle em
memória e a substitui de uma vez. Isso torna explícito que uma falha futura da
implementação Merkle não deve deixar metade de uma saída aplicada.

Este rearranjo é interno ao ledger público SHA-256 v1. Ele não integra os
componentes privados candidatos e não altera consenso, armazenamento ou codecs.
