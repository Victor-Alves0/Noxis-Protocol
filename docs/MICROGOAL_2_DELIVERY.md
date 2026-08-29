# Micro-goal 2 — Estado verificável e recuperação

> Historical delivery record. Later milestones added canonical `NXCP`
> artifacts, cooperative writer exclusion and the authoritative `NXCB` block
> journal; the limits below describe this micro-goal at the time it was
> completed.

## O que foi entregue

- `noxis-merkle`: árvore binária de profundidade fixa para commitments, com raiz, prova de inclusão e verificação.
- `noxis-ledger`: a raiz Merkle agora é o `StateAnchor` entregue ao verificador de transferências. A árvore recebe commitments somente depois da validação do ledger.
- `noxis-storage`: log append-only de transações canônicas, com frame limitado, checksum de corrupção acidental e sincronização de escrita.
- `PersistentLedger`: coordena validar → gravar em disco → publicar estado. Ao reiniciar, reproduz as transações e conserva nullifiers gastos.
- Recuperação explícita de uma cauda final claramente interrompida. O modo estrito preserva o arquivo e falha fechado; o modo de recuperação remove somente um prefixo plausível de frame incompleto e sincroniza o novo tamanho antes de aceitar escritas.

## O que isso significa

O sistema passa a ter uma memória verificável: cada nota nova muda uma raiz de estado, e uma nota gasta continua marcada como gasta após o processo reiniciar. Isso é a base necessária para provar, futuramente, que uma nota pertence ao estado sem revelar qual nota é.

## Limites conhecidos

- A árvore usa SHA-256 com separação de domínio. Ela é correta como estrutura de commitments, mas não é o hash Poseidon que o circuito ZK exigirá.
- O log ainda não encadeia `previous_state_id`/`resulting_state_id`, não possui checkpoints nem coordenação entre processos. Por isso não declara conformidade completa com [Durability Specification v0.1](DURABILITY_SPEC_V0_1.md).
- CRC-32 detecta corrupção acidental, não autentica um operador malicioso.
- Não há consenso, rede ou valor transferível.

## Critério para a próxima entrega

A próxima etapa deve oferecer um serviço de nó local que use `PersistentLedger`, exponha operações e consultas em uma API autenticada localmente. Antes de rede distribuída, esse serviço precisa de configuração de gênese, ciclo de vida, testes de integração e observabilidade.
