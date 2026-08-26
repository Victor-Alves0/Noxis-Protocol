# Noxis Protocol — Checkpoint Specification v0.1

## Estado da implementação

O crate `noxis-checkpoint` implementa a codificação canônica `NXCP` v1 e
`noxis-storage` a publica em `checkpoints/` sem sobrescrever arquivos
existentes. O arquivo é gravado sob um nome temporário, sincronizado, publicado
por link atômico no mesmo diretório e reaberto/decodificado antes do sucesso.
O nó compara candidatos válidos com o replay integral de `NXRF/NXRC`; um
arquivo isolado nunca acelera a abertura nesta versão.

## Snapshot canônico

Um snapshot contém somente estado lógico do ledger:

```text
tree_depth
assets, em ordem estrita de AssetId
commitments, na ordem exata de inserção/Merkle
spent_nullifiers, em ordem estrita
issued_supply, em ordem estrita de AssetId
accepted_transactions, em ordem estrita
```

O importador revalida ticker, profundidade, capacidade da árvore, unicidade de
commitments, ordem/duplicidade de conjuntos e se cada supply se refere a um
ativo conhecido. Ele reconstrói uma nova árvore por `append`; não aceita uma
raiz declarada, mapa, conjunto ou ponteiro de memória como autoridade.

Com um `GenesisId` conhecido, o estado restaurado deve produzir exatamente o
`StateId` calculado no checkpoint. A quantidade de transações aceitas também
deve ser igual à sequência do checkpoint. Caso contrário, o checkpoint não é
elegível.

## Formato entregue

Todos os inteiros são big-endian e não há campos opcionais ou bytes
reservados:

```text
"NXCP" | checkpoint_version:u16 | snapshot_version:u16 |
GenesisId:32 | ValidationContextId:32 | sequence:u64 | StateId:32 |
terminal_RecordHash:32 | snapshot_length:u32 | snapshot_hash:32 |
snapshot_bytes | checkpoint_hash:32
```

`snapshot_hash` é SHA-256 com o domínio
`NOXIS/CHECKPOINT/V1/SNAPSHOT\0`; `checkpoint_hash` usa
`NOXIS/CHECKPOINT/V1\0` e cobre todos os bytes anteriores. O snapshot contém
profundidade, ativos, commitments, nullifiers, supply e IDs de transação nas
ordens canônicas descritas acima. O decoder limita o snapshot a 128 MiB, ativos
a 4.096 e coleções de identificadores a 1.048.576 entradas antes de alocar.

Checkpoints na gênese são recusados: sem uma transição terminal, não há um
`RecordHash` ao qual vinculá-los. O nome do arquivo nunca é autoridade.

Um checkpoint é marcado como verificado somente quando, no mesmo ponto do
replay integral, coincidem seu `GenesisId`, `ValidationContextId`, sequência,
`StateId`, `RecordHash` terminal e snapshot canônico completo. Candidatos
malformados, incompletos, grandes demais, com nome desconhecido ou contexto
divergente são ignorados; corrupção no `NXRF` continua uma falha fechada. O log
não será compactado nesta fase.

## Limite de segurança deliberado

O hash de um checkpoint detecta alteração acidental; ele não é assinatura nem
finalidade. Como `NXRC` ainda não é uma cadeia autenticada por consenso, um
checkpoint não prova sozinho que o prefixo do log foi validado corretamente.
Assim, a recuperação atual faz a validação estrita do histórico antes de
restaurar e comparar o snapshot. Pular esse prefixo exigirá uma âncora
autenticada, atestado assinado ou consenso, todos fora do escopo atual.

## Pré-condição de contexto entregue

A gênese agora vincula um `ValidationContextId`, o `ProofVerifierId` e o
`MintPolicyId` públicos. A abertura compara os IDs dos componentes em execução
antes de tocar no log. Os descritores concretos de circuito e política ainda
precisam ser implementados quando existir um backend de prova/issuance real;
o contrato e a proteção contra troca declarada já existem.

## Falhas

Arquivos de checkpoint temporários, incompletos, desconhecidos ou inválidos
nunca poderão ser usados. Um checkpoint inválido poderá ser ignorado em favor
de outro mais antigo ou de replay completo, mas qualquer corrupção no histórico
`NXRF` continuará sendo falha fechada. Proteção contra um host que substitui
todo o log e todos os checkpoints exige âncora externa, backup ou consenso e
continua fora do escopo v0.1.
