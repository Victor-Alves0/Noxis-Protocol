# Declaração pública unificada de transferência privada — candidata v0.1 (`NXPU`)

## Propósito

`CandidatePrivateTransferProofPublicStatementV1` elimina a fronteira implícita
entre a relação de notas e a relação de nullifiers. Ele cria uma única
declaração pública local para um futuro provador receber, ligando:

1. a âncora tipada `NXPS v2`;
2. a intenção `PrivateTransferIntentV2` de 640 bytes;
3. a moldura pública de notas, com `BytePack3LE(intent)` e `H_INTENT`; e
4. a transição `NXNT v1` antes/depois da árvore `NXSM`.

É uma candidata local e revalidável. Não é uma AIR, STARK, chave verificadora,
prova, codec de rede ou autorização de liquidação.

## Vínculos obrigatórios

A construção e a revalidação recusam qualquer combinação em que:

- a intenção não coincida com gênese, contexto, parâmetros de notas, raiz de
  notas e `StateId` de `NXPS v2`;
- o `H_INTENT` rederivado da moldura de notas não seja o mesmo de `NXNT`;
- `pre_state_id` ou os dois nullifiers da intenção não sejam iguais aos de
  `NXNT`;
- o ID da candidata `NXSM`, sua raiz prévia ou sua contagem prévia não sejam
  os mesmos de `NXPS v2` e `NXNT`; ou
- a árvore prévia fornecida não possa reconstruir toda a transição `NXNT`.

Portanto, um futuro backend não recebe duas relações que apenas “devem” ser
compatíveis. Ele recebe uma declaração cuja compatibilidade já é uma
invariante executável.

## Frame canônico

`NXPU v1` usa 1.440 bytes nesta ordem:

```text
magic NXPU | version:u16be=1 | reserved[2]
| state_id[32] | NXPS-v2-anchor[288]
| private-transfer-intent[640] | H_INTENT[64] | NXNT-v1-transition[408]
```

Seu identificador é SHA-256 com domínio
`NOXIS/PRIVATE-TRANSFER-PROOF-PUBLIC-STATEMENT-ID/V1\0`. Esse identificador
não é `ProofVerifierId`, `TransactionIntentId`, `StateId` do ledger v1 nem
seleção de parâmetros; só identifica exatamente esta declaração candidata.

O frame conserva deliberadamente campos redundantes entre seus componentes.
Essa redundância deixa os vínculos auditáveis e dá à futura AIR uma lista
explícita de igualdades para impor, em vez de confiar em uma montagem externa.

## O que ainda falta

- converter as relações em colunas, traços e restrições de uma AIR executável;
- definir a raiz posterior de notas, a âncora posterior e a inserção atômica
  das duas saídas;
- selecionar backend STARK, FRI, transcript, parâmetros e verificador;
- criar formato de prova e de transação v2 com limites de recursos;
- integrar somente depois de revisão independente, nova gênese e política de
  ativação explícita.

`NXPD v1` continua válido apenas para sua moldura original de 230 elementos.
Ele não deve ser interpretado como compromisso de `NXPU`; um manifesto futuro
precisará versionar essa interface adicional antes de escolher qualquer
backend.
