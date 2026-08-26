# Identidade canônica v0.1

## O problema corrigido

O campo legado `Transaction.id` aparece dentro dos bytes de uma transação.
Logo, ele não pode ser definido como `hash(bytes_da_transação)`: o hash teria
de conter a si mesmo. Esta versão não tenta esconder esse problema.

## Dois identificadores distintos

`TransactionId` permanece um identificador legado de armazenamento. O novo
`TransactionIntentId` identifica o significado econômico público da operação:

```text
SHA-256(
  "NOXIS/TX-INTENT-ID/V1\0" ||
  tamanho_u32_be(intent) ||
  intent_canônica
)
```

A intenção inclui versão, suite, operação, ativo, nullifiers, commitments e,
para mint, valor. Ela exclui o ID legado, bytes de prova e autorização opaca.
Isso permite que uma prova ou assinatura futura se vincule ao ID sem formar um
ciclo. Nesta fase ela ainda não inclui gênese nem anchor explícito; portanto
não é identificador de rede nem proteção contra replay entre redes.

## Identidade de gênese e estado entregue

`GenesisConfig` agora calcula um `GenesisId` canônico (formato 5) com SHA-256 e domínio
`NOXIS/GENESIS-ID/V1\0`. A codificação de identidade está na versão 5 porque
ela inclui o `ValidationContext` canônico e a `ConsensusConfig` canônica, cujo
formato `NXCG` v3 compromete também o limite total de bytes por bloco. O
contexto inclui suite
criptográfica, `ProofVerifierId` e `MintPolicyId`. Ela ainda compromete a
versão do conjunto de regras, profundidade da árvore e o registro de ativos
ordenado por `AssetId`, contexto de validação e configuração canônica de
consenso. Caminho do arquivo, conteúdo do manifesto, máquina,
lock e segredos não fazem parte do cálculo.

O `StateId` usa o domínio `NOXIS/STATE/V2\0` e inclui esse `GenesisId` antes
dos componentes canônicos do ledger. Logo, dois deployments com o mesmo estado
mutável, mas gêneses diferentes, têm IDs de estado incompatíveis. `ChainAnchor`
carrega `GenesisId`, `ValidationContextId`, os IDs de verificador e política,
e o `StateId` do estado gênese; tudo é revalidado antes de o armazenamento
abrir ou truncar um log. O manifesto `NXMF` v6 guarda o contexto completo, a
configuração de consenso canônica, a identidade CometBFT opcional e o
`GenesisId`, recalculando ambos ao abrir; versões anteriores são rejeitadas
explicitamente.

## Próxima evolução obrigatória

Antes de consenso ou valor transferível, `TransactionIntent` deve incluir:

- `GenesisId` calculado a partir de regras de aceitação canônicas, sem paths,
  segredos ou configuração local;
- `StateAnchor` explícito, incluindo especificação e profundidade da árvore;
- limites e versão de protocolo; e
- o ID deve ser revalidado em toda decodificação, em vez de ser confiado de um
  campo transmitido.

Enquanto essa evolução não chega, `TransferStatement` e `MintStatement` já
recebem `GenesisId`, `ValidationContextId`, `TransactionIntentId` e o `StateId`
pré-transição da camada de armazenamento. Isso vincula a prova/autorização ao
deployment e ao estado corretos, mas não transforma o intent isolado em um ID
de rede. Também será necessário substituir os identificadores legados de
transação no estado por intents aceitos e versionar a evolução canônica do
intent antes da rede de consenso.
