# Noxis Protocol — Validation Context Specification v0.1

## Objetivo

`ValidationContext` identifica publicamente os componentes que decidem se uma
transação é aceitável para uma gênese. A codificação v1 é fixa e canônica:

```text
crypto_suite.version (u16 BE)
crypto_suite.hash (u8)
crypto_suite.transport_kem (u8)
crypto_suite.identity_signature (u8)
crypto_suite.proof_system (u8)
ProofVerifierId (32 bytes)
MintPolicyId (32 bytes)
```

`ValidationContextId` é `SHA-256("NOXIS/VALIDATION-CONTEXT/V1\0" ||
contexto_canônico)`. `GenesisId` inclui os bytes completos do contexto; por
isso o `StateId` e o histórico `NXRF` também se tornam incompatíveis quando o
contexto muda.

## Regras operacionais entregues

`ProofVerifier` e `MintPolicy` devem declarar, respectivamente,
`ProofVerifierId` e `MintPolicyId`. Na abertura, `PersistentLedger` verifica
o contexto fornecido, os IDs dos componentes em execução e o `ChainAnchor`
antes de abrir, varrer ou truncar o log. Uma divergência deixa o nó fechado e
não cria nem altera o histórico.

O manifesto `NXMF` v7 contém o contexto completo, a configuração de consenso
e a identidade CometBFT opcional; ele recalcula tanto o
`ValidationContextId` quanto o `GenesisId`; versões anteriores são rejeitadas.

Cada campo da `CryptoSuite` também tem um papel fixo: somente hashes podem
ocupar `hash`, somente algoritmos de transporte podem ocupar `transport_kem`,
somente algoritmos de assinatura podem ocupar `identity_signature` e somente o
identificador de sistema de prova pode ocupar `proof_system`. Versão zero e
combinações semanticamente inválidas são recusadas na gênese, no manifesto e
no codec de transação.

Toda transação persistida deve declarar exatamente a mesma `CryptoSuite` do
contexto de validação ligado à gênese. `PersistentLedger` confere isso antes de
validar ou gravar uma nova transação e também durante cada replay de `NXRF`.
Assim, o próprio histórico não pode trocar silenciosamente a descrição
criptográfica do deployment.

Para emissão, o `MintPolicy` recebe um `MintStatement` completo: identidade da
gênese, contexto de validação, intenção, `StateId` anterior, raiz Merkle,
suprimento anterior, ativo, quantidade e commitments de saída. A autorização
opaca é passada separadamente. Uma política concreta deve autenticar exatamente
esse statement; aceitar uma autorização que não vincule esses campos abriria
espaço para reutilizar uma prova de reserva, ponte ou assinatura em outra
emissão.

## O que os IDs devem representar

Um `ProofVerifierId` futuro deve comprometer a versão do statement/circuito,
parâmetros públicos, verifying key, construção da árvore e regras de raiz. Um
`MintPolicyId` futuro deve comprometer todas as regras públicas de emissão por
ativo, chaves públicas, limiares, rotação/revogação e versões. Eles nunca devem
incluir segredos, paths locais, endpoints ou credenciais.

O valor atual para `DenyAllMints` é explícito. Não existe backend de prova nem
política de emissão transferível habilitada nesta versão.

## Limites

Essa verificação detecta uma troca declarada de configuração; ela não atesta o
binário, não transforma um componente defeituoso em seguro e não substitui
revisão criptográfica. O `TransferStatement` entregue ao `ProofVerifier` agora
carrega explicitamente `GenesisId`, `ValidationContextId`, o
`TransactionIntentId` do registro e o `StateId` pré-transição. Um backend de
prova concreto deve incluí-los em seus inputs públicos e provar que a prova
pertence exatamente a esses valores. O identificador de intenção isolado ainda não contém gênese nem a
raiz de estado; ele não deve ser usado sozinho como identidade de rede antes da
evolução versionada do formato de transação.
