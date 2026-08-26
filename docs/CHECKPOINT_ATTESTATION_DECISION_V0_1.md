# Decisão de atestação de checkpoints v0.1

## Estado

**Decisão de governança obrigatória; recuperação acelerada permanece
desabilitada.** O `NXCP` atual é uma cópia canônica do estado, publicada de
forma segura e comparada ao replay integral. Ele não é certificado de
finalidade, não autentica um histórico e não pode autorizar o nó a pular o
prefixo `NXRF`.

## Por que uma assinatura isolada não basta

Uma assinatura pode provar que uma chave fez uma afirmação. Ela não responde,
por si só, a perguntas essenciais: quem tem permissão de assinar, quantas
assinaturas são necessárias, como membros entram ou saem, o que acontece em
caso de fork e qual é o maior checkpoint seguro contra rollback.

Sem essas regras, duas assinaturas válidas podem afirmar estados incompatíveis
ou um checkpoint antigo pode substituir silenciosamente um mais novo. Isso
seria uma escolha de disponibilidade e governança, não um detalhe de formato.

## Conteúdo mínimo de um futuro certificado

O certificado deverá assinar um transcript canônico e versionado, com domínio
próprio, que inclua pelo menos:

```text
versão do certificado
GenesisId
ValidationContextId
sequência do checkpoint
StateId
RecordHash terminal
hash do NXCP canônico
época/finalidade, quando houver consenso
```

Caminhos locais, nomes de arquivos, segredos, endpoints e credenciais nunca
entram no transcript. A assinatura deve cobrir um digest canônico separado;
ela não deve depender do nome de um arquivo ou de uma representação em memória.

## Decisões que não podem ser presumidas

1. **Autoridade:** conjunto de validadores definido por consenso (decisão
   registrada em `CONSENSUS_DECISION_V0_1.md`); faltam algoritmo, conjunto
   inicial, quórum, rotação e governança.
2. **Algoritmo:** Ed25519, ML-DSA-65 revisado, ou esquema híbrido, incluindo
   plano de migração.
3. **Configuração de autoridades:** fixa na gênese, atualizada por chave raiz
   ou governada por consenso; com rotação, revogação e resposta a incidente.
4. **Semântica:** atestado operacional de um operador ou certificado de
   finalização que efetivamente autoriza pular histórico.
5. **Rollback:** regra para maior sequência/época vista, recuperação após perda
   de dados e equilíbrio explícito entre disponibilidade e segurança.

`CryptoSuite.identity_signature` atual é somente metadado e não implementa
nenhuma dessas decisões. O tag `MlDsa65` não pode ser tratado como uma
assinatura ativa ou uma garantia pós-quântica.

## Condição para habilitar recuperação acelerada

Antes de alterar `PersistentLedger` para começar de um checkpoint, o projeto
deve ter: formato de certificado, verificador criptográfico concreto e
revisado, identidade pública das autoridades, regra de quórum/finalidade,
proteção contra rollback e testes de fork, revogação e indisponibilidade.
