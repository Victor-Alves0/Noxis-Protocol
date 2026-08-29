# Decisão de consenso v0.1

## Decisão registrada

**A rede Noxis será governada por consenso.** Um único operador não será a
fonte de verdade para ordenar transações nem para declarar estados finais.

Esta decisão muda o objetivo da camada de rede: nós validadores devem chegar à
mesma sequência de transições ou rejeitar a proposta. O repositório já contém
o ciclo ABCI v0.38, journal `NXCB`, dados BFT canônicos e uma CI que inicia um
processo CometBFT real contra o adaptador local. Isso **não** significa que já
exista uma rede BFT operacional, assinaturas/votos geridos pelo Noxis ou uma
alegação de finalidade para clientes. `NXRF` permanece histórico legado local;
em modo Comet, somente `NXCB` é autoridade de `Commit`.

## Direção de implementação adotada

Enquanto as escolhas operacionais são fechadas, a fundação usa o modelo de
**quórum BFT permissionado**: participantes identificados possuem peso de voto
e um bloco só pode ser finalizado com poder estritamente maior que dois terços.
Isso ainda não é uma alegação de tolerância a falhas concreta: a configuração
inicial precisa declarar quem pode ser bizantino e permanecer abaixo de um
terço do poder total. Algoritmo/engine, operação das chaves, entrada e saída de
validadores e governança ainda exigem decisão explícita.

Para a primeira integração, a direção escolhida é usar **CometBFT via ABCI
2.0**, mantendo o Noxis como máquina de estados em Rust e o consenso/P2P na
engine. Isto evita implementar um algoritmo BFT próprio. O runtime já possui
executor puro de blocos, persistência atômica via `NXCB` e adaptador TCP ABCI
loopback; o trabalho restante é transformá-los em evidência operacional
multi-validador e não presumir que a integração local equivale a uma rede.

## O que consenso deve garantir

Para um mesmo `GenesisId` e `ValidationContextId`, o protocolo futuro deve
garantir pelo menos:

1. **Segurança:** dois estados incompatíveis não podem ser finalizados na mesma
   altura/época sob o modelo de falhas declarado.
2. **Ordem determinística:** todos os validadores aplicam a mesma lista
   canônica de transações sobre o mesmo estado anterior.
3. **Finalidade verificável:** um cliente ou nó que recebe um certificado de
   finalidade consegue verificar quem votou, qual quórum foi atingido e qual
   estado foi finalizado, sem confiar no transportador da mensagem.
4. **Recuperação anti-rollback:** um nó não aceita silenciosamente uma cadeia
   ou checkpoint abaixo da maior altura/época finalizada que ele conhece.
5. **Evolução governada:** mudanças no conjunto de validadores, nas chaves ou
   nas regras são elas próprias finalizadas por uma regra explícita.

## Separação de responsabilidades

```text
cliente -> proposta de transação canônica
validador -> valida transição e participa do consenso
consenso -> ordena e finaliza uma proposta de estado
armazenamento local -> persiste/reproduz a decisão já ordenada
checkpoint -> acelera recuperação somente após certificado de finalidade
```

`noxis-ledger` continua sendo a máquina de estados determinística. Ele não deve
conhecer sockets, pares, líderes, votos ou chaves de nó. A futura camada de
consenso deve chamar a mesma transição que o nó local usa hoje e só então tornar
a decisão final.

## Transcript mínimo de uma proposta finalizável

Antes de assinar ou votar, uma implementação deve construir bytes canônicos,
versionados e separados por domínio contendo pelo menos:

```text
versão do protocolo de consenso
GenesisId
ValidationContextId
identidade/época do conjunto de validadores
altura e rodada/view
identificador do pai finalizado
StateId anterior
hash da lista canônica e ordenada de transações/registros
StateId resultante
RecordHash terminal ou hash de bloco equivalente
```

O certificado de finalidade deverá autenticar esse transcript, além de indicar
o conjunto de votantes e o quórum. Caminhos locais, endereços de rede,
credenciais, segredos e horários locais não podem entrar nesses bytes.

## Decisões ainda necessárias

"Consenso" por si só não escolhe o mecanismo de segurança. Antes de criar a
crate de rede/consenso, é necessário escolher explicitamente:

1. **Tipo de participação:** validadores permissionados identificados ou rede
   permissionless com mecanismo anti-Sybil econômico.
2. **Modelo de falha:** somente queda de nós (crash fault) ou nós maliciosos/
   bizantinos. Para liquidação multiativo, a referência recomendada é tolerar
   falhas bizantinas.
3. **Algoritmo e regra de quórum:** por exemplo, um BFT autenticado com limite
   de menos de um terço de poder bizantino; o algoritmo concreto não foi
   escolhido ainda.
4. **Identidade e chaves dos validadores:** algoritmo realmente implementado,
   rotação, revogação, armazenamento de chaves e migração criptográfica.
5. **Governança:** como o conjunto de validadores muda, quem propõe mudanças e
   como uma emergência é tratada sem permitir reescrita unilateral.
6. **Política de disponibilidade:** tempos de rodada, comportamento em
   partição, limites de fila, admissão e dados necessários para sincronização.

## Relação com checkpoints

`NXCP` permanece uma cópia local verificada por replay. Recuperação acelerada
só poderá começar de um checkpoint que carregue um certificado de finalidade
válido para sua altura, estado e registro terminal, e que respeite a regra
anti-rollback deste documento. A decisão de consenso substitui a hipótese de
operador único em `CHECKPOINT_ATTESTATION_DECISION_V0_1.md`, mas não remove os
requisitos de certificado, quórum e testes adversariais.

## Micro-entrega concluída: dados canônicos de consenso

`noxis-consensus` agora contém, sem I/O, os tipos canônicos para conjunto de
validadores ponderado, cabeçalho de bloco, compromisso ordenado de `RecordHash`
e certificado de finalidade. Ele rejeita tamanhos excessivos, dados não
canônicos, votos duplicados, validadores desconhecidos, quórum abaixo de mais
de dois terços e certificados destinados a outro bloco/configuração.

Um certificado somente vira `VerifiedFinality` depois de duas verificações:
estrutura/quórum e cada assinatura por um `FinalityVerifier` concreto. A crate
não inventa assinaturas ou uma máquina BFT; isso evita chamar dados locais ou
uma coleção de bytes de "finalidade" antes da integração com uma engine
auditada.

A configuração de consenso também passou a ser parte obrigatória de
`GenesisConfig` e do manifesto local `NXMF` v7. `GenesisId` inclui os bytes
canônicos dessa configuração; trocar chaves, pesos, orçamento de falha ou
limites produz outra identidade de rede e a abertura do diretório com uma
configuração diferente falha.

## Micro-entrega concluída: executor determinístico

`noxis-execution` executa, sem I/O, uma proposta já ordenada contra uma cópia
do estado confirmado. Ele rejeita altura inesperada, estado recuperado que não
pertence à âncora ativa, quantidade ou bytes excessivos, transação não
canônica, suíte criptográfica divergente e qualquer gasto duplo. Se uma única
transação falhar, o estado de entrada permanece intacto: não existe gravação
parcial nessa camada.

O pai do cabeçalho é sempre derivado do último bloco confirmado; não é aceito
como dado livre da proposta. Como a ABCI não fornece uma rodada Comet canônica
ao aplicativo, a primeira versão fixa `epoch` e `round` do cabeçalho Noxis em
zero. Uma versão futura somente poderá preenchê-los a partir de metadados
explicitamente comprováveis.

O resultado inclui `AppHash`, uma impressão digital canônica da posição da
aplicação após o bloco — inclusive em blocos vazios. Ela vincula domínio da
rede, configuração de consenso, altura, `BlockId`, sequência NXRC, registro
terminal opcional e `StateId` resultante. O adaptador ABCI já retorna esses
bytes à engine pelo mapeamento de alturas documentado. Esse vínculo não é, por
si só, uma prova de finalidade remota nem uma alegação de rede BFT operacional.

## Micro-entrega concluída: núcleo do ciclo ABCI

`noxis-comet-abci` implementa o ciclo de aplicação e seu transporte TCP
loopback: o
mapeamento explícito entre alturas Comet e Noxis, `Info`, validação de
identidade em `InitChain`, admissão local `CheckTx`, seleção estável em
`PrepareProposal`, reexecução em `ProcessProposal`, finalização volátil em
`FinalizeBlock` e persistência exclusiva em `Commit`.

Em termos simples: experimentar ou votar numa proposta não grava nada. O
bloco só se torna parte da história local quando a engine chama `Commit`, e
então ele é gravado como um `NXCB` completo. O mempool usa uma cópia descartável
do estado para recusar localmente dois gastos pendentes do mesmo nullifier.
Após uma queda, somente a ponta já confirmada no jornal é anunciada por
`Info`; o candidato finalizado que ainda não recebeu `Commit` é descartado.

O adaptador agora abre um socket TCP local para o protocolo ABCI v0.38. Ele lê
frames protobuf com tamanho limitado e varints canônicos, aceita as chamadas
necessárias de `Info`, `InitChain`, `CheckTx`, propostas, `FinalizeBlock` e
`Commit`, e devolve erros de framing como exceções ABCI. Conexões simultâneas
da engine são serializadas no mesmo núcleo de estado. `Query` continua
indisponível e state-sync é recusado. O adaptador aceita a representação
protobuf canônica de campos vazios (por exemplo, `Echo("")`) e limita cada
frame a 80 MiB. No `InitChain`, ele recusa `BlockParams.max_bytes` fora de
`1..=64 MiB`, de modo que a engine não possa configurar propostas maiores que
a capacidade de transporte e memória assumida pelo nó. Extensões de voto são
aceitas como bytes opacos para preservar a disponibilidade quando a opção da
engine estiver habilitada, mas ainda não participam da execução, do `AppHash`
nem de uma política Noxis.

O código é validado em CI contra um binário CometBFT v0.38.17 fixado por
hash: o cenário local cobre handshake, bloco vazio/`Commit`, `AppHash` e
reinício contra o mesmo journal. Ele ainda não implementa P2P, chaves privadas
de validador, prova de finalidade para clientes nem uma rede com vários nós.
Portanto não constitui rede BFT funcional nem prova de finalidade. O próximo
passo é cenário adversarial multi-validador, não apenas repetir o handshake.

## Micro-entrega concluída: âncora Comet e validadores no histórico

A identidade CometBFT agora é um dado canônico opcional do genesis: `chain_id`,
altura inicial, versão de compatibilidade e SHA-256 do documento canônico de
parâmetros. A primeira integração fixa explicitamente CometBFT v0.38 e aceita
somente a conversão revisada de chaves Ed25519 cruas de 32 bytes, poder positivo
e limite total de poder da engine. A conversão deriva o endereço Comet e o hash
do conjunto com a serialização protobuf e Merkle especificadas pela própria
engine; ela foi conferida contra CometBFT v0.38.17.

Quando o nó é configurado para CometBFT, a identidade e o hash do conjunto
mapeado entram no `GenesisId` (formato 5) e no manifesto `NXMF` v7. Uma âncora
de consenso usa o ID conjunto de rede e validadores, não apenas o nome da rede.

Cada `NXCB` v2 transporta a identidade da rede, altura da decisão, hash do
bloco Comet e hash do próximo conjunto de validadores. O executor valida o
mapeamento de altura e inclui esses campos no `AppHash`; durante a recuperação
ele reexecuta e compara também esse contexto. Assim, a mesma lista de
transações não pode ser reutilizada como pertencente a outra decisão Comet sem
ser detectada.

O núcleo ABCI agora recebe uma estrutura de `InitChain` com `chain_id`, altura,
compromisso dos parâmetros e lista mapeada de validadores; qualquer divergência
é rejeitada antes do primeiro bloco. O transporte TCP v0.38 constrói essa
estrutura após decodificar o protobuf e calcula o SHA-256 dos bytes de
`ConsensusParams` recebidos. A ligação com CometBFT v0.38.17 e o cenário ponta
a ponta local já são executados em CI. Eles continuam insuficientes para
declarar uma rede BFT operacional sem os cenários multi-validador, de partição
e de operação de chaves descritos acima.
