# Dados canônicos de consenso v0.1

## Finalidade deste módulo

`noxis-consensus` descreve os bytes e as verificações locais usados pela
integração CometBFT e que qualquer engine BFT deve usar para decidir blocos
Noxis. A crate não abre portas de rede, não guarda chaves privadas e não
escolhe líderes. Essa separação permite testar a parte mais sensível — o que
exatamente foi votado — sem misturá-la com sockets ou armazenamento.

## Configuração e validadores

Uma `ConsensusConfig` contém:

1. versão do protocolo de consenso;
2. limite positivo de registros por bloco;
3. `maximum_block_transaction_bytes`: limite positivo do total de bytes
   canônicos das transações de um bloco;
4. máximo poder bizantino declarado, que deve permanecer estritamente abaixo
   de um terço do poder total;
5. `ValidatorSet` com entradas ordenadas de `ValidatorId`, poder de voto
   estritamente positivo, identificador de esquema de assinatura e chave
   pública de verificação.

O conjunto é ordenado por `ValidatorId`, não admite duplicatas, limita-se a
10.000 membros e calcula seu `ValidatorSetId` por SHA-256 com separação de
domínio. `ConsensusConfigId` compromete a configuração inteira, inclusive os
pesos. O quórum é estritamente maior que dois terços do poder total; ele é
calculado sem multiplicação que possa causar overflow.

As chaves e o identificador de esquema fazem parte do `ValidatorSetId`; assim,
dois nós não podem usar o mesmo conjunto canônico e discordar sobre a chave de
um validador. A crate ainda não implementa nenhum algoritmo de assinatura: o
adaptador da engine deve suportar explicitamente o esquema declarado e usar a
chave configurada ao implementar `FinalityVerifier`.

Por isso, a presença de uma chave na gênese não torna uma rede inicializável
por si só. O adaptador Comet atual ainda precisa recusar todo esquema que não
implemente e conferir, em um bootstrap multi-validador, a correspondência entre
a chave Noxis, a chave da engine e o peso do validador antes de abrir uma rede.

## Cabeçalho de bloco

Um `BlockHeader` vincula, de modo canônico e versionado:

- `GenesisId`, `ValidationContextId`, `ConsensusConfigId` e `ValidatorSetId`;
- altura, época, rodada e pai (o bloco inicial não tem pai; os seguintes têm);
- `StateId` anterior e resultante;
- primeira sequência NXRC, quantidade de registros e compromisso ordenado dos
  `RecordHash`;
- `BlockId`, calculado a partir de todos os campos anteriores.

O executor Noxis v1 fixa `epoch` e `round` em zero. Esses campos permanecem
no formato para uma evolução que os vincule a metadados comprováveis da engine;
um adaptador ABCI não pode inventar uma rodada Comet a partir de informação que
a ABCI não entrega ao aplicativo.

O compromisso de registros inclui a quantidade e a ordem. Portanto, os mesmos
registros em ordem diferente, ou uma quantidade diferente, não produzem o
mesmo compromisso. `validate_record_hashes` exige coincidência exata com o
cabeçalho; a futura cadeia de consenso verificará também continuidade de pai,
altura, sequência e estado.

Blocos vazios são válidos: eles têm `record_count = 0`, o compromisso canônico
da lista vazia e nenhum `RecordHash` terminal novo. `first_record_sequence`
ainda aponta para a próxima sequência disponível, preservando a continuidade
quando o bloco seguinte trouxer registros. Isso permite que a engine decida
uma altura sem transações sem inventar um registro de ledger.

## Certificado de finalidade

Um `FinalityCertificate` contém um `FinalityTarget` e votos ordenados por
validador. O alvo inclui todos os IDs de domínio, altura/época/rodada e
`BlockId`; os bytes assinados usam um domínio próprio de precommit. Assim, uma
assinatura não pode ser reutilizada como transação, registro local ou voto de
outro bloco.

`validate_structure` confirma ligação ao cabeçalho, à configuração e ao
`ConsensusAnchor` da rede, membros conhecidos, ausência de votos duplicados e
quórum. `verify` faz tudo isso e passa ao adaptador exatamente os bytes
canônicos assinados, a assinatura e a chave pública configurada de cada voto.
Somente seu retorno `VerifiedFinality` representa uma decisão aceita pelo
verificador fornecido; uma finalidade de rede exige o adaptador criptográfico
real e uma engine BFT definidos no próximo passo.

## Formatos e limites

Os formatos `NXCG` (configuração), `NXBH` (cabeçalho) e `NXFC` (certificado)
aceitam somente versão 3, não aceitam bytes finais e limitam alocações antes de
ler vetores. Chaves públicas são limitadas a 8 KiB, assinaturas não vazias a
16 KiB; blocos a 1.000.000 registros como defesa absoluta, além do limite
menor da configuração. `NXCG` também compromete um limite de até 64 MiB para a
soma dos bytes canônicos das transações de um bloco. O executor deve aplicar
esse último limite à proposta concreta; o cabeçalho por si só não contém as
transações. Identificadores e compromissos usam SHA-256 com separação de
domínio.

Esses limites são validações de parser, não parâmetros de desempenho da rede.
A engine e a governança deverão especificar seus próprios limites operacionais
e procedimento de atualização.

Uma gênese que será implantada também limita a configuração a 1 MiB. É um
limite operacional explícito, menor que o limite genérico do parser; ele evita
que uma configuração tecnicamente decodificável, mas desproporcional, seja
gravada no manifesto de um nó.

## Vínculo com gênese e runtime local

`GenesisConfig` exige uma `ConsensusConfig`; seu `GenesisId` compromete os
bytes canônicos dessa configuração. O manifesto de diretório `NXMF` v7 armazena
os mesmos bytes, a identidade CometBFT opcional e os redecodifica antes de
comparar o `GenesisId`. Portanto, um diretório inicializado para um conjunto de
validadores não pode ser reaberto silenciosamente usando outro conjunto, outra
chave pública, outro limite de bloco, outro orçamento de falha ou outra
identidade de engine.

## Limite do certificado genérico

`FinalityCertificate` é uma fronteira genérica para engines cujos validadores
assinem exatamente o transcript Noxis definido aqui. Ele **não** é uma prova
de finalidade CometBFT: Comet assina seu formato `CanonicalVote`, ligado ao
`chain_id`. A integração planejada manterá uma prova específica com
`SignedHeader` e `Commit` Comet para clientes, checkpoints e auditoria.
