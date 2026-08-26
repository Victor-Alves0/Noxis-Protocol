# Plano de Entregas do Noxis

O Noxis será construído em incrementos que funcionam isoladamente. Cada incremento termina com código verificável, documentação atualizada e uma explicação em linguagem simples do que mudou, por que isso importa e qual é a próxima dependência.

## Princípios de entrega

- Nenhuma integração com dinheiro, custódia ou rede pública entra antes de suas regras de segurança e falha estarem especificadas e testadas.
- Não chamamos uma garantia de privacidade, resistência quântica ou solvência de "pronta" antes da implementação concreta, revisão independente e testes adversariais.
- Interfaces estáveis e formatos de dados são definidos antes de rede e banco de dados; isso evita reescrever componentes quando o projeto crescer.
- Cada módulo tem uma responsabilidade única e pode ser testado sem iniciar o sistema inteiro.

## Entregas planejadas

### 1. Mensagens verificáveis e modelo de ameaça

Define quem pode atacar o sistema, o que precisa ser protegido e como uma transação é representada de forma não ambígua entre computadores.

### 2. Estado durável e raiz Merkle

Guarda o histórico de forma recuperável e produz uma impressão criptográfica do conjunto de notas. É o alicerce para provar que uma nota existia sem revelar qual é.

### 3. Nó local funcional

Expõe uma API local, persiste transações, consulta estado e executa fluxos completos de emissão autorizada e transferência com verificadores controlados de desenvolvimento.

### 4. Consenso e rede autenticada

Faz vários nós concordarem na mesma ordem de transações, com identidade de nó, proteção contra mensagens repetidas e regras de recuperação.

**Progresso atual:** a fundação canônica foi criada em `noxis-consensus` e o
ciclo local de aplicação foi separado em `noxis-comet-abci`:
conjunto de validadores ponderado, cabeçalho de bloco, compromisso de registros
e certificado que só se torna finalidade após verificação de quórum e
assinaturas; `CheckTx`/propostas/finalização não gravam e apenas `Commit`
persiste um bloco `NXCB`. A identidade Comet (rede, altura inicial, versão de
compatibilidade e compromisso dos parâmetros) agora faz parte da gênese e do
manifesto; o mapeamento v0.38 de chaves Ed25519, endereços e poderes também é
recalculado e preso à gênese. Cada bloco durável e seu `AppHash` registram a
decisão exata da engine, e o núcleo compara os parâmetros e validadores de
`InitChain` com essa âncora. O adaptador TCP ABCI v0.38 agora decodifica o
socket protobuf estritamente e mantém o núcleo serializado entre conexões. Ainda
faltam validar tudo contra uma engine BFT em execução, adaptador de assinatura
concreto, chaves privadas, rotação/governança, comunicação entre nós e
recuperação baseada em finalidade.

### 5. Privacidade criptográfica auditável

Substitui o verificador de desenvolvimento por um sistema de provas escolhido e revisado, com circuitos, árvore Merkle canônica, provas de associação, conservação de valor e prevenção de gasto duplo.

**Estado atual:** não implementada. As interfaces e a versão de suíte existem
para permitir migração; anonimato real, provas ZK de produção e criptografia
híbrida pós-quântica só poderão ser considerados ativos depois de escolha
formal, implementação, testes adversariais e auditoria independente.

### 6. Adaptadores de ativos e políticas de emissão

Conecta ativos apenas onde o backing, a custódia, resgate, falhas e responsabilidades forem explicitamente especificados. Fiat externo nunca é aceito como prova automática de backing.

### 7. Revisão e testnet fechada

Inclui modelagem formal quando aplicável, fuzzing, testes de propriedade, análise de dependências, auditoria independente e operação em ambiente isolado antes de qualquer rede aberta.
