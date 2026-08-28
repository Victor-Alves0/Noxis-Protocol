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
socket protobuf estritamente e mantém o núcleo serializado entre conexões. Um
teste Linux inicia CometBFT 0.38.17 real, produz um bloco, reinicia ambos os
processos contra o mesmo journal e roda na CI com binário fixado por checksum.
Ainda faltam adaptador de assinatura concreto, chaves privadas,
rotação/governança, comunicação entre nós e recuperação baseada em finalidade.

### 5. Privacidade criptográfica auditável

Substitui o verificador de desenvolvimento por um sistema de provas escolhido e revisado, com circuitos, árvore Merkle canônica, provas de associação, conservação de valor e prevenção de gasto duplo.

**Estado atual:** não implementada. As interfaces e a versão de suíte existem
para permitir migração, e o serviço de liquidação agora falha fechado até uma
pilha criptográfica aprovada existir. A exceção `research-testing` é limitada ao
teste E2E. Anonimato real, provas ZK de produção e criptografia híbrida
pós-quântica só poderão ser considerados ativos depois de escolha formal,
implementação, testes adversariais e auditoria independente. Ver
[`CRYPTO_SERVICE_GATE_V0_1.md`](CRYPTO_SERVICE_GATE_V0_1.md).

**Próxima especificação implementável:** `PrivateTransferV2` foi delimitada
como candidata STARK/AIR transparente, com duas entradas e duas saídas,
árvore Poseidon2 v2 e nova gênese. O perfil de transporte/identidade híbrido
fica separado para não atribuir segurança da rede à prova privada. Ambos são
rascunhos e não habilitam criptografia: ver
[`PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md`](PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md)
e [`HYBRID_CRYPTO_PROFILE_DRAFT_V0_1.md`](HYBRID_CRYPTO_PROFILE_DRAFT_V0_1.md).

**Base de código v2:** o crate isolado `noxis-privacy-types` fixa a intenção canônica de transferência privada, sua aridade e tipos públicos sem acoplar provas, hashes, chaves ou carteira. Os valores públicos de 64 bytes já rejeitam encoding não canônico: são 16 elementos BabyBear little-endian, cada um abaixo do módulo do campo. O codec externo `NXPT` agora enquadra intenção, dois envelopes e prova com limites rígidos, ainda sem aceitar a transação no ledger v1. A árvore ainda não existe: o próximo incremento é selecionar e congelar um backend Poseidon2 completo, seu manifesto e vetores independentes antes de escrever a referência que será comparada com a AIR; ver [`TREE_BACKEND_SELECTION_GATE_V0_1.md`](TREE_BACKEND_SELECTION_GATE_V0_1.md).

### 6. Adaptadores de ativos e políticas de emissão

Conecta ativos apenas onde o backing, a custódia, resgate, falhas e responsabilidades forem explicitamente especificados. Fiat externo nunca é aceito como prova automática de backing.

### 7. Revisão e testnet fechada

Inclui modelagem formal quando aplicável, fuzzing, testes de propriedade, análise de dependências, auditoria independente e operação em ambiente isolado antes de qualquer rede aberta.
