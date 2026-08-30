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

**Evidência P24 candidata:** a referência densa isolada agora reproduz, contra
a execução externa Horizen, dois estados completos da permutação P24 e os
primeiros vetores do sponge/árvore: folha, vazio inicial e raízes de
profundidade 32 para zero, uma e duas notas. Ela continua sem depender do
ledger ou consenso e não seleciona a candidata. Ver
[`POSEIDON2_P24_REFERENCE_EVALUATION_V0_1.md`](POSEIDON2_P24_REFERENCE_EVALUATION_V0_1.md).

**Corpus P24 completo:** `NXTV v2` agora serializa o manifesto P24 completo e
seu ID candidato tanto no perfil inicial quanto no perfil `Complete` congelado.
Este último exige 50 vetores: permutações, folhas, duas ordens de nó,
`EMPTY[0..32]`, raízes de 0 a 4 commitments e caminhos em quatro orientações.
Ele fecha a cobertura de construção da árvore, sem alegar seleção de parâmetros
nem ativação. Ver [`TREE_VECTOR_CORPUS_P24_V2.md`](TREE_VECTOR_CORPUS_P24_V2.md).

**Smoke STARK P24:** o experimento Plonky3 prova e verifica a permutação P24,
pré-imagens privadas de `H_ADDR` e `H_NOTE`, `Hash16(Leaf, commitment)` e
`Hash16(Node, left || right)` ordenado contra vetores externos. A AIR de
`H_ADDR` decompõe cada um dos 32 bytes secretos em oito bits, recompõe os 11
elementos `BytePack3LE`, aplica as duas permutações P24 prescritas e torna
público apenas o commitment de destinatário. A AIR de `H_NOTE` faz o mesmo
para todos os 178 bytes do preimage e seus 60 elementos; torna público apenas
o note commitment. Ambas recusam bits não booleanos e bytes ou packing
incoerentes.

A AIR de posse executa `H_ADDR`, `H_NOTE`, `H_NULLIFIER`, `H_LEAF` e 32
`H_NODE` na mesma prova: o destinatário dentro da nota é `H_ADDR(key)`, o
commitment entra em `H_NULLIFIER` em `u32le`, e a mesma chave, `rho` da nota e
posição `u32be` privada formam o nullifier público. O commitment gera a folha
privada e os 32 irmãos são ordenados pelos 32 bits dessa mesma posição até uma
raiz pública. Folha, irmãos, direções e 31 nós intermediários permanecem
privados no traço. A prova completa exige build `--release`, pilha dedicada de
64 MiB e perfil FRI com `log_blowup = 4`, pois o AIR compacto tem grau 10. É
uma demonstração de pesquisa pesada, não um fluxo de carteira ou validador.
Ainda faltam uma âncora de estado aceita, ausência de nullifier e a
transferência privada.

**Preflight de posse ancorada:** `noxis-private-proof-contract` agora conecta
uma prova P24 de posse de uma nota à raiz de notas do `NXPS v2`, ao nullifier
da intenção `NXPU` e ao witness local de ausência/transição `NXSM`. Para a
declaração candidata fixa de duas entradas, ele executa as duas provas de posse
em sequência, contra a mesma âncora e os nullifiers ordenados, e descarta cada
prova opaca após verificá-la. Isso impede combinar uma prova válida com uma
âncora ou nullifier de outra intenção; não é agregação nem recibo verificável
por terceiros. Os 512 irmãos `NXSM` ainda são testemunha transparente local;
portanto, isto não é prova privada de ausência, autorização de ledger nem
transferência privada.

**Segmentos privados `NXSM`:** o experimento STARK agora cobre oito níveis de
qualquer uma das 64 bytes canônicas do nullifier, usando o domínio de nó, IV e
`BytePack3LE` dos 128 bytes reais de cada nó. Um preflight local já executou os
64 segmentos em sequência, da folha vazia `E0` até uma raiz candidata real de
512 níveis, verificando e descartando cada prova; a execução release levou
1.926,27 s. Irmãos e intermediários permanecem privados em cada traço, mas o
resultado é somente uma checagem local, não agregação, prova portátil ou
transferência privada. Ver [`STARK_NXSM_PREFIX_RESEARCH_V0_1.md`](STARK_NXSM_PREFIX_RESEARCH_V0_1.md).

**Primeira relação AIR da transferência:** o experimento Plonky3 agora prova
o `H_INTENT` exato sobre os 214 elementos públicos `BytePack3LE` da intenção
canônica de 640 bytes e seu digest de 16 elementos. Os dois vetores externos
`NXIV` passam pela prova; ela aritmetiza os 640 bytes, seus bits e o packing
canônico, mas não torna a intenção privada e não compõe notas, valores ou
nullifiers. Ver [`STARK_INTENT_COMMITMENT_RESEARCH_V0_1.md`](STARK_INTENT_COMMITMENT_RESEARCH_V0_1.md).

**Limite de portabilidade do backend:** um teste serializa e desserializa uma
prova P24 de pesquisa com `postcard` e a verifica novamente usando uma
configuração nova com o mesmo perfil de código fixado. Isso prova que a
aleatoriedade local usada para gerar a prova não é necessária ao verificador.
Outro teste leva esses bytes temporários a um processo-filho novo do mesmo
build fixado e também os verifica. Ainda não existe descritor Noxis versionado,
formato de prova, compatibilidade entre versões/máquinas ou perfil selecionado.
Ver
[`STARK_VERIFIER_PROFILE_RESEARCH_V0_1.md`](STARK_VERIFIER_PROFILE_RESEARCH_V0_1.md).

**Parâmetros de pesquisa explícitos:** os valores FRI/PCS que antes apareciam
espalhados no construtor do experimento agora pertencem a dois descritores Rust
versionados: o perfil P24 normal (`log_blowup = 3`) e o de AIRs de grau alto
(`log_blowup = 4`). Ambos fixam consultas, aridade, PoW e codewords aleatórios
e são usados diretamente pelo construtor. Isso melhora auditabilidade, mas não
seleciona backend, cria um formato Noxis de prova ou habilita liquidação.

**Preflight de intenção e posse:** para a declaração `NXPU` 2×2, o contrato de
prova agora executa e verifica `H_INTENT` uma vez e as duas posses ancoradas em
sequência contra a mesma âncora e estado local, retendo apenas um recibo
público após descartar as três provas opacas. Isso é evidência operacional de
vínculo entre os componentes, não agregação, recursão ou prova de transferência;
ver
[`STARK_ANCHORED_OWNERSHIP_PREFLIGHT_RESEARCH_V0_1.md`](STARK_ANCHORED_OWNERSHIP_PREFLIGHT_RESEARCH_V0_1.md).

**Preflight de intenção e saídas:** o mesmo contrato agora também executa
`H_INTENT` uma vez e duas provas privadas `H_NOTE` em sequência, vinculando
cada commitment resultante ao respectivo slot canônico de saída em `NXPU`.
As witnesses de 178 bytes não têm codec e as provas opacas são descartadas;
isso não é agregação, não valida envelopes, valores ou inserção de saídas e não
autoriza o ledger. Ver
[`STARK_OUTPUT_NOTES_PREFLIGHT_RESEARCH_V0_1.md`](STARK_OUTPUT_NOTES_PREFLIGHT_RESEARCH_V0_1.md).

**Preflight completo de transferência:** uma nova entrada executável reúne as
relações de pesquisa já disponíveis sob a mesma declaração `NXPU`: `H_INTENT`
uma vez, duas posses/provas Merkle de profundidade 32 e duas provas `H_NOTE`
de saída. Os resultados são checados contra a âncora, nullifiers e slots de
output do mesmo statement; as provas seguem sequenciais e são descartadas.
Ainda não há AIR única, agregação, envelope, transição privada `NXSM`, estado
v2 ou aceitação pelo ledger. Ver
[`STARK_PRIVATE_TRANSFER_PREFLIGHT_RESEARCH_V0_1.md`](STARK_PRIVATE_TRANSFER_PREFLIGHT_RESEARCH_V0_1.md).

**Ativo dentro da AIR de saída:** a variante `H_NOTE` para outputs agora torna
públicos e restringe os 32 bytes de `asset_id` nos offsets canônicos 2..34 da
pré-imagem privada. O preflight 2×2 a usa para ambas as saídas e compara o
resultado com o ativo da intenção; valor, destinatário, aleatoriedades e
conservação ainda não fazem parte dessa relação. Ver
[`STARK_H_NOTE_ASSET_BINDING_RESEARCH_V0_1.md`](STARK_H_NOTE_ASSET_BINDING_RESEARCH_V0_1.md).

**Transição local de estado privado:** `noxis-private-state` agora deriva,
somente em memória, o estado posterior 2×2 a partir de `NXPS v2`, snapshot,
árvore `NXSM` e intenção. Ela acrescenta os commitments de saída, marca os dois
nullifiers, reconstrói a nova âncora e falha fechado contra gasto repetido ou
commitment reintroduzido. Não consome prova, não persiste ciphertexts e não é
regra de ledger. Ver
[`PRIVATE_STATE_TRANSITION_CANDIDATE_V0_1.md`](PRIVATE_STATE_TRANSITION_CANDIDATE_V0_1.md).

**Abertura e preflight candidatos:** o crate isolado
`noxis-note-opening` mantém localmente a abertura de 178 bytes, segredos sem
codec/`Debug`/`Clone`, caminho P24 de 32 níveis e uma declaração executável
2×2. Ela confere parâmetros candidatos, raiz, ativo, nullifiers, commitments,
conservação e padding, sem tocar ledger, rede ou consenso. Não cria prova nem
habilita liquidação. Ver [`NOTE_OPENING_BOUNDARY_V0_1.md`](NOTE_OPENING_BOUNDARY_V0_1.md)
e [`PRIVATE_TRANSFER_LOCAL_PREFLIGHT_V0_1.md`](PRIVATE_TRANSFER_LOCAL_PREFLIGHT_V0_1.md).

**Candidata de domínios privados:** `ADDR`, `NOTE` e `NULLIFIER` possuem
rótulos, packing e aridades candidatos ligados ao ID P24 pai sem modificá-lo.
O manifesto `NXPH` com IVs rederiváveis, checksum e ID próprio está congelado;
vetores externos, referência local e corpus NXNV estão congelados, ainda sem
seleção como hash de protocolo. Ver
[`POSEIDON2_P24_NOTE_DOMAINS_CANDIDATE_V0_1.md`](POSEIDON2_P24_NOTE_DOMAINS_CANDIDATE_V0_1.md).

**Referência de domínios privados:** o crate isolado
`noxis-poseidon2-privacy-reference` reproduz seis KATs gerados no clone
externo da Horizen para `ADDR`, `NOTE` e `NULLIFIER`, sem conexão com ledger
ou consenso. O corpus `NXNV` e a abertura semântica candidata já a utilizam,
sem convertê-la em criptografia ativa. Ver
[`POSEIDON2_P24_NOTE_DOMAINS_REFERENCE_EVALUATION_V0_1.md`](POSEIDON2_P24_NOTE_DOMAINS_REFERENCE_EVALUATION_V0_1.md).

**Corpus de domínios privados:** o framing `NXNV v1` foi especificado separado
de `NXTV`, com seis KATs fechados, manifesto NXPH completo e recomputação do
packing. O fixture binário e parser estrito estão versionados e verificam
tamanho, checksum, ordem e canonicidade. Ver
[`NOTE_DOMAIN_VECTOR_CORPUS_V0_1.md`](NOTE_DOMAIN_VECTOR_CORPUS_V0_1.md).

**Base de código v2:** `noxis-privacy-types` fixa a intenção canônica de 640
bytes e valores públicos BabyBear; `NXPT` apenas enquadra intenção, envelopes
e uma prova opaca fora do ledger v1. `noxis-tree-params`, `NXTV` e `NXNV`
congelam a candidata P24 e seus vetores completos, e as referências isoladas
reproduzem as evidências externas. A AIR já aritmetiza o compromisso da
intenção e há provas P24 separadas para os primeiros componentes, mas ainda
faltam a composição completa da transferência, política de ciclo de vida de
chaves/envelopes, formato de prova selecionado e revisão independente. Ver
[`PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md`](PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md)
e [`TREE_BACKEND_SELECTION_GATE_V0_1.md`](TREE_BACKEND_SELECTION_GATE_V0_1.md).

**Recebimento híbrido executável:** `noxis-wallet-crypto` agora possui um demo
local que gera um endereço diversificado, faz round-trip estrito de `NXPA` e
`NXRE`, cifra com X25519 + ML-KEM-768, permite decriptação apenas pelo dono e
verifica assinatura Ed25519 + ML-DSA-65. Nenhuma chave é persistida e isso não
é wallet, stealth address, nota privada nem liquidação. Ver
[`WALLET_CRYPTO_LOCAL_DEMO_V0_1.md`](WALLET_CRYPTO_LOCAL_DEMO_V0_1.md).

**Recebimento local de nota candidata:** a mesma camada pode cifrar uma
pré-imagem canônica de nota de 178 bytes em `NXRE`, recuperar somente no dono e
recomputar `H_NOTE` antes de aceitar o commitment público da saída. Isso não
persiste nota ou saldo; o digest candidato de envelope é uma fronteira separada
e ainda não cria transação, wallet ou
privacidade ativada. Ver
[`WALLET_PRIVATE_NOTE_RECEIPT_LOCAL_V0_1.md`](WALLET_PRIVATE_NOTE_RECEIPT_LOCAL_V0_1.md).

**Digest candidato de envelope:** `noxis-wallet-crypto` agora recompõe o
`NXRE` canônico e calcula `H_ENVELOPE` P24 sobre versão, slot, commitment e
comprimento/bytes do envelope. Alterar qualquer um desses itens muda o digest;
uma fronteira local de pacote já o recomputa, porém AIR e ledger ainda não o
aceitam. Vetores externos e integração ao preflight são os próximos gates. Ver
[`RECIPIENT_ENVELOPE_DIGEST_CANDIDATE_V0_1.md`](RECIPIENT_ENVELOPE_DIGEST_CANDIDATE_V0_1.md).

**Validação local de pacote privado:** `noxis-private-packet-validation` agora
redecodifica os dois `NXRE` de um `NXPT`, exige round-trip canônico e compara os
digests candidatos ao intento antes de qualquer prova. Envelope trocado de slot
ou bytes opacos não-`NXRE` são rejeitados. A fronteira não valida prova, estado,
ledger ou rede; integrar seu recibo ao preflight é o próximo passo. Ver
[`PRIVATE_PACKET_ENVELOPE_VALIDATION_CANDIDATE_V0_1.md`](PRIVATE_PACKET_ENVELOPE_VALIDATION_CANDIDATE_V0_1.md).

**Preflight STARK ligado ao pacote:** o contrato de prova agora aceita o
recibo validado de `NXPT`, exige que sua intenção seja a mesma da declaração e
só então executa `H_INTENT`, duas posses e duas saídas. Uma execução release
completa passou em 466,64 s; continua composição sequencial local, sem AIR
única, prova portátil, atualização de estado ou ponte entre `H_ADDR` e a chave
híbrida do destinatário. Ver
[`PACKET_BOUND_STARK_PREFLIGHT_RESEARCH_V0_1.md`](PACKET_BOUND_STARK_PREFLIGHT_RESEARCH_V0_1.md).

**Descriptor e raiz local de destinatário:** a wallet agora cria junto um
endereço `NXPA`, uma chave de nullifier/`H_ADDR` e uma identidade que assina o
par endereço+commitment. As chaves de recebimento e nullifier derivam, no
processo local, de uma raiz aleatória única e apagada; a raiz pode derivar
vários destinatários por época e índice, e remetente/destinatário recusam nota
cujo commitment não seja o do descriptor. O keyset pode virar uma view key de
entrada local, sem nullifier e sem autoridade de gasto. Isto não prova a
relação para terceiros, não oferece view key exportável, formato público,
diretório ou wallet persistente. Ver
[`RECIPIENT_DESCRIPTOR_LOCAL_CANDIDATE_V0_1.md`](RECIPIENT_DESCRIPTOR_LOCAL_CANDIDATE_V0_1.md)
e [`RECIPIENT_ROOT_DERIVATION_CANDIDATE_V0_1.md`](RECIPIENT_ROOT_DERIVATION_CANDIDATE_V0_1.md),
além de [`WALLET_ROOT_SESSION_LOCAL_CANDIDATE_V0_1.md`](WALLET_ROOT_SESSION_LOCAL_CANDIDATE_V0_1.md)
e [`INCOMING_VIEW_KEY_LOCAL_CANDIDATE_V0_1.md`](INCOMING_VIEW_KEY_LOCAL_CANDIDATE_V0_1.md).

**Catálogo local de endereços públicos:** a mesma camada já pode abrir um
diretório com lock exclusivo, gravar bytes `NXPA` canônicos por ID, reabrir e
validar estritamente o endereço. O catálogo nunca recebe chave privada, seed,
nota, saldo ou prova; ele serve somente à distribuição/reuso seguro de
endereços públicos. Persistência de segredo e recuperação de carteira exigem
outro projeto de keystore e não foram iniciadas aqui.

**Gate de keystore:** a persistência de qualquer segredo de wallet permanece
proibida até existir especificação de KDF/AEAD, formato limitado, inventário de
chaves, política de backup/rollback e testes adversariais. Um crate isolado já
decodifica o cabeçalho público candidato `NXKS` e testa Argon2id + XChaCha sobre
uma raiz sintética, mas não recebe segredo de usuário nem seleciona uma
construção de custódia. Um armazenamento separado já grava apenas o cabeçalho
público de forma atômica/com lock e recupera um temporário canônico; a política
de rollback e qualquer payload secreto continuam bloqueados. Ver
[`WALLET_KEYSTORE_SECURITY_GATE_V0_1.md`](WALLET_KEYSTORE_SECURITY_GATE_V0_1.md)
e [`WALLET_KEYSTORE_CONTAINER_CANDIDATE_V0_1.md`](WALLET_KEYSTORE_CONTAINER_CANDIDATE_V0_1.md).

### 6. Adaptadores de ativos e políticas de emissão

Conecta ativos apenas onde o backing, a custódia, resgate, falhas e responsabilidades forem explicitamente especificados. Fiat externo nunca é aceito como prova automática de backing.

### 7. Economia de segurança, liquidez e execução programável

Validação e liquidez têm fontes de receita e riscos distintos. O Noxis começa sem token, taxas, stake, pool ou contratos: a primeira implementação futura será taxa canônica e reserva por época, sem emissão automática. Staking, delegação, slashing, mercado e VM vêm depois e em módulos separados, sempre com conservação por ativo, limites de recurso e governança com atraso. Ver [`ECONOMIC_SECURITY_MODEL_V0_1.md`](ECONOMIC_SECURITY_MODEL_V0_1.md).

### 7. Revisão e testnet fechada

Inclui modelagem formal quando aplicável, fuzzing, testes de propriedade, análise de dependências, auditoria independente e operação em ambiente isolado antes de qualquer rede aberta.
