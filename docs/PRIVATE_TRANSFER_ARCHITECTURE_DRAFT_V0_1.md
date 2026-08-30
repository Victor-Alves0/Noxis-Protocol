# Arquitetura de transferência privada v2 — rascunho v0.1

## Estado e decisão de escopo

Este é um rascunho de arquitetura, não uma implementação criptográfica nem aprovação para operar valor. O protocolo ativo continua em v0.1, com árvore SHA-256 e `Proof` opaco; ele não oferece anonimato nem resistência pós-quântica.

Como o objetivo do Noxis inclui resistência pós-quântica para o sistema de provas, Halo2/PLONK sobre curvas elípticas deixa de ser a direção candidata. O candidato de pesquisa passa a ser `NX-ZK-STARK/V1`: prova transparente baseada em AIR/STARK, sem cerimônia confiável. A segurança dependerá da AIR, do hash, do campo, do transcript, dos parâmetros e de auditoria; este documento não a alega. A motivação técnica está no trabalho original [STARK](https://eprint.iacr.org/2018/046.pdf).

Nenhuma biblioteca é adotada aqui. Winterfell não é elegível nesta etapa: o próprio repositório o declara de pesquisa e não pronto para produção, e a versão atual exige Rust superior ao MSRV do Noxis ([upstream](https://github.com/facebook/winterfell), [manifesto](https://docs.rs/crate/winterfell/latest/source/Cargo.toml)).

## Construção proposta

`PrivateTransferV2` transfere um único `AssetId` público por prova. A primeira AIR terá exatamente duas entradas e duas saídas; slots sem valor usam notas privadas de valor zero geradas normalmente. Não há taxa na v2 inicial. O circuito exige conservação sem overflow:

```text
value_in[0] + value_in[1] = value_out[0] + value_out[1]
0 <= cada value < 2^128
```

O ativo público reduz o escopo inicial multiativo. A prova é vinculada à raiz e ao `StateId` pré-transição exatos; janela de raízes é evolução posterior, nunca flexibilização implícita.

### Nota e witness privado

Cada entrada testemunhada contém:

```text
asset_id
value: u128
recipient_commitment
rho: 32 bytes aleatórios únicos
rcm: aleatoriedade do commitment
nullifier_key: segredo de gasto
leaf_position
merkle_path
```

As funções recebem identificadores de parâmetro e domínios fixos antes de implementação:

```text
recipient_commitment = H_addr(nullifier_key)
cm = H_note(asset_id, value, recipient_commitment, rho, rcm)
nf = H_nf(nullifier_key, rho, cm, leaf_position)
```

A AIR deve provar conhecimento da nota e chave, recomputação de `cm`, inclusão na raiz, recomputação de `nf`, conservação/faixa e criação dos commitments de saída. O mesmo `nullifier_key` precisa produzir `recipient_commitment` e o nullifier; assim, a AIR vincula posse e gasto sem revelar a nota. A descrição de [Orchard](https://zcash.github.io/orchard/design/nullifiers.html) é referência conceitual, não especificação reutilizada.

## Inputs públicos canônicos

O backend monta os inputs nesta ordem, sem campos opcionais ou reordenação:

```text
protocol_id = "NOXIS/NX-ZK-STARK/V1"
circuit_id
genesis_id
validation_context_id
transaction_intent_id
pre_state_id
tree_parameter_id
tree_depth = 32
pre_state_root
asset_id
nullifier[2]
output_commitment[2]
ciphertext_digest[2]
```

`ProofVerifierId` será hash de descritor canônico contendo versão AIR, backend, campo, parâmetros FRI, transcript, parâmetros Poseidon2, árvore, codificação, limites de prova e hash do programa verificador. Trocar qualquer item exige gênese e contexto novos.

`transaction_intent_id` v2 inclui `ciphertext_digest[2]`; isso impede a troca do envelope de destinatário sem invalidar prova e intenção. `NOXT` v1 não possui esses campos e não é compatível com `PrivateTransferV2`.

## Árvore e commitments v2

A árvore SHA-256 atual não pode ser reutilizada dentro do circuito. A v2 fixa profundidade 32 e usa Poseidon2 com domínios independentes `NOTE`, `LEAF`, `NODE` e `EMPTY`. Campo, constantes, endianness, bytes-para-campo, ordem esquerda/direita, folha vazia, inserção por bloco e vetores independentes devem ser congelados. Poseidon2 foi projetado para aritmetização e discute AIR/FRI e árvores Merkle ([paper](https://eprint.iacr.org/2023/323.pdf)); isso não elimina revisão dos parâmetros Noxis.

`NoteCommitmentV2`, `NullifierV2`, `MerkleRootV2` e `CiphertextDigestV2` já têm uma representação de pesquisa canônica no código: 16 elementos BabyBear de 32 bits, cada um little-endian e estritamente menor que `2_013_265_921`, totalizando 64 bytes. O parser recusa elementos fora do campo; assim, não existem dois encodings de bytes para o mesmo elemento matemático. Isso fixa apenas a fronteira de serialização: ainda não escolhe a permutação Poseidon2, o sponge, as constantes, nem uma árvore executável.

O `TreeParametersId` continua sem valor reconhecido nesta versão. Antes de produzir uma raiz ou aceitar qualquer valor v2, o identificador deverá comprometer o manifesto completo da árvore. O processo e as condições de seleção estão em [`TREE_BACKEND_SELECTION_GATE_V0_1.md`](TREE_BACKEND_SELECTION_GATE_V0_1.md). É quebra de formato deliberada: codec, record-chain, storage, checkpoint e gênese v1 ficam imutáveis; uma rede v2 começa com nova gênese.

## Envelope e testes

Cada saída v2 contém `note_commitment_v2`, `hybrid_recipient_envelope` e `ciphertext_digest`. A AIR não verifica KEM/AEAD internamente: o envelope é ligado à prova pelo digest e será especificado separadamente no perfil híbrido.

Antes de autorização de serviço, o repositório precisa conter vetores independentes, teste diferencial entre árvore Rust/referência/AIR, rejeições de cada input público alterado, testes de overflow/conservação/inclusão, fuzzing de parser com orçamento de CPU/RAM, benchmark reproduzível e auditoria externa da AIR, parâmetros, implementação e modelo de privacidade.

Tipos v2, árvore v2 e carteira/prover offline são entregas separadas. Nenhuma delas, isoladamente, remove o gate em [`CRYPTO_SERVICE_GATE_V0_1.md`](CRYPTO_SERVICE_GATE_V0_1.md).

## Base entregue

`noxis-privacy-types` agora fixa a primeira fronteira de código desta arquitetura. O crate depende somente de `noxis-types` e não participa de `NOXT` v1, do ledger ou do serviço Comet. Ele entrega `CircuitId`, parâmetros de árvore, commitments, nullifiers, raiz e digests de envelope em 64 bytes, representados por 16 elementos BabyBear canônicos, e uma `PrivateTransferIntentV2` de 640 bytes, com aridade exatamente 2×2, ordem canônica, rejeição de duplicatas e round-trip testado. O ID da intenção ainda não é calculado ali: uma camada criptográfica futura deverá derivá-lo dos bytes canônicos com o domínio `NOXIS/PRIVATE-TRANSFER-INTENT/V2\0` antes de passá-lo à AIR. Isso evita tanto autorreferência quanto um ID escolhido pelo chamador.

O segundo componente entregue é o enquadramento externo `NXPT` v1, em `noxis-codec`. Ele não altera o formato `NOXT` v1 nem cria uma operação aceita pelo ledger. Sua ordem é fixa: `"NXPT"`, versão `u16` big-endian, intenção de 640 bytes, dois envelopes com comprimento `u16` e uma prova com comprimento `u32`. Cada envelope deve conter de 1 a 4 KiB; a prova deve conter de 1 byte a 2 MiB. O decoder verifica tamanho antes de copiar bytes, recusa versões, truncamento e bytes finais. Os limites da prova são provisórios e não constituem orçamento de produção: só poderão ser congelados depois de benchmark adversarial do backend escolhido.

O parser `NXPT` continua estrutural e não verifica prova. Porém a fronteira local `noxis-private-packet-validation` agora redecodifica os dois envelopes como `NXRE` canônicos, reencoda-os sem normalização e compara `H_ENVELOPE(slot, commitment, nxre)` aos dois digests da intenção antes de qualquer prova. Ainda não há vetores externos, AIR, seleção criptográfica ou chamada pelo ledger; por isso, o pacote permanece impossível de aplicar no ledger v1 e não remove o gate do serviço. Ver [`RECIPIENT_ENVELOPE_DIGEST_CANDIDATE_V0_1.md`](RECIPIENT_ENVELOPE_DIGEST_CANDIDATE_V0_1.md) e [`PRIVATE_PACKET_ENVELOPE_VALIDATION_CANDIDATE_V0_1.md`](PRIVATE_PACKET_ENVELOPE_VALIDATION_CANDIDATE_V0_1.md).
