# Architecture

## Dependency direction

```text
noxis-node ──> noxis-comet-abci ──> noxis-storage ──> noxis-execution ──> noxis-record-chain ──> noxis-codec
     │                │                     │                 │
     ├────────────> noxis-ledger ───────> noxis-crypto ──> noxis-types
     ├────────────> noxis-checkpoint ───> noxis-ledger / record-chain / types
     └────────────> noxis-runtime ──────> noxis-config ────> noxis-consensus

noxis-consensus ────────────────────────> noxis-record-chain / noxis-types
```

Dependencies point inward. Domain types never depend on storage, transport, cryptographic providers or application wiring.

## Responsibilities

| Module | Owns | Must not own |
| --- | --- | --- |
| `noxis-types` | stable IDs, amounts, asset taxonomy | state, I/O, cryptography |
| `noxis-crypto` | suite versioning, proof-verifier contract | ledger mutation, keys, network clients |
| `noxis-ledger` | transaction shape, transition validation, state | concrete cryptography, databases, P2P |
| `noxis-record-chain` | canonical record encoding, sequence and state-link validation | ledger mutation, filesystem I/O, consensus |
| `noxis-checkpoint` | canonical `NXCP` encoding and snapshot integrity validation | filesystem I/O, replay policy, consensus |
| `noxis-consensus` | canonical BFT validator sets, block commitments, quorum and finality-certificate verification boundary | sockets, peer discovery, key storage, a homegrown consensus state machine |
| `noxis-execution` | deterministic no-I/O execution of an ordered block and `AppHash` calculation | filesystem I/O, network engine, finality claim |
| `noxis-config` | validated genesis, validation context and consensus configuration binding | filesystem, environment parsing, networking |
| `noxis-storage` | atomic `NXCB` block append, sync, replay coordination and tail recovery; legacy per-record storage | protocol rules, network transport, genesis policy |
| `noxis-comet-abci` | Comet height mapping, strict v0.38 TCP/protobuf framing, volatile mempool/proposal/finalization lifecycle and the sole durable `Commit` boundary | validator private keys, Comet finality proof, P2P/network claims |
| `noxis-node` | dependency composition and future service startup | protocol rules |

## Incremental roadmap

1. A identidade, o compromisso de parâmetros e o mapeamento exato dos
   validadores Comet v0.38 já estão ancorados no genesis, no manifesto `NXMF`
   v7, em cada decisão `NXCB` v2 e no `AppHash`. O núcleo exige que
   `InitChain` apresente esses mesmos parâmetros e validadores. O servidor TCP
   ABCI v0.38 já existe; em seguida, executar cenários ponta a ponta contra um
   binário CometBFT v0.38 fixado, completar a recuperação coordenada e provar
   a finalidade da engine separadamente do certificado genérico Noxis.
2. Implementar checkpoint de ponta de bloco, incluindo altura, `BlockId`, `AppHash` e futura prova de finalidade.
3. Substituir a fronteira abstrata de provas por um backend auditado e revisado independentemente, com construção canônica da raiz de estado.
4. Adicionar testes de propriedade/fuzz e injeção de falhas de escrita do sistema operacional à persistência.
5. Adicionar carteira e adaptadores de cadeia somente após especificar seus modelos de ameaça, falhas e resgate.
6. Exigir auditoria externa de criptografia e segurança antes de qualquer testnet com valor transferível.
