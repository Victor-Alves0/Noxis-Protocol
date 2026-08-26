# CI do CometBFT v0.38.17

## Objetivo

O adaptador Noxis suporta somente o protocolo ABCI do CometBFT `0.38.x` e a
identidade de gênese registra essa compatibilidade. Portanto, o teste de
integração não pode depender de uma versão arbitrária instalada no executor do
GitHub Actions.

`.github/actions/setup-cometbft/action.yml` baixa exatamente o artefato oficial
Linux x86_64 abaixo, verifica o SHA-256 antes de descompactar ou executar e
expõe seu caminho em `COMETBFT_BIN` e na saída `bin` da ação.
O diretório fica no espaço temporário do executor até o fim do job, para que o
teste seguinte possa executar o caminho publicado; os executores hospedados do
GitHub descartam esse espaço ao concluir o job.

| Campo | Valor fixado |
| --- | --- |
| Versão | `0.38.17` |
| URL | `https://github.com/cometbft/cometbft/releases/download/v0.38.17/cometbft_0.38.17_linux_amd64.tar.gz` |
| SHA-256 | `ca4d7ca0df296e092462edc92a3f07a4cd1e6c0366516e382a0726b522806f38` |
| Origem do hash | `SHA256SUMS-0.38.17.txt` publicado no release oficial `v0.38.17` do CometBFT |

Uma divergência no hash, um pacote sem `bin/cometbft` executável ou uma versão
impressa diferente de `0.38.17` faz a ação falhar antes de qualquer teste.
Guardar o hash no repositório torna a revisão do upgrade explícita: mudar a
versão exige rever a URL, o hash, a compatibilidade ABCI e as regras de
gênese; não basta alterar uma variável de CI.

O hash protege a transferência contra troca acidental ou maliciosa do arquivo,
mas não substitui revisão da origem publicada pelo projeto CometBFT nem uma
política futura de assinaturas/release provenance.

O fixture também usa Go `1.23.12`, instalado explicitamente na CI, porque o
módulo oficial do CometBFT `v0.38.17` declara Go `1.23`. Ele não reimplementa
consenso: pede às bibliotecas oficiais do CometBFT que leiam o genesis gerado e
serializem `ConsensusParams`, antes de o Noxis vincular o SHA-256 resultante à
sua própria identidade de genesis.

## Job de integração

O workflow contém um job independente que instala o motor fixado, inicia um
serviço ABCI Noxis e um validador CometBFT local. Sua forma é:

```yaml
  cometbft-e2e:
    name: CometBFT v0.38 process integration
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: rustup toolchain install 1.85.0 --profile minimal
      - uses: actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff
        with:
          go-version: '1.23.12'
      - id: cometbft
        uses: ./.github/actions/setup-cometbft
      - run: >-
          cargo +1.85.0 test -p noxis-node --test cometbft_e2e --features research-testing --locked --
          --ignored --exact real_cometbft_handshake_empty_block_and_process_restart
        env:
          COMETBFT_BIN: ${{ steps.cometbft.outputs.bin }}
```

O teste precisa criar uma home temporária por execução, usar portas loopback
livres e removê-la ao terminar. Ele deve validar pelo menos: `Info` e
`InitChain`, produção/`Commit` de um bloco, correspondência de altura e
`AppHash` via RPC, e reinício contra o mesmo journal. O `parameters_sha256`
da gênese deve ser calculado por bibliotecas do próprio CometBFT a partir dos
bytes protobuf de `ConsensusParams`, não de uma serialização JSON.

O job é Linux porque o journal `NXCB` exige a barreira de durabilidade de
diretório atualmente implementada em Unix. Esse limite é deliberado: no
Windows a gravação falha fechada em vez de confirmar um bloco sem garantia de
durabilidade.
