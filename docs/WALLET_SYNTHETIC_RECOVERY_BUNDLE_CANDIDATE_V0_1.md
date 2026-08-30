# Bundle sintético de recuperação de keystore — candidato v0.1

## Estado

**Backup/restauração portátil de ciphertext sintético entre diretórios distintos. Não transporta nem libera segredo de wallet.**

`NXKB v1` é a unidade binária de transporte do cabeçalho público `NXKS v2` e
de uma geração opaca `NXKP v1`. O recibo externo `NXKA v1` fica
intencionalmente fora do bundle: copiar o recibo junto com o backup eliminaria
a independência necessária para detectar rollback.

## Formato canônico `NXKB v1`

O bundle tem exatamente 232 bytes:

```text
magic:4 = "NXKB"
version:u16be = 1
header:76 = encode(NXKS v2)
payload:150 = encode(NXKP v1)
```

Não há comprimento variável, campo opcional, padding ou bytes finais. O parser
reabre os dois formatos filhos e exige `payload.header_id == id(header)`.
Portanto trocar o cabeçalho por outro válido não cria um backup válido.

`NXKB` não contém `NXKA`, senha, plaintext, seed, spend key, view key, nota ou
saldo. Ele é somente uma cópia portátil de dados já públicos/opacos no limite
atual do projeto.

## Captura e restauração

`CandidateSyntheticRecoveryBundleV1::capture` recebe um diretório de origem já
bloqueado e um `NXKA` obtido de armazenamento independente. Antes de criar os
bytes do bundle, ela carrega exatamente a geração indicada pelo recibo e confere
cabeçalho, geração e identificador de ciphertext.

Na restauração, o chamador novamente fornece `NXKA` separadamente. O bundle o
valida **antes** de inicializar o diretório de destino. Somente então grava o
`NXKS` e publica a geração imutável `NXKP`, reutilizando o lock, a validação de
nonce e a publicação por temporário do store. O destino não pode aceitar uma
cópia antiga se o recibo independente aponta para uma geração/ciphertext mais
novo.

## Evidência executável

```powershell
cargo test -p noxis-wallet-keystore --locked
cargo clippy -p noxis-wallet-keystore --all-targets --locked -- -D warnings
cargo test -p noxis-wallet-keystore --features research-testing --locked
```

Os testes verificam que `NXKB` é codificado/decodificado e restaurado entre dois
diretórios temporários distintos, com `NXKA` também codificado/decodificado de
forma independente. Eles também verificam que recibo incompatível falha antes
de escrever sequer o cabeçalho de destino, e que truncamento ou substituição de
cabeçalho é rejeitado. Uma restauração interrompida após o cabeçalho e antes do
payload é retomada pelo mesmo bundle/recibo sem sobrescrever bytes. Os testes
de integração também terminam de fato o processo nesse ponto e após sincronizar
o temporário `NXKP`; um segundo processo conclui a restauração nos dois casos.

## Demonstração entre processos

O binário exige explicitamente a feature `research-testing` e usa uma raiz e
senha fixas **sem valor de usuário**. Crie uma pasta externa aos dois diretórios
de wallet e execute os dois comandos separadamente:

```powershell
New-Item -ItemType Directory -Force .\target\noxis-keystore-synthetic-demo | Out-Null

cargo run -p noxis-wallet-keystore --features research-testing --bin noxis-keystore-synthetic-demo -- create `
  --wallet-dir .\target\noxis-keystore-synthetic-demo\source-wallet `
  --bundle .\target\noxis-keystore-synthetic-demo\backup.nxkb `
  --anchor .\target\noxis-keystore-synthetic-demo\anchor.nxka

cargo run -p noxis-wallet-keystore --features research-testing --bin noxis-keystore-synthetic-demo -- restore `
  --wallet-dir .\target\noxis-keystore-synthetic-demo\restored-wallet `
  --bundle .\target\noxis-keystore-synthetic-demo\backup.nxkb `
  --anchor .\target\noxis-keystore-synthetic-demo\anchor.nxka
```

Para reproduzir a retomada após encerramento real, acrescente
`--stop-after-header` ao primeiro `restore`. Ele encerra intencionalmente com
código 86 depois de tornar `NXKS` durável; execute o mesmo `restore` sem a
flag para publicar `NXKP`. O teste de integração cobre essa sequência com dois
processos filhos.

Use `--stop-after-payload-temporary-sync` para encerrar com código 87 depois
de sincronizar `.payload-…nxkp.tmp` e antes do rename. Ao repetir o `restore`,
o store revalida o temporário e o promove para a geração imutável canônica;
`publish` então retorna `AlreadyPublished`.

O binário recusa colocar `NXKB` ou `NXKA` dentro do diretório da wallet. O teste
de integração executa exatamente `create` e `restore` como processos separados
e confirma os tamanhos canônicos dos dois artefatos e os arquivos do destino.

## Limites deliberados

- Os dados do teste ainda representam apenas ciphertext de uma raiz sintética.
- O bundle é um formato de transporte, não uma UX de backup, um arquivo de
  recuperação de senha ou um mecanismo de custódia.
- A restauração possui duas publicações (cabeçalho e payload). A repetição do
  mesmo bundle após a primeira publicação é testada e idempotente, inclusive
  após término real do processo. O temporário de `NXKP` também é recuperado
  após término real. Ainda faltam outros pontos de falha do sistema de arquivos
  e comportamento de volumes/sistemas operacionais distintos.
- Há um teste entre processos locais; ainda não há cópia para mídia externa,
  sincronização remota ou garantia de que o usuário guardou `NXKA` em local
  independente.

## Próximo gate

Definir o conjunto de sistemas de arquivos/plataformas suportados, testar seus
pontos de falha relevantes e revisar a durabilidade multi-arquivo. Só depois
disso, de um inventário de segredos e de revisão independente será aceitável
propor um container real.
