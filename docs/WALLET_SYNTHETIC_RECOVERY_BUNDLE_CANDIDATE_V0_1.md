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
```

Os testes verificam que `NXKB` é codificado/decodificado e restaurado entre dois
diretórios temporários distintos, com `NXKA` também codificado/decodificado de
forma independente. Eles também verificam que recibo incompatível falha antes
de escrever sequer o cabeçalho de destino, e que truncamento ou substituição de
cabeçalho é rejeitado. Uma restauração interrompida após o cabeçalho e antes do
payload é retomada pelo mesmo bundle/recibo sem sobrescrever bytes.

## Limites deliberados

- Os dados do teste ainda representam apenas ciphertext de uma raiz sintética.
- O bundle é um formato de transporte, não uma UX de backup, um arquivo de
  recuperação de senha ou um mecanismo de custódia.
- A restauração possui duas publicações (cabeçalho e payload). A repetição do
  mesmo bundle após a primeira publicação é testada e idempotente, mas ainda
  faltam testes de término real de processo e de todos os pontos de falha do
  sistema de arquivos.
- Não há teste entre processos, cópia para mídia externa, sincronização remota
  ou garantia de que o usuário guardou `NXKA` em local independente.

## Próximo gate

Criar uma demonstração operacional sintética que execute captura, cópia e
restauração em processos separados e testar término real de processo nos
pontos de recuperação. Só depois de resolver essa atomicidade operacional,
inventariar os segredos de uma wallet e passar por revisão independente será
aceitável propor um container real.
