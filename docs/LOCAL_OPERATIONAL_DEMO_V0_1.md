# Demonstração operacional local v0.1

O demo local torna observável a sequência pública atualmente implementada, em
um diretório durável criado pelo operador:

1. cria uma gênese de pesquisa com o ativo sintético `NUSD`;
2. inicializa um `LocalNodeRuntime` e mostra `GenesisId`, altura local e
   `StateId`;
3. submete um mint autorizado pela política de fixture;
4. submete uma transferência de pesquisa com uma prova de fixture;
5. tenta gastar o mesmo nullifier novamente e recebe
   `NullifierAlreadySpent`;
6. fecha e reabre o nó, conferindo que a sequência durável foi recuperada.

## Como executar

```powershell
cargo run -p noxis-node --features research-testing -- demo-local
just demo
.\scripts\demo-local.ps1
```

Em sistemas POSIX:

```sh
./scripts/demo-local.sh
```

O argumento `--data-dir CAMINHO` conserva os artefatos para inspeção. Sem ele,
o binário cria uma pasta única em `target/noxis-demo-local`; os scripts também
criam um caminho único sob `target`.

## Ciclo de vida explícito do nó de pesquisa

Além do demo completo, o mesmo binário pode inicializar e consultar um nó
local persistente. Esses comandos não abrem uma porta de rede: eles mostram o
estado realmente recuperado do diretório escolhido.

```powershell
cargo run -p noxis-node --features research-testing -- research init --data-dir .\target\noxis-research
cargo run -p noxis-node --features research-testing -- research status --data-dir .\target\noxis-research

# Executa mint, transferência de fixture e rejeição de double spend em um
# diretório vazio, depois deixa o estado disponível para `research status`.
cargo run -p noxis-node --features research-testing -- research demo --data-dir .\target\noxis-research-demo
```

`research init` cria ou reabre o diretório ligado à gênese de pesquisa.
`research status` usa o mesmo caminho de abertura e, portanto, falha se o
manifesto ou a recuperação durável não forem válidos. A altura exibida é a
sequência local; não é altura de consenso.

## Submissão manual observável

O demo completo continua sendo o modo mais curto de verificar a sequência,
mas as fixtures também podem ser submetidas uma a uma. Isso permite inspecionar
o estado entre cada operação e ver qual invariante causou uma rejeição.

Em PowerShell, em um diretório inicialmente vazio:

```powershell
$dataDir = '.\target\noxis-research-submit'
$mint = cargo run -q -p noxis-node --features research-testing -- research fixture mint-hex | Select-Object -Last 1
cargo run -q -p noxis-node --features research-testing -- research submit --data-dir $dataDir --transaction-hex $mint

$transfer = cargo run -q -p noxis-node --features research-testing -- research fixture transfer-hex | Select-Object -Last 1
cargo run -q -p noxis-node --features research-testing -- research submit --data-dir $dataDir --transaction-hex $transfer

$duplicate = cargo run -q -p noxis-node --features research-testing -- research fixture duplicate-nullifier-hex | Select-Object -Last 1
cargo run -q -p noxis-node --features research-testing -- research submit --data-dir $dataDir --transaction-hex $duplicate

cargo run -q -p noxis-node --features research-testing -- research status --data-dir $dataDir
```

O primeiro comando de submissão aceita o mint, o segundo aceita a transferência
e o terceiro imprime uma rejeição `NullifierAlreadySpent`. A rejeição não é
erro de processo: ela é o resultado esperado da validação e não altera a
sequência local, que permanece em `2`. Os valores hex são bytes canônicos de
fixtures públicas; não são segredos, chaves, endereços de wallet nem uma API
de emissão de ativos.

## Limites deliberados

O comando exige `research-testing` e imprime esse aviso. A política de mint e
o verificador são fixtures determinísticas, não mecanismos de autorização ou
provas criptográficas reais. A transferência demonstrada é a `Transfer` pública
do ledger v1; ela **não** é `PrivateTransferPacketV2`, não estabelece
privacidade e não deve ser apresentada como transferência privada aceita.

`AppHash` também não se aplica neste fluxo: ele pertence à execução de um bloco
de consenso. O demo local prova admissão, persistência, recuperação e rejeição
de gasto duplo; ele não inicia CometBFT, não produz finalidade e não usa o
journal `NXCB`. A integração CometBFT real permanece uma trilha separada e
Unix-only no estado atual.
