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
