# Gate criptográfico do serviço de liquidação v0.1

## Decisão

O Noxis pode testar execução determinística, journal e integração ABCI, mas não
pode iniciar um **serviço de liquidação** com uma pilha criptográfica apenas de
pesquisa. Em particular, `CryptoSuite::RESEARCH_V1` contém identificadores e
reservas de arquitetura; não contém uma prova privada implementada, uma árvore
compatível com circuito, regras de chaves, nem uma auditoria independente.

Por isso, nesta versão, `ValidationContext::authorize_settlement_service()`
falha fechada para toda suíte. Não existe configuração de operador, variável de
ambiente, feature de produção ou construtor público que transforme o nome de um
algoritmo em aprovação para operar a liquidação.

## Como o bloqueio funciona

1. A autorização é um valor opaco criado pelo `ValidationContext`; código de
   aplicação não consegue fabricá-la.
2. Ela é vinculada ao hash do contexto de validação, que inclui a suíte e os
   IDs do verificador de provas e da política de emissão.
3. `CometNodeService::open` exige a autorização antes de criar o diretório de
   dados ou abrir a interface ABCI.
4. `NoxisCometCore::try_new` exige o mesmo valor novamente antes de receber o
   journal de execução.
5. Um valor emitido para outro contexto é recusado. Assim, não pode ser
   reaproveitado ao trocar verificador, política ou suíte.

O resultado é deliberado: o processo de consenso pode ser integrado e testado,
mas o serviço que aplicaria liquidações permanece indisponível até existir uma
pilha criptográfica aprovada.

## Exceção limitada a testes

A feature não padrão `research-testing` permite criar uma autorização somente
para `CryptoSuite::RESEARCH_V1`. Ela existe para que o teste de integração
inicie CometBFT real, escreva um bloco e valide recuperação do journal. Não é
compilada por padrão e não autoriza custódia, rede pública, testnet aberta ou
alegação de privacidade.

O comando de integração é:

```text
cargo +1.85.0 test -p noxis-node --test cometbft_e2e --features research-testing --locked -- --ignored --exact real_cometbft_handshake_empty_block_and_process_restart
```

## Condições para remover o bloqueio

Uma futura autorização de produção precisa ser baseada em evidência concreta,
no mínimo: circuito e entradas públicas versionados, árvore/raiz compatível com
o circuito, verificação de associação e conservação, regras completas de
chaves e assinatura, política de emissão auditável, testes adversariais,
fuzzing e auditoria criptográfica independente.

Uma direção de estudo para comunicação híbrida é exigir simultaneamente uma
troca clássica e uma pós-quântica (por exemplo, X25519 e ML-KEM-768), e combinar
os segredos por um KDF especificado; identidade também exigiria as duas
assinaturas, como Ed25519 e ML-DSA-65. Esta é somente uma direção de projeto,
não uma implementação ou aprovação no Noxis. ML-KEM e ML-DSA são padronizados
em [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) e
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final); a composição híbrida
precisa seguir uma especificação e análise próprias, como orienta
[SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final).
