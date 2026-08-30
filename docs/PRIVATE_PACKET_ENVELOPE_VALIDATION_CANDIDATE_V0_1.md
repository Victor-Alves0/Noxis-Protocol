# Validação de envelopes em pacote privado — candidata v0.1

## Estado

**Fronteira executável local, não uma regra de consenso.**
`noxis-private-packet-validation` une três responsabilidades já separadas:

```text
NXPT bytes        -> noxis-codec (estrutura e limites)
NXRE bytes        -> noxis-wallet-crypto (parser canônico)
slot/cm/NXRE      -> H_ENVELOPE candidato P24
```

Ela só devolve um recibo de validação se os dois envelopes do `NXPT` forem
`NXRE v1` estritos e se os dois digests recomputados forem exatamente iguais
aos campos dos dois outputs da intenção.

Sobre esse recibo, ela também pode agora entregar as duas posições ao scanner
de uma `CandidateIncomingViewKeyV1`. A ordem é deliberada: a wallet só tenta
abrir um envelope depois de confirmar que os bytes exatos daquele `NXRE` estão
amarrados, por `H_ENVELOPE`, ao commitment e ao slot público da intenção.

## Executar

```powershell
cargo run -p noxis-private-packet-validation --bin noxis-private-packet-validation-demo
```

O demo constrói um `NXPT` local com duas saídas, verifica os dois digests e
então troca os envelopes de posição. A primeira etapa é aceita; a troca é
rejeitada como `DigestMismatch(slot 0)`. Ele também converte a chave do
primeiro destinatário em incoming view key: ela encontra somente uma das duas
notas, sem receber nullifier ou autoridade de gasto.

## Ordem de rejeição

1. o codec recusa um `NXPT` malformado, longo, truncado ou com intenção inválida;
2. a fronteira recusa cada envelope que não seja `NXRE v1` estrito;
3. ela reencoda o `NXRE` e exige igualdade byte a byte, evitando normalização
   silenciosa antes do hash;
4. ela calcula `H_ENVELOPE(slot, commitment, nxre)` para cada posição; e
5. compara os valores com `intent.outputs()[slot].ciphertext_digest()`.

Assim, um envelope válido colocado no slot errado, um envelope associado a
outro commitment, ou bytes opacos que apenas caibam no limite de `NXPT` são
rejeitados antes de qualquer processamento de prova.

Depois dessa validação, o scanner trata um erro de autenticação de envelope
como saída de terceiro/não autenticada e não revela qual dos dois casos ocorreu.
Uma saída que autentique, mas falhe em `H_NOTE` ou `H_ADDR`, faz todo o scan do
pacote falhar fechado. O resultado carrega somente o slot canônico `0` ou `1`
e a nota em memória; não é posição de bloco nem recibo de aceitação.

## O que esta fronteira não faz

- não verifica a prova opaca, `H_INTENT`, posse, inclusão Merkle, nullifiers,
  conservação ou transição `NXSM`;
- não verifica a prova opaca, nem torna o pacote aceito: o scanner de entrada
  só decripta localmente depois do vínculo envelope/commitment e não cria
  saldo, armazenamento ou autoridade de gasto;
- não é invocada pelo ledger, mempool, CometBFT ou nó;
- ainda usa um candidato P24 sem vetores de uma implementação externa
  independente e sem auditoria criptográfica.

Portanto ela melhora a integridade operacional do pacote de pesquisa, mas não
ativa transferências privadas, anonimato, custódia ou segurança pós-quântica do
protocolo completo.

## Próximo gate

O preflight privado já consome este recibo e exige a mesma intenção usada por
`H_INTENT` e pelas relações de posse/saída. A evidência e os limites estão em
[`PACKET_BOUND_STARK_PREFLIGHT_RESEARCH_V0_1.md`](PACKET_BOUND_STARK_PREFLIGHT_RESEARCH_V0_1.md).

Depois disso ainda serão necessários verificador de prova, admissão ao estado,
inclusão/finalidade autenticada, fonte de blocos para a wallet, armazenamento
de notas, vetores externos, AIR única e uma decisão explícita de ativação.
