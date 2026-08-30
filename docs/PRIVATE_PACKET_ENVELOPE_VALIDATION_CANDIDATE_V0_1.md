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

## Executar

```powershell
cargo run -p noxis-private-packet-validation --bin noxis-private-packet-validation-demo
```

O demo constrói um `NXPT` local com duas saídas, verifica os dois digests e
então troca os envelopes de posição. A primeira etapa é aceita; a troca é
rejeitada como `DigestMismatch(slot 0)`.

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

## O que esta fronteira não faz

- não verifica a prova opaca, `H_INTENT`, posse, inclusão Merkle, nullifiers,
  conservação ou transição `NXSM`;
- não decripta `NXRE`, descobre notas, cria saldo ou possui chave privada;
- não é invocada pelo ledger, mempool, CometBFT ou nó;
- ainda usa um candidato P24 sem vetores de uma implementação externa
  independente e sem auditoria criptográfica.

Portanto ela melhora a integridade operacional do pacote de pesquisa, mas não
ativa transferências privadas, anonimato, custódia ou segurança pós-quântica do
protocolo completo.

## Próximo gate

O próximo passo é deixar o preflight privado consumir este recibo, exigindo que
o mesmo `NXPT` validado forneça a intenção usada por `H_INTENT` e pelas relações
de posse/saída. Depois disso ainda serão necessários vetores externos, uma AIR
única, verificador de prova, estado e uma decisão explícita de ativação.
