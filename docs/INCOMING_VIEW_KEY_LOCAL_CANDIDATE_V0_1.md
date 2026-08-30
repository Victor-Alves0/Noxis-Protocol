# Chave de visualização de entrada local — candidata v0.1

## Estado

**Capacidade de leitura local executável, incluindo varredura de lote em
memória; não é uma view key exportável nem uma wallet persistente.**

`CandidateIncomingViewKeyV1` é uma autoridade separada que contém somente o
material híbrido necessário para abrir envelopes `NXRE` destinados a um único
endereço e o `H_ADDR` público esperado da nota. Ela não contém a chave de
nullifier, raiz de derivação, identidade do descriptor ou chave de gasto.

O caminho seguro é por consumo:

```text
CandidatePrivateRecipientKeysetV1
    └── into_incoming_view_key()
            └── CandidateIncomingViewKeyV1
```

Ao fazer a conversão, o keyset completo deixa de existir e sua chave de
nullifier é apagada. A view key resultante ainda consegue autenticar/decriptar
o envelope, recomputar `H_NOTE` e exigir o `H_ADDR` correto, mas não expõe uma
API para criar nullifier ou autorizar gasto.

## Demonstração

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- private-note

# varre três saídas locais: duas próprias e uma de terceiro
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- private-note-scan
```

O demo cria a nota, converte o keyset completo em view key de entrada e só
então abre a nota. O teste `incoming_view_key_scans_its_note_after_full_keyset_is_consumed`
confirma o mesmo limite em código.

O segundo comando percorre um lote limitado fornecido pelo próprio processo.
Ele devolve os índices locais das notas autenticadas para aquele destinatário,
ignora envelopes de terceiros ou não autenticados sem distingui-los e falha
fechado se uma nota autenticada não respeitar `H_NOTE` ou `H_ADDR`.

O crate `noxis-private-packet-validation` também já aplica essa leitura a um
`NXPT` canônico **depois** de conferir `H_ENVELOPE(slot, commitment, NXRE)`.
Esse caminho devolve o slot público da intenção, não uma posição de bloco, e
continua sem demonstrar que o pacote foi provado, aceito ou finalizado.

## O que isso resolve

Uma carteira poderá, no futuro, entregar esta capacidade a um processo de
escaneamento sem dar a ele a chave de nulificador. Isso é o primeiro requisito
prático de uma carteira observável e é uma separação melhor do que usar o
keyset completo para cada leitura.

O scanner não recebe nem produz uma chave de gasto. O resultado contém a nota
validada apenas na memória do processo e o índice dentro do lote do chamador;
ele não define posição de bloco, saldo ou estado de consenso.

## O que permanece proibido

- Não há serialização, exportação, importação, backup ou recuperação da view
  key.
- Não há fonte de blocos autenticada, descoberta sobre a cadeia,
  armazenamento de notas ou saldo. O scanner existente aceita somente um lote
  em memória fornecido pelo chamador, incluindo o lote de dois outputs de um
  `NXPT` localmente validado.
- Não há view key de saída; portanto pagamentos enviados não são auditáveis
  por esta capacidade.
- Não há transação, prova ZK, nullifier, assinatura de gasto, stealth address
  ou liquidação privada.
- Não se deve enviar o objeto de memória a um serviço externo: ainda falta um
  formato de segredo revisado, política de dispositivos e modelo de ameaça.

## Próximo gate

Definir uma fonte de blocos autenticada e sua regra de ancoragem antes de
transformar a varredura local em descoberta na cadeia. Em paralelo, definir o
formato de segredo real, política de dispositivos e modelo de ameaça antes de
qualquer exportação. A integração deverá testar que uma view key nunca alcança
a API de gasto, inclusive por serialização, desserialização ou substituição de
tipos.
