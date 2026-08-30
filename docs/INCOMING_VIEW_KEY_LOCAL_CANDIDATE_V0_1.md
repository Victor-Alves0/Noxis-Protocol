# Chave de visualização de entrada local — candidata v0.1

## Estado

**Capacidade de leitura local executável; não é uma view key exportável nem
uma wallet persistente.**

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
```

O demo cria a nota, converte o keyset completo em view key de entrada e só
então abre a nota. O teste `incoming_view_key_scans_its_note_after_full_keyset_is_consumed`
confirma o mesmo limite em código.

## O que isso resolve

Uma carteira poderá, no futuro, entregar esta capacidade a um processo de
escaneamento sem dar a ele a chave de nulificador. Isso é o primeiro requisito
prático de uma carteira observável e é uma separação melhor do que usar o
keyset completo para cada leitura.

## O que permanece proibido

- Não há serialização, exportação, importação, backup ou recuperação da view
  key.
- Não há scanner de blocos, descoberta de notas, armazenamento de notas ou
  saldo.
- Não há view key de saída; portanto pagamentos enviados não são auditáveis
  por esta capacidade.
- Não há transação, prova ZK, nullifier, assinatura de gasto, stealth address
  ou liquidação privada.
- Não se deve enviar o objeto de memória a um serviço externo: ainda falta um
  formato de segredo revisado, política de dispositivos e modelo de ameaça.

## Próximo gate

Definir o formato de keystore e backup antes de qualquer exportação. Depois,
adicionar descoberta de notas sobre uma fonte de blocos autenticada e testar
que uma view key nunca alcança a API de gasto, inclusive por serialização,
desserialização ou substituição de tipos.
