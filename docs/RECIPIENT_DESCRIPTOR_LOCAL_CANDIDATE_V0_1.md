# Descriptor local de destinatário — candidato v0.1

## Estado

**Capacidade local autenticada, não uma identidade de gasto.**
`CandidatePrivateRecipientKeysetV1` gera, no mesmo processo, uma raiz
aleatória efêmera e dela deriva:

- uma chave de recebimento X25519 + ML-KEM-768 para `NXRE`;
- uma chave de nullifier privada, da qual `H_ADDR` deriva o
  `RecipientCommitmentV2`; e
- uma identidade Ed25519 + ML-DSA-65 separada, usada para assinar o descriptor
  público.

O descriptor contém o endereço público de recebimento e o commitment `H_ADDR`.
O transcript assinado é exatamente:

```text
"NOXIS/CANDIDATE-RECIPIENT-DESCRIPTOR/V1\0"
|| nxpa_length:u16be
|| encode_payment_address(NXPA v1)
|| recipient_commitment:64
```

O par de assinaturas verifica que os dois valores foram apresentados juntos por
a identidade do descriptor. Um remetente que já confia nessa identidade pode
verificar o descriptor e só cifra uma nota cuja região `recipient_commitment`
na pré-imagem de 178 bytes seja igual ao valor assinado.

## O que a wallet passa a recusar

Depois de decriptar e recomputar `H_NOTE`, o keyset local também lê os bytes
50..114 da nota e exige o mesmo `RecipientCommitmentV2` que ele próprio criou.
Logo, uma nota cifrada para a chave de recebimento correta, mas com commitment
de gasto de outro destinatário, não entra como nota local válida.

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- private-note
```

O demo agora exerce descriptor assinado, `H_NOTE`, `NXRE`, digest de envelope e
a confirmação do commitment de destinatário. Os testes também cobrem a recusa
de commitment de outro keyset.

## Limite de segurança crucial

Neste keyset local, a chave X25519/ML-KEM e a chave de nullifier são derivadas
de uma mesma raiz efêmera, com rótulos HKDF distintos. Porém, o descriptor
**não prova publicamente** essa relação: um remetente, nó ou verificador STARK
não recebe a raiz nem uma prova dela. A assinatura continua apenas autenticando
a declaração conjunta para uma identidade que o remetente já conhece por outro
canal. A derivação completa e seus limites estão em
[`RECIPIENT_ROOT_DERIVATION_CANDIDATE_V0_1.md`](RECIPIENT_ROOT_DERIVATION_CANDIDATE_V0_1.md).

Ele também não tem encoding público, diretório confiável, rotação, backup ou
política de confiança. Portanto não é stealth address, chave de gasto, prova
ZK de posse, wallet persistente nem defesa completa contra substituição de
descriptor em uma distribuição não autenticada.

## Próximo gate

Antes de promover esse vínculo a protocolo, é necessário especificar a
derivação e o keystore de forma recuperável, criar chaves de visualização sem
autoridade de gasto e decidir como a relação aparece no AIR ou em uma prova de
posse. Isso exige vetores independentes para X25519 e ML-KEM, formato público,
KDF, rotação, recuperação, revogação e revisão antes de qualquer ativação.
