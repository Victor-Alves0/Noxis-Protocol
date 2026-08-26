# Perfil criptográfico híbrido v1 — rascunho

## Limite de status

Este documento define direção de interoperabilidade e critérios de implementação. Não habilita ML-KEM, ML-DSA, assinatura híbrida, cifragem de notas ou transporte seguro no código atual. O perfil só poderá entrar em uma gênese nova após implementação, vetores, análise de canais laterais e auditoria independente.

## Separação de responsabilidades

O Noxis não criará handshake de transporte próprio. Para comunicação entre processos e nós, a direção é TLS 1.3 com o grupo padronizado `X25519MLKEM768`; ele fixa ordem, tamanho e combinação no [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html). ML-KEM é padronizado pelo [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), e ML-DSA pelo [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

Identidade de protocolo e envelopes de destinatário são construções diferentes de TLS. O RFC 10024 depende do transcript TLS e não pode ser copiado como receita para outro protocolo. Envelopes Noxis exigirão especificação e análise próprias, em consonância com [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final).

## Perfil proposto `noxis-hybrid-v1`

```text
transporte: TLS 1.3, X25519MLKEM768 obrigatório
identidade: Ed25519 + ML-DSA-65
assinatura: ambas obrigatórias (regra AND)
chaves de cifra de nota: X25519 + ML-KEM-768, distintas das de assinatura
```

`X25519` e `Ed25519` são definidos pelos [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) e [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html). Perfil híbrido nunca aceita assinatura clássica isolada. Enquanto CometBFT v0.38 usa chaves de validador Ed25519, a camada de consenso atual permanece clássica e não deve ser chamada de híbrida.

### Mensagem de identidade

As duas assinaturas cobrem a mesma mensagem canônica:

```text
domain = "NOXIS/IDENTITY-SIGN/V1"
protocol_version
chain_id
genesis_id
message_type
body_hash
crypto_profile_id
key_epoch
keyset_id
```

`keyset_id` é hash do conjunto completo de chaves públicas. Assim, ambas as assinaturas ficam vinculadas à mesma rede, mensagem, perfil e chaves; concatenar bytes de assinatura sem essa mensagem não é suficiente.

### Chave de destinatário e envelope

O contrato ainda não implementado é:

```text
RecipientKemKeySet {
  profile_id, key_epoch,
  x25519_public_key[32], ml_kem_768_public_key[1184]
}
RecipientEnvelope {
  ephemeral_x25519_public_key[32], ml_kem_768_ciphertext[1088],
  encrypted_payload
}
```

Um combiner futuro vincula em ordem fixa os dois segredos, chaves públicas, valores transmitidos, `profile_id`, `chain_id`, `key_epoch` e rótulo de domínio. HKDF é definido no [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html), mas usá-lo neste envelope é uma decisão de protocolo que exige vetores e auditoria.

## Downgrade, rotação e evidência

- `CryptoProfileId` entra na gênese/configuração e em todo payload assinado ou cifrado. Rede híbrida não negocia perfil por transação.
- Parser rejeita versão, tamanho, algoritmo, ordem ou campo desconhecido; cabeçalho canônico é AAD do AEAD futuro.
- `KeySet` declara `epoch`, altura de ativação, expiração e `keyset_id`. Atualização é assinada pelas duas chaves antigas e prova posse das duas novas.
- Ativação ocorre por altura de bloco, não pelo relógio local. Epoch e perfil nunca recuam; a janela da chave anterior é curta e explícita.
- Componentes não reutilizam chaves fora do mesmo perfil. Material efêmero e aleatoriedade são novos por sessão ou mensagem.

Uma implementação futura precisa de vetores FIPS 203/FIPS 204/RFC 7748/RFC 8032, interoperabilidade TLS real, segredo X25519 todo-zero tratado como falha, rejeição de assinatura parcial/tamanho inválido, testes de downgrade/rotação/rollback, fuzzing de decoder e auditoria independente.
