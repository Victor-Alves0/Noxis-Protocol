# Raiz de sessão da wallet — candidata local v0.1

## Estado

**Capacidade executável em memória; não é seed phrase, keystore, backup ou
recuperação de wallet.**

`CandidateWalletRootV1` é o tipo secreto que mantém uma raiz de 64 bytes
somente durante uma sessão local. Ele não oferece serialização, cópia pública
ou extração de bytes. Quando é descartado, seus bytes são apagados.

Uma raiz pode derivar quantos keysets de destinatário forem necessários:

```rust
let root = CandidateWalletRootV1::generate();
let first = root.derive_recipient_keyset(key_epoch, 0)?;
let next = root.derive_recipient_keyset(key_epoch, 1)?;
```

Para uma mesma raiz, época e índice, o endereço e `H_ADDR` são reproduzíveis.
Mudar época ou índice altera ambos. Isso permite uma wallet local criar vários
endereços sem criar segredos sem relação entre si.

## Separação de domínio

A derivação de cada filho usa o transcript já definido para a raiz de
destinatário, agora com:

```text
... || key_epoch:u64be || address_index:u32be || diversifier:16
```

O `address_index` vem depois da época e antes do diversificador. Ele faz parte
da KDF de diversificador, X25519, ML-KEM-768 e nullifier; portanto não é só um
contador de interface. Reutilizar a mesma raiz com índices distintos não
reutiliza a mesma chave de recebimento ou `H_ADDR`.

## Evidência executável

```powershell
cargo test -p noxis-wallet-crypto --locked
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- private-note
```

O teste `fixed_root_reproduces_one_address_and_separates_address_indexes`
verifica repetição para o mesmo índice e separação entre os índices `0` e `1`.
O demo deriva o destinatário de índice zero de uma raiz local, cria uma nota e
a abre com a view key de entrada sem nulificador.

## Limites

- Fechar o processo perde a raiz. Ainda não há backup ou recuperação.
- O índice não é persistido, sincronizado entre dispositivos ou protegido
  contra reutilização após reinício.
- O tipo ainda pode derivar o material de nullifier; não deve ser enviado a um
  scanner ou serviço remoto. Para leitura, use somente a view key local.
- Nenhuma derivação equivale a autorização de gasto, transação privada,
  stealth address ou ativação de privacidade.

## Próximo gate

Especificar um keystore que persista apenas a raiz com proteção por senha,
metadados autenticados, limites de custo, backup/rollback e recuperação. A
serialização da raiz não será adicionada ao tipo de wallet: ela deve pertencer
a um crate de keystore separado e revisável.
