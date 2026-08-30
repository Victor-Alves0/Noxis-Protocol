# Recebimento local de nota privada candidata v0.1

## Estado

**Evidência executável local, não uma wallet.** O crate
`noxis-wallet-crypto` consegue agora cifrar e recuperar em memória uma única
pré-imagem canônica de nota v2, usando o envelope híbrido `NXRE v1` existente.
O destinatário só aceita o resultado se ele também recomputar `H_NOTE` e
obtiver exatamente o commitment público associado à saída.

Isso é uma fronteira de cliente: não cria saldo persistente, não prova posse,
não gasta uma nota, não consulta estado e não autoriza uma transação.

## Executar

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- private-note
```

O programa gera chaves efêmeras, cifra uma pré-imagem de 178 bytes para um
endereço público diversificado, faz o round-trip estrito de `NXRE`, decripta no
dono e confere o commitment. Ele só imprime o commitment público e o tamanho
do envelope; não grava nem mostra a nota, ativo, valor, segredo ou ciphertext.

O modo `private-note` também usa o descriptor local autenticado: o remetente
confere que a pré-imagem carrega o `H_ADDR` assinado junto ao endereço, e a
wallet confere o mesmo valor depois de decriptar. Ver
[`RECIPIENT_DESCRIPTOR_LOCAL_CANDIDATE_V0_1.md`](RECIPIENT_DESCRIPTOR_LOCAL_CANDIDATE_V0_1.md).

## Regra que é realmente verificada

Para uma saída local `(cm, nxre)`:

```text
plaintext = Decrypt_NXRE(owner, context, nxre)
require len(plaintext) = 178
require H_NOTE(plaintext) = cm
accept plaintext locally
```

`NXRE` já autentica o contexto de rede, época de chave e conjunto de chaves do
destinatário, combinando X25519 e ML-KEM-768 antes de XChaCha20-Poly1305. A
comparação posterior de `H_NOTE` é independente dessa autenticação: ela recusa
um envelope válido que tenha sido trocado pelo envelope de outra nota.

Os testes cobrem tanto o recebimento válido quanto essa troca de commitment:

```powershell
cargo test -p noxis-wallet-crypto --locked private_note::tests
```

## Limites deliberados

- O `CiphertextDigestV2` que aparece na intenção `NXPU` ainda **não** é
  derivado dos bytes `NXRE`; portanto esta evidência não liga um envelope a uma
  intenção ou a uma prova de transferência.
- Não há AAD de saída canônica que inclua slot, commitment, intenção e contexto
  de transação. O contexto atual de `NXRE` é somente o perfil local de
  destinatário já documentado.
- Não existe descoberta de notas, base de dados de wallet, recuperação,
  sincronização com nó, chave de gasto, stealth address, prova ZK, inserção em
  `NXSM` ou gasto.
- O perfil permanece experimental e não é aprovado para custódia, rede pública
  ou alegação de anonimato/resistência pós-quântica do protocolo completo.
- O descriptor não prova uma derivação comum entre as chaves X25519/ML-KEM e a
  chave de nullifier; sua assinatura exige uma identidade de descriptor já
  confiável fora deste código.

## Próximo gate: digest de envelope

Antes de uma intenção ou AIR poder aceitar essa saída, o projeto precisa
especificar e congelar uma função separada para `CiphertextDigestV2`, com:

1. domínio Poseidon2 P24 próprio, distinto de `NOTE`, `ADDR` e `NULLIFIER`;
2. bytes canônicos exatos de `NXRE`, slot de saída, commitment e AAD;
3. regras de tamanho, versão e rejeição de ambiguidade;
4. vetores independentes e testes de alteração de cada campo; e
5. posterior vínculo dessa digest à intenção e à relação de prova.

Não é seguro improvisar esse mapeamento somente porque `CiphertextDigestV2`
é representado por dezesseis elementos BabyBear: domínio, packing e vetores
são propriedades de segurança, não detalhes de conversão de tipos.
