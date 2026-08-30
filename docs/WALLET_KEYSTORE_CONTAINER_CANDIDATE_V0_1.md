# Container de keystore de wallet — candidato v0.1

## Estado

**Parser público executável e cifra exercida apenas em fixture de teste. Nenhum
segredo de usuário é persistido ou exportado.**

O crate isolado `noxis-wallet-keystore` não depende de ledger, consenso,
endereços públicos ou `noxis-wallet-crypto`. Ele define o cabeçalho canônico
`NXKS v2` de uma futura raiz de wallet e testa internamente a combinação
Argon2id + XChaCha20-Poly1305 contra uma raiz sintética de 64 bytes.

Há somente um armazenamento de arquivo para o cabeçalho público, com lock e
publicação atômica. Não há API de importação/exportação de raiz, integração com
`CandidateWalletRootV1` nem container de segredo liberado em build normal.
Consequentemente, este trabalho não cria uma carteira persistente ou
custodiante.

## Cabeçalho `NXKS v2`

O cabeçalho tem exatamente 76 bytes, sempre em big-endian:

```text
magic:4 = "NXKS"
version:u16be = 2
kdf_id:u8 = 1 (Argon2id)
aead_id:u8 = 1 (XChaCha20-Poly1305)
memory_kib:u32be = 65536
time_cost:u32be = 3
lanes:u32be = 4
salt:16
wallet_id:32
key_epoch:u64be
```

O decoder aceita apenas esse perfil; não aceita algoritmo, versão, custo,
tamanho, magic, salt ou `wallet_id` nulos diferentes. Essa escolha evita que um arquivo
controle o custo da KDF e cause consumo de recursos arbitrário ou downgrade.
Os 76 bytes canônicos são o associated data obrigatório da cifra exercida no
fixture de teste: alterar época, ID da wallet, perfil ou salt impede a
autenticação.

O nonce de 24 bytes do XChaCha20-Poly1305 **não** pertence ao cabeçalho. Cada
payload cifrado futuro deverá carregar e autenticar seu próprio nonce único.
Isso impede reutilizar nonce com a mesma chave quando uma wallet for atualizada.
O layout experimental `NXKS v1` foi revogado por manter esse nonce no cabeçalho;
o parser o reconhece e o rejeita explicitamente. Como nunca houve payload de
segredo suportado, não existe migração automática de v1 para v2.

O perfil de 64 MiB, 3 passagens e 4 lanes segue a segunda recomendação de
Argon2id para contextos com menos memória do RFC 9106. Ele é um **perfil
candidato fixo**, não uma calibração final para todos os dispositivos.

## Evidência executável

```powershell
cargo test -p noxis-wallet-keystore --locked
cargo clippy -p noxis-wallet-keystore --all-targets --locked -- -D warnings
```

Os testes cobrem:

1. encode/decode canônico e rejeição de truncamento, magic e perfil alterados;
2. selagem e abertura de uma raiz **sintética** com Argon2id e
   XChaCha20-Poly1305;
3. rejeição indistinguível de senha errada, ciphertext adulterado e cabeçalho
   autenticado substituído.

## Limites de segurança e operação

- A fixture não grava arquivos e não recebe uma raiz de wallet real.
- O ciclo de vida **do cabeçalho público** já tem lock exclusivo, criação de
  arquivo temporário, `sync_all`, rename e recuperação somente de temporário
  completo/canônico. Um temporário truncado falha fechado. Isso não persiste
  segredo nem prova durabilidade de um payload futuro.
- Ainda não existe backup, recuperação de segredo, UX de senha ou suporte a
  dispositivos. A âncora externa `NXKA` define a política candidata de
  rollback, mas ainda não há payload secreto para protegê-la na prática.
- A senha nunca aparece nos erros, mas o modelo de memória do processo ainda
  precisa de revisão de plataforma.
- Os parâmetros não foram calibrados nos sistemas suportados; por isso não há
  contêiner de usuário habilitado.
- Um review independente continua obrigatório antes de qualquer fluxo com
  autoridade de gasto.

## Próximo gate

A política explícita de backup e rollback foi publicada em
[`WALLET_BACKUP_ROLLBACK_POLICY_CANDIDATE_V0_1.md`](WALLET_BACKUP_ROLLBACK_POLICY_CANDIDATE_V0_1.md).
O próximo trabalho é estender os testes de interrupção ao futuro arquivo de
payload secreto, usando o recibo externo `NXKA` já selecionado. Só então um
crate de persistência poderá receber uma raiz de sessão por uma interface
privada, sem tornar seus bytes parte de APIs de endereço, CLI ou transação.
