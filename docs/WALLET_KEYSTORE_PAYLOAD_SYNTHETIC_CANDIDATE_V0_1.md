# Payload cifrado sintético de keystore — candidato v0.1

## Estado

**Parser público de ciphertext opaco e cifra exercida somente em testes. Não há API de produção para criar, desbloquear, gravar ou restaurar segredo.**

`NXKP v1` torna verificável a unidade que uma futura política de backup terá de identificar: um payload cifrado associado a um cabeçalho `NXKS v2`, a uma geração monotônica e a um nonce próprio. Ele usa uma raiz sintética de 64 bytes somente dentro dos testes de `noxis-wallet-keystore`; nenhum tipo secreto de wallet cruza esta fronteira.

O formato existe separado do cabeçalho porque os dois têm ciclos de vida diferentes: `NXKS` é identidade pública imutável, enquanto `NXKP` será a geração substituível do conteúdo cifrado. Reutilizar `NXKS` para ambos tornaria o contrato de nonce, atualização e rollback ambíguo.

## Formato canônico `NXKP v1`

O payload tem exatamente 150 bytes, sempre em big-endian onde há inteiros:

```text
magic:4 = "NXKP"
version:u16be = 1
header_id:32
payload_generation:u64be
nonce:24
ciphertext:80
```

`ciphertext` é, nesta entrega, apenas a cifra autenticada de uma raiz sintética de 64 bytes sob XChaCha20-Poly1305 (64 bytes + tag de 16 bytes). Um payload de segredos reais exigirá nova versão, inventário de segredos e revisão independente; `NXKP v1` não pode ser reinterpretado para isso.

O decoder exige tamanho e EOF exatos, magic e versão exatos, geração não nula e nonce não nulo. Ele não tenta decriptar nem expõe plaintext em builds normais.

## Vínculos criptográficos exercidos

Nos testes, a chave é derivada com o perfil Argon2id fixado pelo `NXKS v2`. O associated data é exatamente:

```text
"NOXIS/KEYSTORE-PAYLOAD-AAD/V1\0"
|| encode(NXKS v2)
|| encode(NXKP v1)[0..70]
```

Assim, a autenticação cobre o cabeçalho inteiro, o `header_id`, a geração e o nonce antes do ciphertext. Trocar qualquer um desses campos ou a senha falha a abertura sintética. Cada nova geração de teste recebe nonce distinto; o nonce fica no payload, nunca no cabeçalho imutável.

O identificador levado pelo recibo externo `NXKA` é:

```text
SHA-256(
  "NOXIS/KEYSTORE-PAYLOAD-CIPHERTEXT-ID/V1\0"
  || encode(NXKP v1)
)
```

Logo o recibo compromete geração, nonce e ciphertext, sem comprometer plaintext. A verificação também exige que `header_id == id(NXKS)` antes de uma abertura futura.

## Evidência executável

```powershell
cargo test -p noxis-wallet-keystore --locked
cargo clippy -p noxis-wallet-keystore --all-targets --locked -- -D warnings
```

Os testes cobrem round-trip canônico, truncamento, geração/nonce ausentes, senha errada, ciphertext adulterado, cabeçalho substituído, nova geração com nonce distinto e rejeição de uma geração antiga pelo recibo externo mais novo.

## Limites deliberados

- Não existe arquivo `NXKP`, diretório de backup, restauração ou UX de senha.
- A cifra e a abertura são privadas aos testes; o parser de release manipula somente ciphertext opaco e seus metadados públicos.
- Não há garantia mecânica de unicidade de nonce entre execuções porque não há armazenamento de geração nem emissor de nonce persistente. Essa garantia é requisito do próximo ciclo de vida de arquivo, não uma alegação desta fixture.
- Não existem seed, chave de gasto, view key, notas, saldo ou nullifier dentro do payload.

## Próximo gate

Adicionar um ciclo de vida de arquivo **ainda sintético**: publicação atômica de uma geração `NXKP`, recuperação de temporário, comparação obrigatória com um `NXKA` fornecido fora do diretório e testes de interrupção/rollback. Somente depois desses testes e de revisão independente poderá existir uma proposta de container com segredo real.
