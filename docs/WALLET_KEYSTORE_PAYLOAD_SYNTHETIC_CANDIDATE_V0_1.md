# Payload cifrado sintético de keystore — candidato v0.1

## Estado

**Parser público e ciclo de vida em arquivo para ciphertext opaco; cifra exercida somente em testes. Não há API de produção para criar, desbloquear ou restaurar segredo.**

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

Nos testes e no demo explicitamente compilado com `research-testing`, a chave é derivada com o perfil Argon2id fixado pelo `NXKS v2`. O associated data é exatamente:

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

## Ciclo de vida sintético em arquivo

`CandidateKeystorePayloadStore` só pode ser aberto a partir do
`CandidateKeystoreHeaderStore` já bloqueado. Logo, cabeçalho e payload usam o
mesmo lock de escritor, sem criar um segundo dono concorrente do diretório.

Cada geração é imutável e recebe o nome canônico
`payload-<generation decimal de 20 dígitos>.nxkp`; por exemplo, a geração 7 é
`payload-00000000000000000007.nxkp`. A publicação cria primeiro o temporário
homólogo, sincroniza seus bytes e o renomeia para esse destino inexistente. Não
há overwrite atômico dependente da plataforma. Na reabertura, um temporário
canônico e completo é publicado; um temporário truncado, malformado ou ligado
a outro cabeçalho falha fechado.

O store limita o diretório a 32 gerações sintéticas, exige uma geração acima da
maior existente e recusa nonce que já apareça em outra geração retida. Para
leitura, o chamador fornece `NXKA`: o store abre exatamente o nome daquela
geração e exige coincidência de cabeçalho, geração e identificador de
ciphertext. Substituir bytes da geração 8 pelos da 7, ou restaurar diretório
sem a geração ancorada, não satisfaz o recibo externo mais novo.

## Limites deliberados

- Os arquivos `NXKP` carregam somente ciphertext sintético. A cifra e a abertura são privadas aos testes; o parser de release manipula ciphertext opaco e seus metadados públicos.
- O store aplica unicidade de nonce entre as gerações que ainda estão no diretório. A garantia ainda não cobre restauração a partir de um backup externo, concorrência hostil fora do lock, nem uma futura API de criação de payload real.
- Não há fluxo de cópia de backup, restauração de segredo ou UX de senha.
- Não existem seed, chave de gasto, view key, notas, saldo ou nullifier dentro do payload.

## Próximo gate

O bundle portátil `NXKB` agora cobre cópia e recuperação entre diretórios, sem
embutir `NXKA`. O próximo passo é uma demonstração operacional entre processos
e testes de interrupção da restauração de múltiplos arquivos. Só depois disso,
de um inventário de segredos e de revisão independente poderá existir uma
proposta de container com segredo real.
