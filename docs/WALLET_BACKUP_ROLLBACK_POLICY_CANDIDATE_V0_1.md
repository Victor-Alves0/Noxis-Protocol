# Política de backup e rollback de wallet — candidata v0.1

## Estado

**Recibo externo público e ciclo de vida de payload sintético executáveis;
nenhum backup de segredo ou restauração de wallet é implementado.**

O diretório atual persiste apenas o cabeçalho público `NXKS`. Cada cabeçalho
canônico agora tem um `KeystoreHeaderIdV1`:

```text
SHA-256(
  "NOXIS/KEYSTORE-HEADER-ID/V1\0"
  || encode(NXKS v2)
)
```

Esse ID é público e muda se qualquer byte canônico do cabeçalho mudar. Ele
pode ser anotado fora do diretório da wallet para confirmar que a identidade e
o perfil de uma wallet restaurada são os esperados. Ele não revela segredo,
não verifica senha e não prova que um payload secreto está atualizado.

## A limitação que não pode ser escondida

Se um atacante pode substituir todos os arquivos da wallet por uma cópia antiga
e também controla tudo o que a wallet usa para lembrar seu estado, **nenhum
contador apenas local detecta rollback**. Um contador, journal ou hash dentro
do mesmo diretório volta junto com a cópia antiga.

Logo, a proteção de rollback exige pelo menos uma âncora independente do
diretório principal. A primeira estratégia candidata selecionada é um recibo
binário externo mantido pelo usuário. Armazenamento seguro da plataforma e um
serviço de sincronização autenticado seguem como alternativas futuras, mas não
fazem parte desta entrega.

O usuário deve guardar o recibo em um local independente — por exemplo, uma
cópia de backup diferente, dispositivo separado ou cofre de senhas que preserve
arquivo — e não ao lado do diretório da wallet. Uma cópia no mesmo diretório
não protege contra rollback.

## Recibo externo `NXKA v1`

`ExternalRollbackAnchorV1` possui parser estrito e tamanho exato de 78 bytes:

```text
magic:4 = "NXKA"
version:u16be = 1
header_id:32
payload_generation:u64be
payload_ciphertext_id:32
```

Geração zero e identificador de ciphertext nulo são rejeitados. A estrutura
não contém senha, raiz, plaintext ou chave. Ela tampouco tem API de arquivo:
o chamador deve escolher um meio de armazenamento genuinamente externo.

## Contrato para o futuro payload secreto

Quando um payload criptografado for permitido, cada atualização deverá criar
uma nova geração monotônica, gerar um nonce XChaCha20-Poly1305 novo e único
para aquele payload, e produzir um recibo de backup externo contendo no mínimo:

```text
header_id:32
payload_generation:u64be
payload_ciphertext_id:32
```

O nonce faz parte dos bytes canônicos autenticados do `NXKP v1` sintético —
nunca do cabeçalho imutável `NXKS`. O `payload_ciphertext_id` é um hash com
domínio próprio sobre os bytes canônicos completos do payload cifrado, e **não** sobre plaintext. O recibo
deve ser registrado fora do diretório antes de a interface chamar a wallet de
“backup confirmado”. Na abertura/restauração:

1. a wallet compara `header_id` com a âncora externa;
2. ela exige geração exatamente igual à geração esperada;
3. ela exige o mesmo identificador do ciphertext para essa geração; e
4. se faltar âncora, houver geração menor ou identificador diferente, não
   libera qualquer operação de gasto.

Uma cópia mais nova pode exigir uma decisão explícita de recuperação; ela não
deve ser sobrescrita por uma cópia antiga automaticamente.

## Backup e recuperação

Um backup futuro terá de transportar o cabeçalho, o payload cifrado e seu
recibo externo como uma unidade. A senha e a raiz não serão copiadas em texto
claro. O procedimento de UX precisará dizer claramente que Noxis não consegue
recuperar uma senha esquecida ou uma âncora externa perdida.

A derivação de chave para proteger dados armazenados exige material de senha,
salt e parâmetros persistidos; este é o papel geral descrito por
[NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final). O perfil
Argon2id atual permanece candidato e precisa de calibração por plataforma.

## Evidência atual

```powershell
cargo test -p noxis-wallet-keystore --locked
```

Os testes confirmam que o ID do cabeçalho é estável após encode/decode e muda
quando a época muda. Eles também fazem round-trip de `NXKA` e rejeitam cabeçalho,
geração ou ciphertext diferentes. `NXKP v1` agora exercita essa ligação com
uma raiz sintética e seu ciclo de arquivo; ele ainda não prova backup,
restauração ou rollback de segredo.

## Próximo gate

O bundle `NXKB` agora transporta `NXKS + NXKP` entre diretórios, mantendo
`NXKA` externo; a repetição após publicar somente o cabeçalho já é idempotente.
Construir a demonstração e os testes de backup/restauração em processos
separados, incluindo término real de processo. Só após esses testes, inventário
de segredo e revisão independente a raiz de wallet poderá atravessar a fronteira
do keystore.
