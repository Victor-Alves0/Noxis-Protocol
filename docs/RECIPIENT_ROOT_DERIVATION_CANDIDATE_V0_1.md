# Derivação de raiz do destinatário — candidato v0.1

## Estado

**Capacidade local executável; não é uma especificação de keystore nem uma
garantia verificável pela rede.**

`CandidatePrivateRecipientKeysetV1` agora cria uma raiz aleatória de 64 bytes
em memória e, a partir dela, deriva:

1. um diversificador público de endereço;
2. a semente X25519 de 32 bytes para recebimento;
3. a semente ML-KEM-768 de 64 bytes para recebimento; e
4. a chave privada de nullifier de 32 bytes, que alimenta `H_ADDR`.

Assim, no processo local que construiu o keyset, o endereço que recebe uma
nota e o commitment exigido na relação privada de posse têm uma origem secreta
única. A raiz é apagada depois da construção. A identidade híbrida que assina
o descriptor continua separada: ela autentica uma declaração pública; ela não é autoridade
de gasto.

## Derivação exata

Para uma raiz `root:64` recém-gerada pelo CSPRNG do sistema, a implementação
usa HKDF-SHA-256 com:

```text
salt = "NOXIS/CANDIDATE-RECIPIENT-ROOT/V1/SALT\0"
info = "NOXIS/CANDIDATE-RECIPIENT-ROOT/V1\0"
     || component_label
     || key_epoch:u64be
     || diversifier:16                 (exceto ao derivar o diversificador)
```

Os `component_label` canônicos são `DIVERSIFIER\0`, `NULLIFIER\0`,
`X25519\0` e `ML-KEM-768\0`. Primeiro derivamos `DIVERSIFIER` com apenas
`key_epoch`; todos os demais filhos incluem esse diversificador no `info`.
Os quatro rótulos impedem que a mesma sequência de bytes seja reutilizada em
duas funções de chave.

A saída ML-KEM-768 é fornecida à interface determinística de semente de 64
bytes da biblioteca. Esse modelo corresponde à entrada `(d, z)` definida para
a geração interna ML-KEM por FIPS 203; a FAQ do NIST também reconhece esse par
de sementes como formato alternativo de material de chave. Isto não equivale,
por si só, a uma seleção de biblioteca ou aprovação do protocolo.

## Evidência executável

```powershell
cargo test -p noxis-wallet-crypto --locked
```

Os testes verificam que a mesma raiz de teste e o mesmo `key_epoch` reproduzem
o mesmo `H_ADDR` e `address_id`, e que mudar somente `key_epoch` muda ambos.
Também continuam verificando cifra híbrida, decoder estrito e a rejeição de
uma nota cujo `H_ADDR` não é o do destinatário local.

## Limites deliberados

- A raiz não é serializada, exportada, persistida ou recuperável. Não existe
  backup de wallet.
- O descriptor público não revela nem prova a derivação. Um nó, remetente ou
  verificador STARK só vê o endereço e `H_ADDR` assinados.
- A relação raiz→chaves ainda não aparece no AIR nem na prova de transferência.
- Há uma chave de visualização de entrada local, separada e não exportável.
  Ela abre `NXRE` e valida `H_NOTE`/`H_ADDR`, mas não contém a chave de
  nullifier. Ver
  [`INCOMING_VIEW_KEY_LOCAL_CANDIDATE_V0_1.md`](INCOMING_VIEW_KEY_LOCAL_CANDIDATE_V0_1.md).
- Não há chave de gasto, derivação de mudança, visão de saída, rotação,
  revogação, stealth address, carteira persistente ou transação privada.
- Este candidato não recebe aprovação para custódia, rede pública ou ativação
  de privacidade.

## Próximo gate: exportação de view key e keystore

Antes de exportar uma view key, o projeto precisa especificar três autoridades
distintas e testá-las isoladamente:

| Material | Pode fazer | Não pode fazer |
| --- | --- | --- |
| Chave de visualização de entrada | detectar e abrir envelopes/notas destinadas ao usuário | criar nullifier, autorizar gasto ou recuperar a raiz |
| Chave de visualização de saída (se adotada) | auditar pagamentos enviados | abrir entradas de terceiros ou gastar |
| Chave de gasto/nullifier | autorizar uma transação privada | ser entregue a um explorador, servidor ou dispositivo de leitura |

Isso exige um formato de keystore/backup revisado, inventário de segredos,
política de rotação, limites de parser, vetores independentes e revisão de
segurança. Até lá, o separador de domínio deste documento é local e candidato,
não um compromisso de compatibilidade de longo prazo.
