# Digest de envelope de destinatário — candidato v0.1

## Estado

**Candidato executável, não criptografia de protocolo ativada.** Esta entrega
define e calcula um `CiphertextDigestV2` candidato para um envelope híbrido
`NXRE v1`. O valor é uma saída Poseidon2 P24 de 16 elementos BabyBear
canônicos e pode preencher o campo público já existente em `PrivateTransferOutputV2`.

Nenhum decoder de `NXPT`, AIR, prova, ledger ou nó ainda recompõe esse digest
para aceitar uma transação. Portanto esta peça não autoriza liquidação nem
prova que uma intenção recebida contém envelopes corretos.

## Frame canônica

Para uma saída de posição `slot` e commitment `cm`, a única entrada válida é:

```text
frame_version:u16be = 1
output_slot:u8       = 0 ou 1
note_commitment:64   = NoteCommitmentV2, 16 BabyBear u32le canônicos
nxre_length:u16be
nxre:nxre_length     = encode_hybrid_recipient_envelope(NXRE v1)
```

O `NXRE` é primeiro serializado pelo encoder canônico e limitado pelos seus
próprios limites: payload cifrado entre 16 e 2.048 bytes, envelope total entre
1.210 e 3.242 bytes. A frame tem, por isso, entre 1.279 e 3.311 bytes.

O comprimento explícito elimina a ambiguidade que `BytePack3LE` teria para
zeros no último grupo. O slot impede reutilizar o mesmo envelope/commitment em
outro output da declaração 2×2; o commitment impede associar o envelope válido
à nota pública errada.

## Função candidata

```text
H_ENVELOPE(frame) = Poseidon2-BabyBear-P24(
  IV("NOXIS/POSEIDON2-PRIVACY/V1/RECIPIENT-ENVELOPE-DIGEST\0"),
  BytePack3LE(frame),
  squeeze 16 elementos
)
```

O IV é derivado por SHA-256 com rejeição de elementos fora do campo, a partir
do ID completo do candidato pai `NXPH`; ele usa prefixo de KDF e rótulo próprios.
O descritor também tem um ID candidato independente. Ele é código de pesquisa,
não um novo formato de rede ou armazenamento e não recebe magic `NX..`.

## Executar

```powershell
cargo run -p noxis-wallet-crypto --bin noxis-wallet-crypto-demo -- private-note
cargo test -p noxis-tree-params -p noxis-poseidon2-privacy-reference -p noxis-wallet-crypto --locked
```

O demo mostra um digest público depois de a wallet local cifrar uma nota,
redecodificar `NXRE` e confirmar `H_NOTE`. Os testes verificam estabilidade
após round-trip canônico e mudança de digest quando se modifica slot,
commitment ou envelope.

## O que falta antes de confiar nele

- Vetores produzidos por uma implementação externa independente do P24 e uma
  revisão do transcript/IV/frame.
- Um verificador de pacote que redecodifique os dois `NXRE`, recompute os dois
  digests e os compare aos dois campos da intenção **antes** de qualquer AIR.
- Vínculo dessa verificação ao `NXPT`, à intenção `H_INTENT`, à AIR de
  transferência e a uma política de AAD de transação selecionada.
- Fuzzing direcionado ao limite de 3.311 bytes, à canonicidade do envelope e a
  alterações de todos os campos públicos.

Até esses gates, X25519 + ML-KEM-768 protege apenas o envelope local que já
existe; não torna a rede, o consenso, a wallet ou o protocolo inteiro
resistentes a computação quântica.
