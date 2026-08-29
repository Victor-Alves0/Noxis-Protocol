# Transição de nullifiers `NXSM` para transferência privada — candidata v0.1 (`NXNT`)

`NXNT v1` é o contrato público executável que falta entre uma intenção privada
e uma AIR futura: ele mostra como os dois nullifiers de uma intenção 2×2 mudam
uma raiz esparsa `NXSM` antes/depois. Não contém uma prova, não expõe uma
testemunha de nota e não movimenta valor.

## Relação que é verificada hoje

Para uma `PrivateTransferIntentV2`, uma âncora `NXPS v2` e uma árvore `NXSM`
prévia, `CandidateNxsmNullifierTransitionV1` exige:

1. a intenção coincide exatamente com a gênese, contexto, parâmetros, raiz de
   notas e `StateId` da âncora;
2. a raiz e a contagem da árvore fornecida coincidem com a âncora;
3. cada um dos dois nullifiers públicos está ausente da raiz prévia;
4. as duas inserções canônicas são aplicadas em uma cópia da árvore; e
5. a raiz posterior e a contagem posterior (`prévia + 2`) são registradas junto
   do `H_INTENT` rederivado dos 640 bytes canônicos da intenção.

A API também reexecuta a relação e compara todos os campos públicos antes de
entregá-los a um futuro provador. A ausência é conferida hoje sobre estado
transparente em memória. A interface local
[`CandidateNxsmNullifierTransitionWitnessV1`](PRIVATE_TRANSFER_WITNESS_CONSTRAINT_INTERFACE_CANDIDATE_V0_1.md)
agora mantém os dois caminhos de 512 irmãos em sequência: o segundo começa na
raiz intermediária após a primeira inserção.

## Frame público canônico

O frame `NXNT v1` tem 408 bytes e sua identidade é SHA-256 com domínio
`NOXIS/NXSM-NULLIFIER-TRANSITION-ID/V1\0`:

```text
magic NXNT | version:u16be=1 | reserved[2]
| nxsm_candidate_id[32] | pre_state_id[32]
| pre_nxsm_root[64] | pre_spent_count:u64be
| post_nxsm_root[64] | post_spent_count:u64be
| nullifier_0[64] | nullifier_1[64] | H_INTENT[64]
```

Os nullifiers já obedecem a ordem canônica da intenção. O ID da candidata
`NXSM` impede que uma implementação substitua silenciosamente outra árvore ou
outros IVs. O `pre_state_id` é o de `NXPS v2`, portanto a relação está ligada
ao contexto de notas; ele não deve ser interpretado como estado do ledger v1.

## O que a relação ainda não prova

- Não prova em zero conhecimento a posse, a abertura ou a inclusão das notas.
- Não atualiza a raiz de notas nem cria uma âncora `NXPS v2` posterior; essa
  parte precisa da relação completa de entradas e saídas.
- Não serializa estado, aceita pacotes de rede, seleciona um STARK ou verifica
  proofs.
- Não é compatível com liquidação do ledger v1, consenso ou produção.

O próximo trabalho de prova deve transformar a
[interface de witness e restrições](PRIVATE_TRANSFER_WITNESS_CONSTRAINT_INTERFACE_CANDIDATE_V0_1.md)
em uma AIR: caminhos de ausência, derivação de nullifier e atualização de raiz
devem ser avaliados dentro do circuito junto das restrições de notas, valores
e saídas.
