# Perfil de restrições AIR para transferência privada — candidata v0.1 (`NXAR`)

## O que este perfil resolve

`NXAR v1` é um artefato canônico de 152 bytes que congela a forma e o conjunto
de restrições que um futuro programa AIR deverá implementar para a transferência
privada 2×2. Ele reduz o risco de uma integração “quase igual”: o backend não
pode escolher silenciosamente outra profundidade, aridade, árvore ou subconjunto
de regras.

Ele não é programa AIR, STARK, prova, chave verificadora, `CircuitId`,
`ProofVerifierId` nem seleção de produção. O serviço continua fail-closed.

## O que fica congelado

| Item | Valor em `NXAR v1` |
| --- | --- |
| Declaração pública composta | `NXPU v1`, 1.440 bytes |
| Moldura pública de notas | 230 elementos: 214 de intenção e 16 de `H_INTENT` |
| Forma da transferência | 2 inputs, 2 outputs |
| Caminho de notas | profundidade 32 |
| Caminho `NXSM` | profundidade 512, primeiro → intermediário → posterior |
| Valores | quatro limbs `u32` para cada `u128` |
| Ancestrais | IDs exatos da candidata P24, `NXSM` e `NXPD v1` |

O perfil também fixa dez famílias de restrições: bytes/`H_INTENT` canônicos,
inclusão de notas, derivação de nullifier, abertura de saídas, conservação de
valor, unicidade, ausência do primeiro nullifier, raiz intermediária, raiz
posterior e vínculos cruzados de `NXPU`.

## Formato e identidade

```text
magic NXAR | version:u16be=1 | reserved[2]
| nxpu_bytes:u16be | public_elements:u16be | intent_elements:u16be
| digest_elements:u8 | input_count:u8 | output_count:u8 | note_depth:u8
| nxsm_depth:u16be | value_u32_limbs:u8 | constraint_mask:u16be | reserved
| p24_candidate_id[32] | nxsm_candidate_id[32] | nxpd_candidate_id[32]
| checksum[32]
```

O checksum e o ID candidato são SHA-256 com domínios separados. O decoder aceita
somente os bytes canônicos rederivados dos artefatos locais; mudar um bit de um
limite, máscara ou ID é recusado.

## O que vem depois

O próximo passo técnico é implementar as mesmas famílias de restrições em um
programa AIR concreto e comparar seus resultados contra a referência Rust e
vetores externos. A escolha de backend STARK, FRI, transcript e parâmetros só
deve acontecer junto desse programa e de sua revisão criptográfica.
