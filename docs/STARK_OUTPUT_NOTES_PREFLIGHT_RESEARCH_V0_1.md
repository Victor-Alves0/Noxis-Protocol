# Preflight STARK de duas notas de saída — pesquisa v0.1

## O que é executável agora

`noxis-private-proof-contract` disponibiliza
`run_candidate_intent_output_notes_preflight`. Para uma declaração pública
canônica `NXPU v1`, ela executa e verifica, nesta ordem:

1. uma prova local de `H_INTENT` sobre os 640 bytes públicos da intenção;
2. uma prova privada de `H_NOTE` com vínculo de `asset_id` para a saída no slot canônico 0;
3. uma prova privada de `H_NOTE` com vínculo de `asset_id` para a saída no slot canônico 1.

Cada resultado `H_NOTE` é convertido de forma estrita para
`NoteCommitmentV2`, comparado ao commitment já presente no mesmo slot e tem
seus bytes públicos de ativo comparados ao único `asset_id` da intenção. As
três provas opacas são verificadas e descartadas antes de o
preflight devolver seu recibo público. A revalidação posterior repete todos os
vínculos públicos e de estado candidato, mas não tenta fingir que pode verificar
provas que já foram descartadas.

A witness `CandidateOutputNoteWitnessV1` só existe em memória e não possui
codec. Isso evita que esta camada, cujo papel é ligar relações de prova, passe
a ser acidentalmente uma camada de persistência de segredos.

## O que isso demonstra, em linguagem simples

Uma transação candidata já declara dois "recibos" públicos de saída
(commitments). Agora o código consegue receber as duas notas secretas e provar,
separadamente, que cada uma realmente produz exatamente o recibo declarado.
Trocar uma nota, inverter os slots ou alterar um commitment público causa
rejeição fechada.

Esta é uma ligação operacional entre o formato canônico da transação e suas
duas saídas privadas; não é apenas uma descrição da relação futura.

## Limites de segurança deliberados

Este preflight **não** é uma prova de transferência privada, prova agregada,
prova recursiva, artefato portátil ou autorização do ledger. Em especial, ele
ainda não prova:

- a semântica interna restante da abertura (valor, destinatário, `rho` e `rcm`);
- conservação de valores em zero knowledge;
- que o digest de ciphertext corresponde a um envelope cifrado da nota;
- inserção das saídas na árvore de notas ou uma atualização atômica do estado;
- ausência global de nullifier, posse das entradas ou anonimato de remetente.

`noxis-note-opening` continua contendo a verificação semântica local das
aberturas, inclusive conservação, mas ele não é dependência deste crate: fazer
isso criaria um ciclo entre o contrato de prova e seu consumidor local. A
composição criptográfica completa precisa absorver essas relações em uma AIR
única, revisada e com backend selecionado.

## Verificação

```powershell
cargo test -p noxis-private-proof-contract output_notes::tests::locally_binds_two_private_output_notes_to_one_canonical_intent --locked
```

O teste forma duas notas privadas distintas, ordena seus commitments conforme a
regra canônica da intenção, prova `H_INTENT` uma vez e `H_NOTE` duas vezes, e
revalida o recibo. Um teste separado cobre a rejeição de um resultado retido no
slot público errado.

## Próximo passo correto

O próximo passo técnico é uma AIR composta que ligue, no mesmo sistema de
restrições, intent, duas posses das entradas, duas aberturas das saídas,
conservação de valor e a transição `NXSM`. Antes dela, ainda é necessário
definir o envelope de saída e a inserção atômica das novas notas no estado
privado v2.
