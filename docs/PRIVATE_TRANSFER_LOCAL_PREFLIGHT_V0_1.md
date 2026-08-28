# Pré-validação local de transferência privada 2×2 — candidata v0.1

## Propósito

`noxis-note-opening::CandidatePrivateTransferWitnessV2` executa localmente as
relações candidatas que uma futura AIR deverá provar para uma transferência de
dois inputs e dois outputs. O objeto retém dados secretos somente em memória,
não tem codec, não cria prova, não atualiza estado e não autoriza o ledger.

Ele recebe a `PrivateTransferIntentV2` canônica de 640 bytes, duas
`SpendingWitnessV2` e duas `NoteOpeningV2` de saída. A construção falha antes
de reter a witness se qualquer relação abaixo não for satisfeita.

## Relações verificadas

1. `TreeParametersId` da intenção é igual ao adaptador local derivado dos bytes
   do manifesto P24 candidato congelado;
2. cada input revalida `H_ADDR`, `H_NOTE`, `H_NULLIFIER`,
   `H_LEAF(H_NOTE(...))` e seu caminho de profundidade 32 até exatamente
   `pre_state_root`;
3. nullifiers dos inputs e commitments dos outputs são iguais, na mesma ordem,
   aos campos públicos da intenção;
4. os quatro `asset_id` privados são iguais ao único ativo público da intenção;
5. `in[0] + in[1] == out[0] + out[1]`, sempre com `checked_add` em `u128`;
6. input de valor zero é rejeitado; saída zero só pode existir se foi criada
   explicitamente como padding;
7. a mesma nota/posição não pode aparecer duas vezes como input, uma saída não
   pode reapresentar um commitment de input e `rho`/`rcm` não se repetem entre
   as quatro aberturas locais.

O adaptador do item 1 é apenas coerência de uma execução de pesquisa: ele não
transforma o ID P24 em parâmetro selecionado, allowlisted ou elegível para
consenso.

## Limites deliberados

O preflight não cria nem valida prova STARK/AIR, não deriva um
`TransactionIntentId` v2, não verifica envelope KEM/AEAD, não liga os
`ciphertext_digest` a bytes de envelope e não verifica nullifier contra um
estado global. Ele também não prova unicidade global de `rho` ou `rcm`.

Portanto, alterar `circuit_id`, gênese, contexto de validação, `pre_state_id`
ou digest de envelope muda a intenção canônica armazenada, mas ainda não recebe
um compromisso criptográfico aritmetizado nesta etapa. Essa ligação é uma
pré-condição obrigatória para a AIR, e não pode ser substituída por este
verificador local.

## Testes

Os testes cobrem uma transferência 20+30 para 50+0 (padding), caminhos para as
duas posições da mesma raiz, conservação inválida, troca de parâmetro
candidato, nullifier trocado e commitment de saída trocado. Os testes de nota
subjacentes cobrem chave incorreta, caminho alterado, raiz alterada e mutações
das regiões do preimage.

## Próximo passo

Especificar e congelar o compromisso canônico dos 640 bytes da intenção que a
AIR conseguirá verificar. Somente depois a declaração local poderá ser
traduzida para traços, colunas e restrições de uma prova candidata.
