# Snapshot de estado privado candidato v0.1

Este marco introduz uma representacao local e deterministica do estado privado
candidato. Ele existe para tornar verificavel a base de dados que uma futura
prova privada devera representar, sem conectar esse experimento ao ledger
SHA-256 atual.

## O que ele armazena

`noxis-private-state` mantem, somente em memoria:

- os commitments de notas, preservando a ordem de insercao;
- os nullifiers ja gastos, em ordem canonica;
- uma raiz Merkle de 64 bytes obtida com a referencia Poseidon2 P24; e
- um identificador de snapshot derivado da raiz, das contagens e de todo o
  conteudo canonico.

A arvore tem profundidade 32 e usa os valores vazios publicados pela referencia
P24. Para manter o marco pequeno e facilmente auditavel, aceita no maximo 1.024
notas. Commitments ou nullifiers duplicados sao rejeitados.

## Limites de seguranca intencionais

Isto **nao** e uma implementacao de transicao de estado, persistencia,
sincronizacao de rede nem um verificador de provas. Em especial, nao ha metodo
para aplicar uma transferencia, marcar uma nota como gasta ou aceitar uma prova
opaca.

O campo `pre_state_id` do intento privado ainda nao possui um enquadramento
canonico `H_STATE` compativel com a prova candidata. Portanto, permitir uma
transicao agora poderia ligar um intento a um estado calculado de forma
inconsistente. O identificador deste modulo tambem nao e o `StateId` do ledger
atual e nunca e convertido para ele.

## Proximo passo

Publicar o manifesto de `H_STATE`, com codificacao, vetores e corpus de
interoperabilidade. Somente depois disso sera possivel projetar uma transicao
atomica: verificar a prova selecionada, conferir o estado anterior, impedir
nullifier repetido, acrescentar commitments e produzir a nova raiz.
