# Decisão Criptográfica v0.1

## Decisão

O Noxis não implementará primitivas criptográficas próprias. A evolução será feita em camadas, usando bibliotecas estabelecidas e mantendo a possibilidade de troca explícita de algoritmos.

| Necessidade | Decisão | Motivo |
| --- | --- | --- |
| Formato de transação | `noxis-codec` próprio, pequeno e canônico | Bytes que serão identificados, assinados ou enviados entre nós não podem depender de serialização genérica. |
| Árvore de commitments | Árvore v2 com Poseidon2 e parâmetros congelados | Software, vetores e AIR precisam calcular exatamente a mesma raiz; a árvore SHA-256 atual é apenas de pesquisa. |
| Provas privadas | Candidato `NX-ZK-STARK/V1`, após especificação e vetores | A direção transparente/AIR preserva a premissa pós-quântica do sistema de provas; backend e parâmetros continuam não escolhidos para produção. |
| Identidade/transporte pós-quântico | Perfil híbrido especificado, não habilitado | ML-KEM e ML-DSA padronizados pelo NIST não resolvem automaticamente a segurança da prova; combinação e integração exigem vetores e auditoria. |

## Consequências imediatas

1. `CryptoSuite` é metadado de versão; seus identificadores não significam que ML-KEM, ML-DSA ou qualquer mecanismo pós-quântico já está em uso.
2. O `state_anchor` já carrega uma raiz Merkle tipada e a profundidade da árvore. A implementação SHA-256 atual estabelece a semântica provisória; `PrivateTransferV2` exige nova gênese, tipos v2 e árvore Poseidon2 compatível com AIR.
3. O nó só aceitará transferências privadas depois de verificar uma prova concreta contra essa raiz. Não haverá modo que aceite uma prova simulada em ambientes com valor transferível.
4. Antes de introduzir um backend STARK, o projeto define bytes canônicos, separação de domínio, parâmetros, limites e vetores de teste.
5. O serviço de liquidação não pode ser aberto com nenhuma suíte nesta versão: a autorização de produção falha fechada. A feature `research-testing` só libera o fixture E2E com `RESEARCH_V1`; detalhes estão em [`CRYPTO_SERVICE_GATE_V0_1.md`](CRYPTO_SERVICE_GATE_V0_1.md).

## Sequência obrigatória

```text
tipos privados e codec v2
  -> árvore Poseidon2 + vetores independentes
    -> AIR/STARK mínimo + testes negativos
      -> carteira/prover offline + envelope de destinatário
        -> revisão independente e testnet fechada
```

O primeiro circuito deverá provar, no mínimo: inclusão dos inputs sob uma raiz pública, derivação de nullifier, conservação por `asset_id`, faixas válidas de valor, criação de commitments e vínculo com o hash da transação canônica.

## Critérios antes de adicionar dependências criptográficas

- Fixar domínio de hash, profundidade da árvore, ordem esquerda/direita, valor de folha vazia, codificação da folha e posição.
- Fixar a versão das dependências e registrar vetores de teste reproduzíveis.
- Testar que a implementação do nó e a do circuito produzem a mesma raiz e rejeitam os mesmos casos inválidos.
- Incluir testes negativos de restrições, testes de parser adversarial e fuzzing.
- Realizar revisão independente do circuito e da integração antes de qualquer ativo transferível.

## Referências primárias

- [STARK](https://eprint.iacr.org/2018/046.pdf)
- [Poseidon2](https://eprint.iacr.org/2023/323.pdf)
- [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)

Os detalhes propostos estão em [`PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md`](PRIVATE_TRANSFER_ARCHITECTURE_DRAFT_V0_1.md) e [`HYBRID_CRYPTO_PROFILE_DRAFT_V0_1.md`](HYBRID_CRYPTO_PROFILE_DRAFT_V0_1.md).

Essas escolhas descrevem uma direção de engenharia. Elas não constituem uma alegação de segurança ou uma aprovação para custódia de ativos.
