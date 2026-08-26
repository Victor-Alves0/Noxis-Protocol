# Decisão Criptográfica v0.1

## Decisão

O Noxis não implementará primitivas criptográficas próprias. A evolução será feita em camadas, usando bibliotecas estabelecidas e mantendo a possibilidade de troca explícita de algoritmos.

| Necessidade | Decisão | Motivo |
| --- | --- | --- |
| Formato de transação | `noxis-codec` próprio, pequeno e canônico | Bytes que serão identificados, assinados ou enviados entre nós não podem depender de serialização genérica. |
| Árvore de commitments | `incrementalmerkletree` como estrutura incremental | Tem uso no ecossistema Zcash e oferece posições, caminhos, fronteiras e checkpoints. |
| Hash da árvore provada | Poseidon compatível com o circuito | O software do nó e o circuito precisam calcular exatamente a mesma raiz. SHA-3 não deve ser escolhido apenas por constar no `CryptoSuite`. |
| Provas privadas | Halo2, após especificação e vetores de teste | Permite PLONK sem cerimônia confiável e é usado por Zcash; cada circuito Noxis continua exigindo revisão própria. |
| Identidade/transporte pós-quântico | Capacidade reservada, não habilitada agora | ML-KEM e ML-DSA padronizados pelo NIST não resolvem automaticamente a segurança do circuito ZK, e a combinação híbrida precisa ser formalmente especificada e auditada. |

## Consequências imediatas

1. `CryptoSuite` é metadado de versão; seus identificadores não significam que ML-KEM, ML-DSA ou qualquer mecanismo pós-quântico já está em uso.
2. O `state_anchor` já carrega uma raiz Merkle tipada e a profundidade da árvore. A implementação SHA-256 atual estabelece a semântica de estado e é declarada no `CryptoSuite` provisório, mas será substituída por uma árvore Poseidon compatível com o circuito antes de introduzir provas ZK.
3. O nó só aceitará transferências privadas depois de verificar uma prova concreta contra essa raiz. Não haverá modo que aceite uma prova simulada em ambientes com valor transferível.
4. Antes de introduzir Halo2, o projeto define os bytes canônicos de cada transação, a separação de domínio, os limites e vetores de teste.
5. O serviço de liquidação não pode ser aberto com nenhuma suíte nesta versão: a autorização de produção falha fechada. A feature `research-testing` só libera o fixture E2E com `RESEARCH_V1`; detalhes estão em [`CRYPTO_SERVICE_GATE_V0_1.md`](CRYPTO_SERVICE_GATE_V0_1.md).

## Sequência obrigatória

```text
codec canônico
  -> árvore Merkle + vetores de teste
    -> circuito Halo2 mínimo + testes negativos
      -> persistência e consenso
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

- [incrementalmerkletree 0.8.2](https://docs.rs/incrementalmerkletree/0.8.2/incrementalmerkletree/)
- [Halo2](https://github.com/zcash/halo2)
- [FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)

Essas escolhas descrevem uma direção de engenharia. Elas não constituem uma alegação de segurança ou uma aprovação para custódia de ativos.
