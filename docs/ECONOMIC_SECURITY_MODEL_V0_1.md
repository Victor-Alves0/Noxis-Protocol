# Modelo econômico e de segurança — rascunho v0.1

## Estado e limite desta decisão

O Noxis ainda não tem token nativo, taxa de transação, stake, delegação, pool, troca de ativos, contrato inteligente ou conjunto dinâmico de validadores. Os pesos de validação atuais pertencem à gênese e **não são stake**. Portanto, não há recompensa on-chain, rendimento, APR ou liquidez disponível hoje.

Este documento define a separação que uma versão futura deverá preservar. Não escolhe percentuais, emissão, preço, token ou retorno financeiro. Nenhuma participação no Noxis deve ser apresentada como lucro garantido.

## Duas atividades, dois riscos, duas fontes de receita

| Atividade | O que sustenta | Fonte permitida de receita | Risco principal |
| --- | --- | --- | --- |
| Validação | segurança, ordenação e finalidade dos blocos | taxas realmente pagas e finalizadas pela rede | custo operacional, penalidade futura por evidência verificável, risco do ativo recebido |
| Provisão de liquidez | capacidade de negociação de um mercado específico | taxas realmente pagas naquele pool ou mercado | perda impermanente/adverse selection, depeg, concentração, falha de contrato e manipulação |

Em termos simples: validar é prestar o serviço de segurança da rede; prover liquidez é emprestar capital a um mercado. Uma atividade não financia, não controla e não garante a outra.

## Fase zero: operação atual

Enquanto a rede for permissionada e não tiver liquidação privada auditada:

- validadores podem ser remunerados somente por acordo operacional externo e explícito;
- o protocolo não cria inflação nem créditos para recompensá-los;
- não existem provedores de liquidez, pois não existe mercado; e
- contratos inteligentes gerais permanecem fora de escopo.

Isso evita inventar valor, incentivar comportamento financeiro prematuro ou conceder poder de consenso antes de existirem provas, regras econômicas e governança verificáveis.

## Primeiro mecanismo on-chain: taxas e reserva de validadores

O primeiro mecanismo econômico, quando houver transferência privada realmente verificada, deverá ser uma taxa canônica por transação. A prova precisará demonstrar a conservação do ativo incluindo a taxa: ela não pode ser criada do nada, subtraída de uma nota sem autorização nem cobrada duas vezes.

```text
taxa de transação finalizada
        -> reserva por ativo e por época
        -> direito determinístico de resgate
        -> validadores elegíveis naquela época
```

Regras iniciais propostas:

1. A única fonte de recompensa será taxa finalizada; emissão automática não entra na primeira versão.
2. A reserva é separada por `AssetId`; ativos nunca são misturados para pagar uma recompensa.
3. O direito nasce ao fim de uma época, somente a partir de fatos de consenso que todos os nós conseguem reproduzir.
4. A distribuição é ponderada pelo poder de consenso elegível e não por telemetria privada de uptime.
5. Não há bônus ao propositor do bloco; isso reduz incentivo de censura e extração de valor.
6. Restos de divisões inteiras permanecem na reserva. O cálculo nunca cria ou destrói unidades por arredondamento.
7. Mudanças de política só entram em vigor em época futura, após governança versionada e atraso público.

O modelo é deliberadamente mais simples que delegação e comissão. Sistemas de distribuição existentes mostram que delegação, recompensa e punição exigem contabilidade histórica complexa; por isso serão módulos separados, não atalhos no consenso ([Cosmos distribution](https://docs.cosmos.network/sdk/latest/modules/distribution/README), [Cosmos evidence](https://docs.cosmos.network/sdk/latest/modules/evidence/README)).

## Staking e conjunto de validadores: fase posterior

Uma rede permissionless futura precisará de módulo próprio para bonds, unbonding, delegação, rotação de validadores e slashing. Nenhuma dessas regras deve ser inferida do peso de voto atual.

Uma punição só pode existir quando a prova de infração for canônica, verificável por qualquer nó e ligada ao período correto. Alegação externa, reputação ou monitoramento privado nunca devem causar slashing. A primeira economia de taxas não inclui delegação, comissão ou slashing até que essa evidência e a mudança dinâmica de conjunto estejam implementadas e revisadas.

## Liquidez só depois de existir mercado

O protocolo de liquidação não precisa de AMM para ser útil. Liquidez entra apenas depois de escolher um motor de mercado — AMM, livro de ofertas ou RFQ — e construir sua contabilidade isolada.

Cada mercado futuro precisará manter, separadamente:

- depósitos e retiradas explícitos por ativo;
- cotas de participação do provedor;
- taxas efetivamente geradas naquele mercado;
- reservas e direitos de resgate por pool; e
- incentivos opcionais, pré-financiados e aprovados de forma versionada.

No desenho inicial, um LP recebe somente uma parcela das taxas daquele mercado. Não haverá subsídio geral por emissão nem cálculo baseado em “valor em dólar”, pois isso introduziria oráculo e superfície de manipulação. Taxas podem ser menores que perdas; liquidez não é renda garantida.

## Fronteira de contratos inteligentes

Contratos gerais não são requisito para a primeira economia. A sequência prevista é:

1. módulos nativos e determinísticos para taxa, reserva, direitos de recompensa e, se necessário, mercado;
2. medição canônica de recursos, limites de armazenamento e rollback atômico;
3. governança de atualizações e resposta a incidentes; e
4. somente então, uma VM WASM restrita.

Essa VM futura não terá filesystem, rede, relógio local, aleatoriedade, threads, ponto flutuante, SIMD nem acesso genérico ao sistema. Um contrato só poderá movimentar ativos que tenham sido depositados explicitamente em seu vault; não poderá criar ativos, alterar consenso, modificar stake, chamar políticas de mint ou acessar notas privadas de terceiros. Execução privada programável exige circuitos/STARKs próprios e não é consequência automática de uma VM pública.

## Módulos futuros e responsabilidades

| Módulo | Responsabilidade exclusiva |
| --- | --- |
| `noxis-fees` | taxa canônica, recibo e reserva por época/ativo |
| `noxis-rewards` | direitos de resgate e distribuição determinística de reservas |
| `noxis-validator-staking` | bonds, delegação, unbonding, evidência e slashing futuros |
| `noxis-liquidity` | pools/mercados, cotas e taxas de LP |
| `noxis-governance` | parâmetros versionados, atraso de ativação e votação |
| `noxis-contract-*` | tipos, estado, VM restrita e host limitado, somente em fase posterior |
| `noxis-execution` | composição atômica das transições, sem escolher política econômica |
| `noxis-consensus` | ordenação/finalidade e conjunto validado, sem calcular recompensa |

## Invariantes obrigatórios antes de valor transferível

- Cada unidade de taxa, recompensa, depósito e retirada é conservada por `AssetId`.
- Uma reserva não pode ser resgatada duas vezes, por validador nem por época.
- Uma mudança de parâmetros não altera direitos de época já encerrada.
- Uma recompensa nunca depende de fonte fora do estado e do consenso canônico.
- Um pool não pode usar seus ativos para recompensar validação, e validação não pode usar reserva de pool.
- Nenhum contrato pode alterar diretamente consenso, emissão, stake, governança ou política de segurança.
- Limites de tamanho, CPU, memória, profundidade e armazenamento fazem parte do `AppHash` e são testados adversarialmente.

## Próxima entrega

Depois de uma árvore/prova privada auditável, a primeira implementação econômica será `noxis-fees`: modelo puro, sem token novo, sem contratos e sem dinheiro real, acompanhado de vetores de conservação e testes de época. `noxis-rewards`, staking, liquidez e VM só avançam quando os pré-requisitos desta seção forem comprovados.
