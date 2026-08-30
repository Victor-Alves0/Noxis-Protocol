# Preflight STARK completo de transferência candidata — pesquisa v0.1

## Execução disponível

`run_candidate_private_transfer_stark_preflight` é a primeira entrada única
para todas as relações STARK candidatas hoje implementadas para a forma fixa
2×2. Ela recebe uma declaração pública `NXPU v1`, estado de nullifiers antes da
transação, witness `NXSM`, duas witnesses privadas de posse e duas witnesses
privadas de saída. A execução faz, nesta ordem:

1. revalida a declaração pública, âncora e transição local de nullifiers;
2. prova e verifica `H_INTENT` **uma única vez**;
3. prova e verifica posse/Merkle de profundidade 32 para cada input;
4. prova e verifica `H_NOTE` para cada output;
5. confere todos os resultados públicos contra os slots canônicos da mesma
   intenção e devolve apenas um recibo de resultados públicos.

As quatro provas privadas são sequenciais e são descartadas depois da
verificação. O recibo preserva a identidade SHA-256 da declaração exata e pode
revalidar as ligações públicas e de estado local, mas não recupera nem reenvia
uma prova opaca.

## O que isso significa na prática

Há agora um caminho executável que responde a uma pergunta concreta: “estas
duas entradas pertencem à raiz declarada, produzem os nullifiers declarados, e
estas duas notas de saída produzem os commitments declarados pela mesma
transação?” Se um commitment, nullifier, raiz, slot ou `H_INTENT` não coincide,
o caminho falha fechado.

O código evita calcular `H_INTENT` duas vezes: os preflights de posse e de
saída expõem variantes sem intent para que a composição superior faça essa
prova uma vez e use uma única declaração compartilhada.

## O que continua faltando

Esta execução **não** é uma transação privada submetível. Ainda não há:

- AIR única que absorva todas as relações;
- agregação ou recursão das quatro provas;
- prova privada da transição completa `NXSM` (a witness é local transparente);
- regras aritmetizadas de valor/ativo, unicidade de `rho`/`rcm` e semântica de
  abertura no mesmo sistema de prova;
- vínculo entre commitment de saída e envelope cifrado/digest de ciphertext;
- inserção atômica de outputs, estado privado v2 persistente, verificador
  selecionado, formato de prova ou aceitação pelo consenso/ledger.

As verificações semânticas locais existentes em `noxis-note-opening` continuam
importantes, mas não são dependência deste crate: inverter a dependência criaria
um ciclo arquitetural. O próximo AIR deverá incorporar as relações, não ligar
crates em ciclo.

## Como reproduzir

```powershell
cargo test -p noxis-private-proof-contract transfer_preflight::tests::executes_every_available_private_relation_for_one_statement --release --locked
```

O teste constrói duas notas de entrada, seus caminhos Merkle e nullifiers,
duas saídas privadas ordenadas canonicamente e uma mesma âncora candidata. Em
seguida executa toda a sequência e testa rejeição ao alterar o commitment de
intenção retido. Como o backend atual não agrega provas, o teste é
computacionalmente mais caro que as verificações unitárias isoladas. Na máquina
de desenvolvimento de referência, a execução release medida em 2026-08-30
terminou em **440,17 segundos**; durante a execução, o processo observado
atingiu aproximadamente **4 GB** de memória residente. Esses números são uma
medição de pesquisa local, não meta de desempenho nem garantia operacional.

## Próximo passo correto

Transformar esta sequência em uma especificação de composição AIR por etapas:
primeiro compartilhar colunas e vínculos públicos entre `H_INTENT`, uma posse e
uma saída; depois escalar para 2×2, conservação de valor, envelope e transição
de estado. Nenhuma etapa deve ativar serviço de privacidade antes de backend,
formato de prova e revisão independente.
