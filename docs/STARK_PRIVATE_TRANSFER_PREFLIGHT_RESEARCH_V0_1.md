# Preflight STARK completo de transferência candidata — pesquisa v0.1

## Execução disponível

`run_candidate_private_transfer_stark_preflight` é a primeira entrada única
para todas as relações STARK candidatas hoje implementadas para a forma fixa
2×2. Ela recebe uma declaração pública `NXPU v1`, estado de nullifiers antes da
transação, witness `NXSM`, duas witnesses privadas de posse e duas witnesses
privadas de saída. A execução faz, nesta ordem:

1. revalida a declaração pública, âncora e transição local de nullifiers;
2. rejeita localmente versão, ativo, zero, overflow ou desequilíbrio com erros
   precisos e então prova/verifica, no mesmo AIR, quatro `H_NOTE`, ativo comum,
   conservação privada `u128` por bytes/carries e os dois slots públicos de
   commitment de saída da `NXPU`;
3. prova e verifica `H_INTENT` **uma única vez**;
4. passa os commitments de entrada recém-verificados às duas provas de
   posse/Merkle de profundidade 32, que os igualam ao próprio `H_NOTE` interno;
5. prova e verifica `H_NOTE` com vínculo do ativo público para cada output;
6. confere todos os resultados públicos contra os slots canônicos da mesma
   intenção e devolve apenas um recibo de resultados públicos.

As quatro provas privadas são sequenciais e são descartadas depois da
verificação. O recibo preserva a identidade SHA-256 da declaração exata e pode
revalidar as ligações públicas e de estado local, mas não recupera nem reenvia
uma prova opaca.

`run_candidate_packet_bound_private_transfer_stark_preflight` acrescenta uma
entrada mais estrita: ela aceita somente um recibo já validado de `NXPT` e
falha se a intenção desse pacote não for byte a byte a intenção da declaração
`NXPU`. O pacote é revalidado ao revalidar o recibo composto. Ver
[`PACKET_BOUND_STARK_PREFLIGHT_RESEARCH_V0_1.md`](PACKET_BOUND_STARK_PREFLIGHT_RESEARCH_V0_1.md).

## O que isso significa na prática

Há agora um caminho executável que responde a uma pergunta concreta: “estas
duas entradas pertencem à raiz declarada, produzem os nullifiers declarados, e
estas duas notas de saída produzem os commitments declarados pela mesma
transação, com o mesmo ativo e valor conservado?” Se um commitment, nullifier,
raiz, slot, ativo, valor ou `H_INTENT` não coincide, o caminho falha fechado.

O código evita calcular `H_INTENT` duas vezes: os preflights de posse e de
saída expõem variantes sem intent para que a composição superior faça essa
prova uma vez e use uma única declaração compartilhada.

## O que continua faltando

Esta execução **não** é uma transação privada submetível. Ainda não há:

- AIR única que absorva todas as relações;
- agregação ou recursão das quatro provas;
- prova privada da transição completa `NXSM` (a witness é local transparente);
- uma AIR única que absorva a ponte local entre conservação/posse e vincule
  `H_INTENT`, nullifier e semântica restante de abertura;
- AIR que recompute o vínculo já checado localmente entre commitment de saída,
  slot e envelope cifrado/digest de ciphertext, além da ponte entre `H_ADDR` e
  a chave híbrida de recebimento;
- inserção atômica de outputs, estado privado v2 persistente, verificador
  selecionado, formato de prova ou aceitação pelo consenso/ledger.

As verificações semânticas locais existentes em `noxis-note-opening` continuam
importantes, mas não são dependência deste crate: inverter a dependência criaria
um ciclo arquitetural. O próximo AIR deverá incorporar as relações, não ligar
crates em ciclo.

A conservação `u128` agora também é imposta pela relação STARK de quatro
`H_NOTE`, com bytes range-checked e carries Booleanos, e não retém valores no
recibo. A variante usada pelo preflight também vincula os `H_NOTE` de saída aos
slots públicos da `NXPU`. O preflight continua a fazer a checagem local antes
do provador para produzir rejeições claras. A relação isolada ainda não é uma
prova transferível nem está ligada dentro de uma única AIR ao `H_INTENT`, aos
nullifiers ou à posse; as duas provas de posse recebem os mesmos commitments de
entrada apenas como bridge local de pesquisa. Ver
[`STARK_VALUE_CONSERVATION_RESEARCH_V0_1.md`](STARK_VALUE_CONSERVATION_RESEARCH_V0_1.md).

## Como reproduzir

```powershell
cargo test -p noxis-private-proof-contract transfer_preflight::tests::executes_every_available_private_relation_for_one_statement --release --locked
```

O teste constrói duas notas de entrada, seus caminhos Merkle e nullifiers,
duas saídas privadas ordenadas canonicamente e uma mesma âncora candidata. Em
seguida cifra as duas saídas em `NXRE`, valida o `NXPT` ligado aos digests e
executa toda a sequência; também testa rejeição ao alterar o commitment de
intenção retido. Como o backend atual não agrega provas, o teste é
computacionalmente mais caro que as verificações unitárias isoladas. A medição
histórica de **466,64 segundos**, feita em 2026-08-30 antes da ponte de
commitments de entrada, não deve ser tratada como desempenho do fluxo atual.
O teste release completo com a ponte passou; uma nova medição controlada deve
substituir o número histórico antes de qualquer comparação. Execuções de posse
de profundidade 32 podem usar aproximadamente **4 GB** de memória residente.
Esses números são pesquisa local, não meta de desempenho nem garantia
operacional.

## Próximo passo correto

Transformar esta sequência em uma especificação de composição AIR por etapas:
primeiro compartilhar witness e vínculos públicos entre a conservação 2×2,
uma posse, uma saída e o digest de envelope; depois compor os dois inputs, os
dois outputs e a transição de estado. Nenhuma etapa deve ativar serviço de privacidade antes de backend,
formato de prova e revisão independente.
