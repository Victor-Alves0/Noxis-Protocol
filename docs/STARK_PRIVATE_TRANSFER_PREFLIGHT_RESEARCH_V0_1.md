# Preflight STARK completo de transferência candidata — pesquisa v0.1

## Execução disponível

`run_candidate_private_transfer_stark_preflight` é a primeira entrada única
para todas as relações STARK candidatas hoje implementadas para a forma fixa
2×2. Ela recebe uma declaração pública `NXPU v1`, estado de nullifiers antes da
transação, witness `NXSM`, duas witnesses privadas de posse e duas witnesses
privadas de saída. A execução faz, nesta ordem:

1. revalida a declaração pública, âncora e transição local de nullifiers;
2. rejeita localmente versão, ativo, zero, overflow ou desequilíbrio com erros
   precisos e então prova/verifica, no mesmo AIR composto, `H_INTENT`, quatro
   `H_NOTE`, ativo comum, conservação privada `u128` por bytes/carries e o
   vínculo byte a byte entre cada slot de saída do intent e seu `H_NOTE`;
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

O código evita calcular `H_INTENT` duas vezes: ele agora é parte da mesma AIR
que prova conservação e os dois commitments de saída, enquanto os preflights
de posse e de saída expõem variantes sem intent para compartilhar a declaração.

## O que continua faltando

Esta execução **não** é uma transação privada submetível. Ainda não há:

- AIR única que absorva posse, nullifiers, envelope e transição de estado;
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

A conservação `u128` agora também é imposta pela relação STARK composta de
`H_INTENT` e quatro `H_NOTE`, com bytes range-checked e carries Booleanos, e
não retém valores no recibo. A mesma AIR liga os `H_NOTE` de saída aos slots
canônicos autenticados pelo intent. O preflight continua a fazer a checagem
local antes do provador para produzir rejeições claras. Ela ainda não é uma
prova transferível nem inclui nullifiers ou posse; as duas provas de posse
recebem os mesmos commitments de entrada apenas como bridge local de pesquisa. Ver
[`STARK_VALUE_CONSERVATION_RESEARCH_V0_1.md`](STARK_VALUE_CONSERVATION_RESEARCH_V0_1.md).

Como próximo recorte executável, `noxis-stark-experiment` também contém uma
AIR única para `H_INTENT`, conservação de quatro notas e a posse/Merkle da
**primeira** entrada. O teste de restrições constrói um witness canônico e
confirma as três famílias no mesmo traço de 8.192 linhas. Ela ainda não é usada
pelo preflight normal. Em 2026-08-31, a geração **e verificação** local em
release dessa primeira prova composta passaram em **1.178,05 s**. A segunda
posse, nullifier-transition e envelope continuam fora desse recorte.

## Como reproduzir

```powershell
cargo test --release -p noxis-private-proof-contract transfer_preflight::tests::executes_every_available_private_relation_for_one_statement --lib -- --exact --ignored --nocapture
```

O teste constrói duas notas de entrada, seus caminhos Merkle e nullifiers,
duas saídas privadas ordenadas canonicamente e uma mesma âncora candidata. Em
seguida cifra as duas saídas em `NXRE`, valida o `NXPT` ligado aos digests e
executa toda a sequência; também testa rejeição ao alterar o commitment de
intenção retido. Como o backend atual não agrega provas, o teste é
computacionalmente mais caro que as verificações unitárias isoladas e é
ignorado por padrão. Em 2026-09-01, a execução local em release, já incluindo
o bundle que retém e revalida as provas opacas, passou em **936,43 segundos**.
O build release adicional levou **33,53 segundos**. O pico observado durante
as provas de posse de profundidade 32 foi de aproximadamente **4,45 GB** de
memória residente. Uma execução debug foi interrompida após cerca de 181
minutos ainda em progresso; ela não é um benchmark útil. Esses números são
pesquisa local, não meta de desempenho nem garantia operacional. Ver
[`PRIVATE_TRANSFER_PROOF_BUNDLE_RESEARCH_V0_1.md`](PRIVATE_TRANSFER_PROOF_BUNDLE_RESEARCH_V0_1.md).

## Próximo passo correto

Transformar esta sequência em uma especificação de composição AIR por etapas:
primeiro compartilhar witness e vínculos públicos entre a conservação 2×2,
uma posse, uma saída e o digest de envelope; depois compor os dois inputs, os
dois outputs e a transição de estado. Nenhuma etapa deve ativar serviço de privacidade antes de backend,
formato de prova e revisão independente.
