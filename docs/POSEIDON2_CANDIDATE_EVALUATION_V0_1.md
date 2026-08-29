# Avaliação de candidatos Poseidon2 — v0.1

## Decisão desta entrega

**Nenhum backend de árvore ou prova privada é selecionado ou integrado ao
protocolo.** O gate da árvore v2 permanece fechado e o Noxis usa Rust 1.93
como MSRV. O Plonky3 existente permanece limitado ao experimento STARK de
pesquisa; ele não fornece o hash de árvore do ledger nem seleciona parâmetros.

Esta é uma decisão de engenharia, não uma alegação sobre a segurança dos projetos avaliados. Forçar uma dependência que não suporta o compilador mínimo do Noxis quebraria a política de reprodução antes mesmo de existir uma raiz, uma prova ou uma transação privada verificável.

## Critérios usados

O candidato teria de oferecer todos estes requisitos: BabyBear, Poseidon2,
caminho claro para AIR/STARK, parâmetros determinísticos inspecionáveis,
licença compatível e compilação/testes no Rust 1.93 do workspace. Além disso,
continuaria sujeito ao manifesto, vetores externos e auditoria definidos no
[gate da árvore](TREE_BACKEND_SELECTION_GATE_V0_1.md).

## Resultado da avaliação

| Candidato | Resultado | Evidência relevante |
| --- | --- | --- |
| Plonky3 `0.6.3` | Rejeitado como backend Poseidon2/árvore; mantido somente no experimento STARK | O pacote requer Rust posterior a 1.87, não fecha seus próprios testes por dependência de teste ausente e a chamada direta da sua permutação width-16 não reproduziu o vetor que publica. O experimento Noxis usa a AIR/PCS, mas a referência P24 isolada para os parâmetros e a permutação. |
| Plonky3 `0.4.1` | Rejeitado para o MSRV atual | A verificação também falha em `p3-util` por `usize::is_multiple_of` indisponível/instável no Rust 1.85. |
| Plonky3 `0.3.0` | Rejeitado como base de produção | Compila no Rust 1.85 e expõe AIR, mas a linha antiga não declara MSRV e os testes publicados de `p3-baby-bear` não fecham sem uma dependência de teste ausente. Não atende à exigência de reprodução verificável. |
| HorizenLabs `poseidon2` / `zkhash` | Não é backend escolhido; possível oráculo futuro | Tem parâmetros BabyBear e gerador próprio, sob Apache-2.0, mas não disponibiliza a integração AIR/STARK de que o Noxis precisa. É útil para comparar vetores, não para desbloquear o protocolo. |

O Plonky3 atual continua sendo relevante para pesquisa: sua implementação BabyBear 16 publica parâmetros determinísticos (`p = 2_013_265_921`, S-box `x^7`, `R_F = 8`, `R_P = 13`) e inclui uma AIR Poseidon2. Esses fatos **não** autorizam chamar `default_*` como se fosse uma especificação Noxis. Os detalhes publicados estão no [código dos parâmetros](https://docs.rs/p3-baby-bear/0.6.3/src/p3_baby_bear/poseidon2.rs.html), no [crate da AIR](https://crates.io/crates/p3-poseidon2-air/0.6.3) e no [gerador do projeto Poseidon2](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage).

## Rejeição da publicação 0.6.3

Depois da autorização para avaliar a integração, o Noxis criou uma fronteira mínima que chamava `default_babybear_poseidon2_16()` com os 16 elementos canônicos do vetor publicado. Em Rust 1.93, a saída divergiu do resultado esperado que aparece em `p3-baby-bear 0.6.3/src/poseidon2.rs`. Essa divergência foi observada antes de qualquer código Noxis ser publicado e, por si só, impede usar o pacote como referência.

Também foi tentada a execução do teste upstream exato. A compilação do pacote publicado falhou antes de alcançar esse teste, porque módulos internos importam `p3_field_testing`, mas a dependência não está disponível no manifesto normalizado distribuído pelo crate. Portanto, nem o vetor nem a suíte upstream podem servir como evidência reproduzível para Noxis nesta publicação.

O experimento Plonky3 e suas dependências foram reintroduzidos apenas após a
fronteira P24 congelada, vetores externos e testes de prova ficarem explícitos.
O MSRV foi elevado para Rust 1.93 porque o `p3-util 0.6.3` do lockfile exige a
API estabilizada nessa versão. Isso não muda a decisão: Plonky3 não é a fonte
dos parâmetros P24 nem um backend privado selecionado.

## Evidência de compatibilidade de compilador

O Noxis executou a verificação diretamente contra os crates publicados, com os respectivos `Cargo.lock`:

| Rust | `p3-baby-bear 0.6.3` | Resultado |
| --- | --- | --- |
| 1.85 | falha | APIs de fatia `MaybeUninit` e `usize::is_multiple_of` indisponíveis/instáveis. |
| 1.86 | falha | Mesmo conjunto de APIs indisponível. |
| 1.87 | falha | `usize::is_multiple_of` deixa de bloquear, mas a API de fatia `MaybeUninit` ainda é instável. |
| 1.93 | compila, mas não é suficiente | `cargo +1.93.0 check --locked` concluiu; em seguida `cargo +1.93.0 test --workspace --locked` do Noxis passou. A divergência de vetor e os testes upstream não reprodutíveis ainda rejeitam a publicação. |

O Rust estabilizou `&[MaybeUninit<T>]::assume_init_ref` na versão 1.93, que explica o limiar observado ([fonte oficial](https://doc.rust-lang.org/stable/src/core/mem/maybe_uninit.rs.html)). Isso é evidência técnica de compilação, não uma promessa de suporte do upstream, pois a versão publicada não declara MSRV.

## Consequência prática

O `Cargo.lock` contém Plonky3 exclusivamente para o experimento STARK; não há
árvore Poseidon2 no ledger e nenhum `TreeParametersId` é reconhecido. O parser
de valores públicos permanece uma fronteira canônica, mas não equivale a hash,
árvore ou prova de protocolo.

## Próxima decisão necessária

O próximo candidato só pode entrar em avaliação se oferecer, ao mesmo tempo,
pacote reproduzível, vetor publicado que reproduza a permutação escalar em ao
menos duas configurações de compilação, testes upstream fechados e caminho
verificável para AIR/STARK. O Noxis usa Rust 1.93 porque o lockfile atual de
Plonky3 exige APIs posteriores a 1.87; elevar o MSRV corrige essa
incompatibilidade de compilação, não uma divergência criptográfica.

Antes de qualquer rota entrar no código, o manifesto precisa eliminar ambiguidades de `TreeParametersId`, sponge, domínios e formato de vetores, conforme o gate atualizado.
