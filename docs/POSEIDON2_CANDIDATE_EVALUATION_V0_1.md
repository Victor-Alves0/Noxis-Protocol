# Avaliação de candidatos Poseidon2 — v0.1

## Decisão desta entrega

**Nenhum backend é selecionado ou integrado.** O gate da árvore v2 permanece fechado.

Esta é uma decisão de engenharia, não uma alegação sobre a segurança dos projetos avaliados. Forçar uma dependência que não suporta o compilador mínimo do Noxis quebraria a política de reprodução antes mesmo de existir uma raiz, uma prova ou uma transação privada verificável.

## Critérios usados

O candidato teria de oferecer todos estes requisitos: BabyBear, Poseidon2, caminho claro para AIR/STARK, parâmetros determinísticos inspecionáveis, licença compatível e compilação/testes no Rust 1.85 do workspace. Além disso, continuaria sujeito ao manifesto, vetores externos e auditoria definidos no [gate da árvore](TREE_BACKEND_SELECTION_GATE_V0_1.md).

## Resultado da avaliação

| Candidato | Resultado | Evidência relevante |
| --- | --- | --- |
| Plonky3 `0.6.3` | Rejeitado para o MSRV atual | Os crates `p3-baby-bear`, `p3-poseidon2` e `p3-poseidon2-air` oferecem BabyBear/Poseidon2/AIR sob `MIT OR Apache-2.0`, mas `cargo +1.85.0 check --locked` falha no transitivo `p3-util`: usa APIs ainda indisponíveis ou instáveis naquele compilador. Os manifests publicados não declaram `rust-version`; portanto, não há MSRV garantido. |
| Plonky3 `0.4.1` | Rejeitado para o MSRV atual | A verificação também falha em `p3-util` por `usize::is_multiple_of` indisponível/instável no Rust 1.85. |
| Plonky3 `0.3.0` | Rejeitado como base de produção | Compila no Rust 1.85 e expõe AIR, mas a linha antiga não declara MSRV e os testes publicados de `p3-baby-bear` não fecham sem uma dependência de teste ausente. Não atende à exigência de reprodução verificável. |
| HorizenLabs `poseidon2` / `zkhash` | Não é backend escolhido; possível oráculo futuro | Tem parâmetros BabyBear e gerador próprio, sob Apache-2.0, mas não disponibiliza a integração AIR/STARK de que o Noxis precisa. É útil para comparar vetores, não para desbloquear o protocolo. |

O candidato arquitetural mais promissor é o Plonky3 atual: sua implementação BabyBear 16 publica parâmetros determinísticos (`p = 2_013_265_921`, S-box `x^7`, `R_F = 8`, `R_P = 13`) e inclui uma AIR Poseidon2. Esses fatos **não** autorizam chamar `default_*` como se fosse uma especificação Noxis. Os detalhes publicados estão no [código dos parâmetros](https://docs.rs/p3-baby-bear/0.6.3/src/p3_baby_bear/poseidon2.rs.html), no [crate da AIR](https://crates.io/crates/p3-poseidon2-air/0.6.3) e no [gerador do projeto Poseidon2](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage).

## Consequência prática

Não há nova dependência no `Cargo.lock`, não há árvore Poseidon2 no ledger, e nenhum `TreeParametersId` é reconhecido. O parser de valores públicos permanece útil como fronteira canônica, mas não equivale a hash, árvore ou prova.

## Próxima decisão necessária

Há apenas duas rotas aceitáveis, a serem avaliadas em uma entrega própria:

1. elevar deliberadamente o MSRV, depois testar todo o workspace e a versão exata do Plonky3/AIR; ou
2. manter Rust 1.85 e escolher uma referência compatível, auditável e com AIR equivalente, sem copiar primitivas criptográficas para dentro do Noxis.

Antes de qualquer rota entrar no código, o manifesto precisa eliminar ambiguidades de `TreeParametersId`, sponge, domínios e formato de vetores, conforme o gate atualizado.
