# Framing de parâmetros de árvore v2 — v0.1

## Estado

Esta entrega cria bytes e vetores verificáveis para uma **candidata ainda não selecionada**. Ela não cria árvore Poseidon2, raiz, prova, allowlist, `TreeParametersId` reconhecido ou transação privada válida.

O crate isolado `noxis-tree-params` não depende de backend criptográfico. Sua única responsabilidade é impedir que, no futuro, dois implementadores atribuam a mesma identidade a bytes diferentes de parâmetros.

## NXTM v1: manifesto rascunho

O manifesto tem 24 bytes fixos, sem payload:

```text
"NXTM" | version=1(u16be) | kind=unselected | flags=0
tree_depth=32 | arity=2 | field=BabyBear | encoding=16×u32le
elements=16 | reserved=0×3 | modulus=2_013_265_921(u32be) | payload_length=0(u32be)
```

Seu ID de candidata é:

```text
SHA-256("NOXIS/TREE-PARAMETERS-ID/V2\0" || NXTM_canonical_bytes)
= 3352ddb41ccc2d1b3e8b37d3b93acae91a81def57c94e76fac1485fcb24edb76
```

Esse valor não é e não pode ser convertido em `TreeParametersId` aprovado. O fato de um ID ter 32 bytes não prova que os parâmetros correspondentes existem, foram revisados ou podem entrar no ledger.

## Vetor de interoperabilidade de campo

`CanonicalBabyBearVectorV1` fixa 16 inteiros de borda e seus 64 bytes little-endian esperados. Ele cobre `0`, `1`, `p - 2`, `p - 1` e valores de tamanhos variados. O teste compara o vetor com a implementação compartilhada de `noxis-privacy-types`; assim, mudança de endianness ou de módulo quebra a validação imediatamente.

Este ainda não é vetor de Poseidon2. Vetores de permutação, folha, nó, árvore vazia e caminho só serão congelados depois de a referência Horizen BabyBear-16 e a implementação Zig independente reproduzirem o mesmo corpus.

## Referência sob avaliação

A referência primária em avaliação é a implementação BabyBear-16 da [HorizenLabs](https://github.com/HorizenLabs/poseidon2), com `p=2_013_265_921`, largura 16, S-box `x^7`, oito rounds externos e treze internos. Ela compilou e executou seus testes BabyBear no Rust 1.85. A publicação `zkhash 0.2.0` é usada apenas como oráculo independente de vetor BabyBear-24; não é backend de consenso nem AIR para Noxis.

O próximo passo é fixar commits, gerar um corpus BabyBear-16 e exigir concordância entre Horizen, [blockblaz/zig-poseidon](https://github.com/blockblaz/zig-poseidon) e uma referência Noxis isolada. Sem essa concordância, `NXTM` permanece intencionalmente vazio.
