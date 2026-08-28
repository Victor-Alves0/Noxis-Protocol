# Referência executável da árvore esparsa de nullifiers — candidata v0.1

O crate `noxis-nullifier-tree-reference` é a leitura lenta e verificável de
`NXSM v1`. Ele serve de oráculo de correção para futuras implementações
otimizadas, circuitos AIR e armazenamento persistente; não é uma carteira, nó
ou validador.

## Operações implementadas

- `spent_leaf`: calcula a folha de um `NullifierV2` canônico;
- `node`: calcula um pai ordenado de dois digests;
- `empty_values`: deriva `E0` até a raiz vazia no nível 512;
- `root_from_path`: recompõe uma raiz a partir da folha e dos 512 irmãos;
- `verify_inclusion` e `verify_absence`: conferem respectivamente gasto e não
  gasto para um nullifier específico.

O caminho é sempre derivado dos 64 bytes do nullifier. No nível `n`, usa-se o
bit `n % 8` do byte `n / 8`; nenhum índice ou mapa de direções é aceito do
chamador. Assim, uma prova de ausência não pode ser reutilizada para outro
nullifier com caminho diferente.

## Proteções e limites

O crate carrega e valida `NXSM` antes de calcular, usa seu próprio sponge
`BytePack3LE` e IVs específicos, e rejeita irmãos não canônicos, tamanho de
caminho diferente de 512 e raízes incompatíveis. A raiz vazia foi congelada em
um teste de regressão.

Ele ainda não mantém um mapa de nós, não gera provas a partir de um estado,
não impede inserção duplicada e não substitui `H_NFSET` no `H_STATE`. Esses
passos exigem vetores externos e uma estrutura mutável que preserve
atomicidade, e permanecem fora desta entrega.
