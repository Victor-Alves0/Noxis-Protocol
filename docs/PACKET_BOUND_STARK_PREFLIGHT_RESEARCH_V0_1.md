# Preflight STARK ligado ao pacote privado — pesquisa v0.1

## Estado

**Evidência executável local, não prova composta.** A entrada
`run_candidate_packet_bound_private_transfer_stark_preflight` só começa as
relações privadas depois de receber um recibo de
`noxis-private-packet-validation`. Esse recibo garante que os dois `NXRE`
canônicos pertencem aos dois digests públicos da mesma intenção `NXPT`.

Em seguida, o preflight existente executa `H_INTENT` uma vez, duas relações de
posse/inclusão e duas relações `H_NOTE` de saída contra a mesma declaração
`NXPU`. Antes dessas provas, ele rejeita localmente ativo privado divergente,
entrada de valor zero, overflow ou conservação `u128` inválida. O recibo final mantém ambos os comprovantes locais e pode revalidar os
bytes do pacote antes de revalidar os resultados públicos retidos.

```text
NXPT → NXRE[2] estritos → H_ENVELOPE[2] = intent digests
     → mesma intent → H_INTENT + ownership[2] + H_NOTE[2]
```

## Evidência reproduzida

```powershell
cargo test -p noxis-private-proof-contract --release --locked transfer_preflight::tests::executes_every_available_private_relation_for_one_statement -- --exact
```

Em 2026-08-30, a execução local release mais recente passou em **466,64 segundos**. O teste
cria duas pré-imagens de saída de 178 bytes, cifra cada uma em um `NXRE`,
calcula os digests candidatos nos slots canônicos, valida o pacote `NXPT` e só
então executa as cinco relações disponíveis.

## Rejeições estabelecidas pela fronteira

- `NXPT` malformado ou fora dos limites falha no codec;
- envelope que não é `NXRE` estrito falha antes do digest;
- envelope trocado de slot falha no digest;
- commitment ou envelope alterado não produz o digest da intenção;
- ativo privado divergente, entrada zero, overflow ou soma não conservada
  falha antes de iniciar o STARK;
- recibo de pacote cuja intenção não seja byte a byte a intenção da declaração
  STARK falha como `PacketIntentMismatch`.

## Limites importantes

- As cinco provas seguem independentes e são descartadas após verificação;
  não existe uma AIR única, agregação, recursão, serialização de prova ou
  verificador portátil.
- A relação `H_ADDR` ainda não prova que o commitment de recebimento da nota é
  a mesma chave X25519 + ML-KEM do `NXRE`. O teste cifra a pré-imagem de saída,
  mas essa ponte de chaves permanece um requisito de design criptográfico.
- O preflight não decripta os envelopes, não atualiza `NXSM`, não persiste
  ciphertexts, não consulta rede nem autoriza o ledger.
- O domínio `H_ENVELOPE` continua candidato sem vetores P24 de referência
  externos independentes e sem auditoria.

## Próximo gate

Um descriptor local assinado já evita o mix-up de endereço e commitment na
wallet, mas não prova derivação comum das chaves. O próximo gate é selecionar
uma ponte criptográfica revisada entre o recipient commitment usado em
`H_NOTE`/`H_ADDR` e as chaves híbridas, com formato público, vetores e prova de
ligação. Só depois faz sentido projetar uma AIR única que consuma esse vínculo
e a validação de pacote. Ver
[`RECIPIENT_DESCRIPTOR_LOCAL_CANDIDATE_V0_1.md`](RECIPIENT_DESCRIPTOR_LOCAL_CANDIDATE_V0_1.md).
