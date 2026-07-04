# Homomorphic Cryptography

Trabalho sobre criptografia homomorfica, com apontamentos teoricos, referencias e uma implementacao simples de exemplo baseada no esquema DGHV.

## Estrutura

- `Conceitos Teóricos/` - apontamentos e material teorico de apoio.
- `Projeto/` - versao final do trabalho em PDF.
- `Projeto/Referencias/` - bibliografia e artigos consultados.
- `Projeto/Referencias/Notebooks/` - notebooks e script Python com demonstracoes praticas.
  - `somewhat_homomorphic.py` - implementacao/demonstracao de cifra parcialmente homomorfica sobre bits.
  - `somewhat_homomorphic.ipynb` - versao em notebook da demonstracao.
  - `fully_homomorphic.ipynb` - notebook de apoio sobre criptografia totalmente homomorfica.

Para executar a demonstracao em Python:

```bash
python3 "Projeto/Referencias/Notebooks/somewhat_homomorphic.py"
```

O script gera chaves, cifra bits, avalia circuitos booleanos com soma e multiplicacao homomorficas, e mostra o resultado esperado e o resultado decifrado.

Para abrir os notebooks:

```bash
jupyter notebook "Projeto/Referencias/Notebooks"
```

Se o Jupyter nao estiver instalado:

```bash
python3 -m pip install notebook
```

## Trabalho final

O PDF final encontra-se em:

```text
Projeto/a108393_FCSI2526.pdf
```
## Final Grade:
19