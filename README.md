# Encriptação de Imagens com 3D-MMHM e SHA-512

Este projeto explora a encriptação de imagens digitais no contexto de comunicações UAV (Unmanned Aerial Vehicles), recorrendo ao mapa hipercaótico tridimensional **3D-MMHM** e ao hashing **SHA-512**.

O algoritmo combina técnicas de permutação e difusão de píxeis para proteger as imagens, utilizando uma **S-Box dinâmica** para substituição dos valores dos píxeis e operações **XOR** com bytes derivados da sequência caótica para reforçar a difusão.

## Implementação

O script principal desenvolvido é:

- `teste_encriptacao_3d_mmhm.py`

Foram realizados testes utilizando várias imagens de exemplo, organizadas nas seguintes pastas:

- `imagens/test_cases/` — imagens originais utilizadas nos testes.
- `imagens/resultados/` — resultados obtidos após a execução do algoritmo.

## Tecnologias e Métodos

- **Python** — implementação do algoritmo.
- **3D-MMHM** — mapa hipercaótico tridimensional para geração de sequências caóticas.
- **SHA-512** — hashing utilizado no processamento associado à derivação de parâmetros.
- **Permutação de píxeis** — reorganização das posições dos píxeis através da sequência caótica.
- **S-Box dinâmica** — substituição dos valores dos píxeis.
- **XOR** — operação de difusão utilizando bytes derivados da sequência caótica.

## Como executar

Para executar o script, utiliza o seguinte comando no terminal:

```bash
python teste_encriptacao_3d_mmhm.py <imagem>.png
