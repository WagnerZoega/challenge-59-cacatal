# Descrição

Desafio do canal Investidor Internacional

Como funciona o desafio: https://www.youtube.com/watch?v=4JAquWro4rg
<strong>Premio: 0.0015 BTC</strong>

# Uso

Instale as bibliotecas, dependências e compile o código
```bash
# Instalação das dependências
sudo apt update
sudo apt install libsecp256k1-dev libssl-dev git make g++ python3 python3-pip -y

# Instalar biblioteca Python bit (ambiente virtual recomendado)
python3 -m venv env
source env/bin/activate
pip install bit

# Se o arquivo challenge.cpp estiver corrompido e você estiver usando git
# git checkout challenge.cpp

# Método de compilação alternativo (caso o makefile apresente problemas)
g++ -o challenge challenge.cpp -I/usr/local/ssl/include -I/usr/include -I/usr/local/include -march=native -O2 -w -lssl -lcrypto -lsecp256k1 -fopenmp

# Verificar se a compilação foi bem-sucedida
./challenge -h
```

Altere o arquivo config.txt:
- Na primeira linha: coloque a chave privada parcial fornecida no desafio
- Na segunda linha: coloque o endereço Bitcoin alvo

## Execução do programa

Exemplo básico:
```bash
./challenge -t 20 -s
```

Opções disponíveis:
```
-t <numero_threads>    Define o número de threads a serem usadas
-d <endereço_btc>      Define um endereço de destino para transferir fundos imediatamente
-i <arquivo_config>    Define o arquivo de configuração (padrão: config.txt)
-s                     Salva o progresso no arquivo {partial_key}.txt
-h                     Mostra a mensagem de ajuda
```

## Solução de Problemas

Se ocorrerem erros de compilação, tente:

1. Restaurar o arquivo original se estiver usando git: `git checkout challenge.cpp`
2. Compilar com otimizações reduzidas: `g++ -o challenge challenge.cpp -O1 -w -lssl -lcrypto -lsecp256k1`
3. Verificar se todas as dependências estão instaladas corretamente


