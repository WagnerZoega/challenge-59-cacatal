#include <stdio.h>
#include <stdlib.h>
#include <vector>

// Substituição condicional para unistd.h
#ifdef _WIN32
    // Windows não possui unistd.h
    #include <windows.h>
    #include <direct.h>
    #include <io.h>    // Corrigido - estava faltando o '>'
    
    // Define funções equivalentes para compatibilidade
    #define sleep(x) Sleep(x * 1000)
#else
    // Sistemas UNIX/Linux
    #include <unistd.h>
#endif

#include <cmath>
#include <csignal>
#include <thread>
#include <random>
#include <atomic>
#include <secp256k1.h>
#include <iostream>

// Caminho OpenSSL - usando condicional para tratar diferentes plataformas
#ifdef _WIN32
    // No Windows, apontando para os arquivos do WSL Ubuntu
    #include "\\\\D:\\bibliotecas\\openssl\\OpenSSL-Win64\\include\\openssl\\sha.h"
    #include "\\\\D:\\bibliotecas\\openssl\\OpenSSL-Win64\\include\\openssl\\ripemd.h"
#else
    // Em sistemas UNIX/Linux, usamos o caminho padrão
    #include <openssl/sha.h>
    #include <openssl/ripemd.h>
#endif

#include <chrono>
#include "base58.cpp"
#include <fstream>
#include <iomanip>
#include <locale>
#include <algorithm>
#include <sstream>
#include <cstdlib>
#include "base58.h"

// Global Variables
static secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
std::string const hex_chars = "0123456789abcdef";

std::vector<std::string> random_prefixes;
std::int64_t verified_batches;
std::int32_t const batch_size = 65536; //Do not change, equals to 16 ^ 4
int refresh_time;
int num_threads;
bool save = 0;
bool send = 0;
std::atomic<bool> found=0; 
std::string destination;    
std::string partial_key;
std::string target_address;
std::string last_key;
std::vector<unsigned char> decoded_target_address;
std::vector<int> x_positions;
pthread_mutex_t file_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t counter_lock = PTHREAD_MUTEX_INITIALIZER; 
bool auto_select_mode = false;
std::vector<int> additional_positions;

// Variáveis globais para rotação de posições
std::uint64_t positions_combinations_tested = 0;
std::uint64_t max_positions_combinations = 0;
bool need_new_positions = false;

// Adicione estas variáveis globais após as outras variáveis globais
const int FIXED_POS_BEFORE_X = 8;  // Posição do caractere "4" antes do "x" (índice 0-based)
const int FIXED_POS_AFTER_X = 10;  // Posição do caractere "8" após do "x" (índice 0-based)
const char FIXED_CHAR_BEFORE_X = '4';
const char FIXED_CHAR_AFTER_X = '8';

// Terminal Colors
const std::string red = "\033[91m";
const std::string green = "\033[92m";
const std::string yellow = "\033[93m";
const std::string blue = "\033[94m";
const std::string cyan = "\033[96m";
const std::string reset = "\033[0m";

// Threads Args
struct ThreadArgs{
    int thread_id;
    int refresh_time;
    int batch_size;
};

//Config file
struct KeyConfig {
    std::string partial_key;
    std::string target_address;
};

KeyConfig readConfigFromFile(const std::string &filename) {
    std::ifstream file(filename);
    KeyConfig config;
    
    if (file.is_open()) {
        std::getline(file, config.partial_key);
        std::getline(file, config.target_address);
        file.close();
    } else {
        throw std::runtime_error("Não foi possível abrir o arquivo " + filename);
    }
    
    if (config.partial_key.empty() || config.target_address.empty()) {
        throw std::runtime_error("Configuração incompleta.");
    }
    
    return config;
}

// Valida os inputs
int validate_input(int value, const std::string& prompt) {
    if (value < 1 || value > 128) {
        std::cerr << "Error: " << prompt << " deve estar entre 1 e 128 " << std::endl;
        exit(1); 
    }
    return value;
}

void auto_select_positions() {
    if (x_positions.size() == 1) {
        std::cout << "Auto-selecting 8 additional positions for substitution..." << std::endl;
        std::cout << yellow << "Note: Positions " << FIXED_POS_BEFORE_X << " ('" << FIXED_CHAR_BEFORE_X 
                  << "') and " << FIXED_POS_AFTER_X << " ('" << FIXED_CHAR_AFTER_X 
                  << "') will remain fixed!" << reset << std::endl;
        
        // Limpa as posições anteriores e reinicia o contador
        additional_positions.clear();
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dist(0, partial_key.size() - 1);
        
        // Guardamos a posição original do 'x'
        int original_x_pos = x_positions[0];
        
        // Seleciona 8 posições adicionais
        int count = 0;
        while (count < 8) {
            int pos = dist(gen);
            
            // Verifica se a posição já está selecionada, é o 'x' original, ou é uma posição fixa
            if (pos != original_x_pos && 
                pos != FIXED_POS_BEFORE_X && 
                pos != FIXED_POS_AFTER_X &&
                std::find(additional_positions.begin(), additional_positions.end(), pos) == additional_positions.end() &&
                partial_key[pos] != 'x' && partial_key[pos] != 'y' && 
                partial_key[pos] != 'z' && partial_key[pos] != 'w') {
                
                additional_positions.push_back(pos);
                count++;
                std::cout << "Added position " << pos << " (character: " << partial_key[pos] << ")" << std::endl;
            }
        }
        
        // Calcula o número total de combinações para estas posições
        max_positions_combinations = static_cast<std::uint64_t>(pow(16, 9)); // 16^9 combinações (1 'x' original + 8 posições)
        need_new_positions = false;
        
        std::cout << green << "Combinações totais para posições selecionadas: " << max_positions_combinations << reset << std::endl;
    }
}

std::string generate_random_prefix(){
    std::random_device rd;
    std::mt19937 gen(rd()+14061995);
    std::stringstream ss;
    
    // No modo auto-select com apenas 1 'x', geramos caracteres para todas as posições (x original + adicionais)
    int positions_count = x_positions.size();
    if (auto_select_mode && x_positions.size() == 1) {
        positions_count = 1 + additional_positions.size(); // 1 'x' original + 8 posições adicionais
    } else {
        positions_count = x_positions.size() - 4; // Modo normal, reservando 4 posições para sequencial
    }
    
    for (int i=0; i < positions_count; i++){
        ss << std::hex << hex_chars[gen()%16];
    }
    
    //key for "z"
    ss << std::hex << hex_chars[(gen()%7)+9];
    //key for "y"
    int y_position = gen()%13;
    ss << std::hex << hex_chars[y_position];
    //key for "w"
    ss << std::hex << hex_chars[y_position+3];
    
    return ss.str();
}

// Função para gerar as chaves
std::string generate_random_key(std::vector<std::string> &output_key) {
    
    unsigned int sequential_counter = 0;
    std::string random_prefix;

    if(save){
        // Gera um prefixo único
        do {
            random_prefix = generate_random_prefix();
        } while (std::find(random_prefixes.begin(), random_prefixes.end(), random_prefix) != random_prefixes.end());
        
        // Adiciona o novo prefixo ao vetor
        random_prefixes.push_back(random_prefix);
    } else {
        random_prefix = generate_random_prefix();
    }

    //Itera sobre o array de chaves
    for (int position = 0; position < output_key.size(); position ++){

        std::string new_key = partial_key;

        // Garantir que os caracteres fixos estejam corretos antes de qualquer substituição
        if (partial_key[FIXED_POS_BEFORE_X] != FIXED_CHAR_BEFORE_X) {
            new_key[FIXED_POS_BEFORE_X] = FIXED_CHAR_BEFORE_X;
        }
        if (partial_key[FIXED_POS_AFTER_X] != FIXED_CHAR_AFTER_X) {
            new_key[FIXED_POS_AFTER_X] = FIXED_CHAR_AFTER_X;
        }
        
        // Adicionar os x aleatórios e caracteres nas posições adicionais
        int x_index = 0;
        
        // Modo auto-select com apenas 1 'x'
        if (auto_select_mode && x_positions.size() == 1) {
            // Substitui o 'x' original
            new_key[x_positions[0]] = random_prefix[0];
            
            // Substitui os caracteres nas posições adicionais
            for (size_t i = 0; i < additional_positions.size(); i++) {
                new_key[additional_positions[i]] = random_prefix[i+1]; // +1 porque já usamos a posição 0 para o 'x' original
            }
            
            // Garante que os caracteres fixos não sejam alterados
            new_key[FIXED_POS_BEFORE_X] = FIXED_CHAR_BEFORE_X;
            new_key[FIXED_POS_AFTER_X] = FIXED_CHAR_AFTER_X;
        } else {
            // Modo normal
            for (int i = 0; i < partial_key.size(); i++){
                if (partial_key[i] == 'x' && x_index < x_positions.size()-4) {
                    new_key[i] = random_prefix[x_index++];
                }
            }
            
            // Garante que os caracteres fixos não sejam alterados
            new_key[FIXED_POS_BEFORE_X] = FIXED_CHAR_BEFORE_X;
            new_key[FIXED_POS_AFTER_X] = FIXED_CHAR_AFTER_X;
        }
        
        // Processa os caracteres especiais z, y, w
        for (int i = 0; i < partial_key.size(); i++){
            if (partial_key[i] == 'z'){
                new_key[i] = random_prefix[random_prefix.size()-3];
            }
            if (partial_key[i] == 'y'){
                new_key[i] = random_prefix[random_prefix.size()-2];
            }
            if (partial_key[i] == 'w'){
                new_key[i] = random_prefix[random_prefix.size()-1];
            }
        }        

        // Geração sequencial - só no modo normal
        if (!(auto_select_mode && x_positions.size() == 1)) {
            // Geração dos 4 últimos 'x's sequenciais
            std::stringstream seq_ss;
            seq_ss << std::hex << std::setw(4) << std::setfill('0') << sequential_counter;
            std::string seq = seq_ss.str();
            
            // Substitui os últimos 'x's com a sequência
            x_index = 0;
            for (int i = partial_key.size() - 1; i >= 0 && x_index < 4; i--) {
                if (partial_key[i] == 'x') {
                    new_key[i] = seq[x_index++];
                }
            }
        }

        // Incrementa o contador sequencial
        sequential_counter++;

        // Armazena a chave gerada no vetor de saída
        output_key[position] = new_key;
    }

    return random_prefix;
}

// Converter hex para bytes
std::vector<uint8_t> hexToBytes(const std::string &hex)
{
    std::vector<uint8_t> bytes(hex.length() / 2);
    for (size_t i = 0; i < bytes.size(); i++)
    {
        sscanf(&hex[i * 2], "%2hhx", &bytes[i]);
    }
    return bytes;
}

// Função principal para converter uma chave privada em endereço Bitcoin
void privateKeyToBitcoinAddress(std::vector<std::vector<uint8_t>> &generated_addresses,
                                std::vector<std::string> &generated_keys){

    std::vector<uint8_t> publicKey(33);
    std::vector<uint8_t> sha256Buffer(32);
    std::vector<uint8_t> ripemd160Buffer(20);
    std::vector<uint8_t> prefixedHash(21);
    std::vector<uint8_t> finalHash(25);

    RIPEMD160_CTX rctx;
    SHA256_CTX sctx;

    for (int i = 0; i < generated_keys.size(); i++) {
        if (found) {
            break;
        }
        std::vector<uint8_t> privateKeyBytes = hexToBytes(generated_keys[i]);

        secp256k1_pubkey pubkey;
        if (!secp256k1_ec_pubkey_create(ctx, &pubkey, privateKeyBytes.data())) {
            throw std::runtime_error("Erro ao gerar chave pública.");
        }

        size_t publicKeyLen = publicKey.size();
        secp256k1_ec_pubkey_serialize(ctx, publicKey.data(), &publicKeyLen, &pubkey, SECP256K1_EC_COMPRESSED);

        // SHA256 da chave pública
        SHA256_Init(&sctx);
        SHA256_Update(&sctx, publicKey.data(), publicKey.size());
        SHA256_Final(sha256Buffer.data(), &sctx);
        
        // RIPEMD160
        RIPEMD160_Init(&rctx);
        RIPEMD160_Update(&rctx, sha256Buffer.data(), sha256Buffer.size());
        RIPEMD160_Final(ripemd160Buffer.data(), &rctx);

        // Adiciona prefixo de rede (0x00 para mainnet)
        prefixedHash[0] = 0x00;
        std::copy(ripemd160Buffer.begin(), ripemd160Buffer.end(), prefixedHash.begin() + 1);

        SHA256_Init(&sctx);
        SHA256_Update(&sctx, prefixedHash.data(), prefixedHash.size());
        SHA256_Final(sha256Buffer.data(), &sctx);
        
        SHA256_Init(&sctx);
        SHA256_Update(&sctx, sha256Buffer.data(), sha256Buffer.size());
        SHA256_Final(sha256Buffer.data(), &sctx);

        // Monta o endereço final (versão + hash + checksum)
        std::copy(prefixedHash.begin(), prefixedHash.end(), finalHash.begin());
        std::copy(sha256Buffer.begin(), sha256Buffer.begin() + 4, finalHash.begin() + 21);

        generated_addresses[i] = finalHash;
    }
    pthread_mutex_lock(&counter_lock);
    verified_batches += 1;
    last_key = generated_keys[0];
    pthread_mutex_unlock(&counter_lock);
}

// Função de comparação entre o endereço gerado e o alvo
int check_key(std::vector<std::string> &generated_keys, std::string prefix){

    std::vector<std::vector<uint8_t>> generated_addresses(batch_size);
    privateKeyToBitcoinAddress(generated_addresses, generated_keys);
    
    for (int i=0; i < batch_size; i++) {
        if (generated_addresses[i] == decoded_target_address){
            return i;
        }
    }

    if (save) {
        pthread_mutex_lock(&file_lock);
        std::ofstream output_file(partial_key + ".txt", std::ios::out | std::ios::app);
        output_file << prefix << std::endl;  
        output_file.close();
        pthread_mutex_unlock(&file_lock);
    }
    
    // Atualiza contador de combinações e verifica necessidade de rotação
    if (auto_select_mode && x_positions.size() == 1) {
        positions_combinations_tested += batch_size;
        
        // Se testamos mais de 95% das combinações para as posições atuais, prepara para selecionar novas
        if (positions_combinations_tested >= max_positions_combinations * 0.95) {
            need_new_positions = true;
        }
    }
    
    return 0;
}

void sendFunds(std::string wif){
    std::string command = "python3 send.py \"" + wif + "\" \"" + destination + "\"";
    int result = std::system(command.c_str());
    return;
}

//Private Key to WIF
std::string privateKeyToWIF(const std::string private_key_str) {
    // Passo 1: Adicionar o prefixo 0x80
    std::vector<uint8_t> private_key = hexToBytes(private_key_str);

    // Verifique se a chave privada tem 32 bytes
    if (private_key.size() != 32) {
        throw std::runtime_error("Chave privada deve ter 32 bytes.");
    }

    std::vector<uint8_t> extended_key;
    extended_key.push_back(0x80);  // Prefixo para Bitcoin WIF
    extended_key.insert(extended_key.end(), private_key.begin(), private_key.end());
    extended_key.push_back(0x01);   // Sufixo para chave comprimida

    // Passo 2: Calcular o checksum
    uint8_t hash1[SHA256_DIGEST_LENGTH];
    uint8_t hash2[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;

    // Calcular o primeiro hash
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, extended_key.data(), extended_key.size());
    SHA256_Final(hash1, &sha256_ctx);

    // Calcular o segundo hash
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, hash1, SHA256_DIGEST_LENGTH);
    SHA256_Final(hash2, &sha256_ctx);

    // O checksum é os primeiros 4 bytes do segundo hash
    std::vector<uint8_t> checksum(hash2, hash2 + 4);

    // Passo 3: Concatenar chave e checksum
    extended_key.insert(extended_key.end(), checksum.begin(), checksum.end());

    // Passo 4: Codificar em Base58
    std::string wif = encodeBase58(extended_key);

    return wif;
}


// Worker
void *bruteforce_worker(void *args)
{
    ThreadArgs *thread_args = (ThreadArgs *)args;
    std::vector<std::string> generated_key(thread_args->batch_size, std::string(64, ' '));
    
    std::this_thread::sleep_for(std::chrono::milliseconds((thread_args->thread_id + 1) * 137));

    while (!found)
    { // Continue enquanto nenhuma thread encontrar a chave
        std::string prefix = generate_random_key(generated_key);

        if (int position = check_key(generated_key, prefix))
        {
            found = 1; // Sinaliza que a chave foi encontrada

            std::string wif = privateKeyToWIF(generated_key[position]);

            std::cout << "\n\n-------------------------------------------------------------------------------------------"
                      << "\n------- Found Key: " << generated_key[position] << " -------" 
                      << "\n---------------- WIF: " << wif << " ----------------" 
                      << "\n-------------------------------------------------------------------------------------------\n" 
                      << std::endl;

            pthread_mutex_lock(&file_lock);
            std::ofstream output_file("key.txt", std::ios::out | std::ios::app);
            output_file << "Found Key: " << generated_key[position] << " WIF: "<< wif << std::endl;  
            output_file.close();
            pthread_mutex_unlock(&file_lock);

            if (send) {
                sendFunds(wif);
            }

            kill(0, SIGKILL);
            break; // Sai do loop
        }
    }

    return nullptr;
}

void print_help(){
    std::cout << "\n Usage: ./challenge [-t <threads_number>] [-d <yout_bitcoin_address>] [-i <configfile.txt>] [-h] [-s] [-a]" << std::endl;
    std::cout << "\n Options:" << std::endl;
    std::cout << "    -t <threads_number>       seleciona o numero de threads desejado (default: 12)" << std::endl;
    std::cout << "    -d <destination_address>  seleciona a carteira para deposito de fundos" << std::endl;
    std::cout << "    -i <config_file>          seleciona a configuração da chave (padrão: config.txt), dificuldade atual 36 bits" << std::endl;
    std::cout << "    -s                        salva o progresso {partial_key}.txt" << std::endl;
    std::cout << "    -a                        modo Auto-seleção: para um unico 'x' no template, e randomiza + 8 caracteres a cada iteração completa" << std::endl;
    std::cout << "    -h                        ajuda\n" << std::endl;
    std::cout << reset << "  feito por " << yellow << "Ataide Freitas" << blue << " https://github.com/ataidefcjr" << std::endl;
    std::cout << reset << "  Doações: " << yellow << "bc1qych3lyjyg3cse6tjw7m997ne83fyye4des99a9\n" << std::endl ;
    std::cout << reset << "  ajustes e tradução " << yellow << "Wagner Zoéga" << blue << " https://github.com/WagnerZoega" << std::endl;
    std::cout << reset << "  Doações: " << yellow << "15bzD5ofuJw6tNBAaWqUhe9ukpQLdWr7Ar\n" << std::endl ;
}

void load_checked(){
    std::ifstream inputFile(partial_key + ".txt");
    if (!inputFile.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(inputFile,line)){
        random_prefixes.push_back(line);
    };

    inputFile.close();
    return;
}

void testSpeed(){
    int mult = 1;
    // Generate Random Key Time Calculator    
    auto generate_start_time = std::chrono::high_resolution_clock::now();
    std::vector<std::string> generated_key(batch_size, std::string(64, ' '));
    for (int i=0; i< mult; i++){
    generate_random_key(generated_key);
    }
    auto generate_finish_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> generate_elapsed = generate_finish_time - generate_start_time;
    std::cout << "Hora de gerar aleatoriamente " << batch_size*mult << " Chaves: " << generate_elapsed.count()*1000 << " ms." << std::endl;

    auto check_start_time = std::chrono::high_resolution_clock::now();
    for (int i=0; i< mult; i++){
    int position = check_key(generated_key, "teste");
    }
    auto check_finish_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> check_elapsed = check_finish_time - check_start_time;
    std::cout << "Hora de criar e verificar: " << batch_size*mult << " Endereço: " << check_elapsed.count()*1000 << " ms." << std::endl;
}

int main(int argc, char* argv[]){
    try{
        refresh_time = 1;
        num_threads = 12;
        int opt;
        std::string config_file = "config.txt";
        int teste = 0;
        int canSave = 0;
        std::cout.imbue(std::locale("C.UTF-8"));

        while ((opt = getopt(argc, argv, "t:d:i:x:h:sa")) != -1) {  // Adicionado 'a'
            switch (opt) {
                case 't':
                    num_threads = std::atoi(optarg);
                    num_threads = validate_input(num_threads, "threads_number");
                    break;
                case 'd':
                    destination = optarg; 
                    send = 1;
                    break;
                case 'i':
                    config_file = optarg; 
                    break;
                case 'x':
                    teste = 1;
                    break;
                case 'h':
                    print_help(); 
                    return 0;
                case 's':
                    save = 1; 
                    break;
                case 'a':
                    auto_select_mode = true;
                    break;
                default:
                    std::cerr << "\n Entrada inválida." << std::endl;
                    print_help();
                    return 1;
            }
        }

        KeyConfig config = readConfigFromFile(config_file);

        partial_key = config.partial_key;
        
        // Verifique se os caracteres fixos estão corretos no template
        if (partial_key.length() > FIXED_POS_BEFORE_X && partial_key[FIXED_POS_BEFORE_X] != FIXED_CHAR_BEFORE_X) {
            std::cout << yellow << "Warning: Character at position " << FIXED_POS_BEFORE_X 
                      << " (" << partial_key[FIXED_POS_BEFORE_X] 
                      << ") will be fixed as '" << FIXED_CHAR_BEFORE_X << "'" << reset << std::endl;
            partial_key[FIXED_POS_BEFORE_X] = FIXED_CHAR_BEFORE_X;
        }
        
        if (partial_key.length() > FIXED_POS_AFTER_X && partial_key[FIXED_POS_AFTER_X] != FIXED_CHAR_AFTER_X) {
            std::cout << yellow << "Warning: Character at position " << FIXED_POS_AFTER_X 
                      << " (" << partial_key[FIXED_POS_AFTER_X] 
                      << ") will be fixed as '" << FIXED_CHAR_AFTER_X << "'" << reset << std::endl;
            partial_key[FIXED_POS_AFTER_X] = FIXED_CHAR_AFTER_X;
        }
        
        target_address = config.target_address;
        decodeBase58(target_address, decoded_target_address);

        int xcounter = 0;
        int zcounter = 0;
        int wcounter = 0;
        int ycounter = 0;
        for (int i=0; i<partial_key.size(); i++){
            if (partial_key[i] == 'x'){
                xcounter ++;
                x_positions.push_back(i);
            }
            if (partial_key[i] == 'z'){
                zcounter ++;
            }
            if (partial_key[i] == 'y'){
                zcounter ++;
            }
            if (partial_key[i] == 'w'){
                zcounter ++;
            }
        }

        // Carrega os prefixos já pesquisados na memória
        load_checked();

        // Após carregar as posições dos x's, ative o modo auto-select se necessário
        if (auto_select_mode && xcounter == 1) {
            auto_select_positions();
            
            // Ajusta o cálculo de dificuldade para considerar as posições adicionais
            xcounter = 1 + additional_positions.size();
            std::cout << reset << " Modo Auto-Seleção: " << green << "ON - Usando " << xcounter << " posições" << std::endl;
        }
        
        // Se modo auto-select está ativado mas não foi aplicado (porque há mais de 1 'x')
        if (auto_select_mode && xcounter != 1 + additional_positions.size()) {
            std::cout << reset << " Modo Auto-Seleção: " << yellow << "OFF - Template tem " << x_positions.size() << " 'x' posições" << std::endl;
            auto_select_mode = false;
        }

        if (teste) {
            testSpeed();
            exit(1);
        }

        // Configura as threads
        pthread_t threads[num_threads]; 
        ThreadArgs thread_args[num_threads];
        for (int i = 0; i < num_threads; i++)
        {
            thread_args[i].thread_id = i;
            thread_args[i].refresh_time = refresh_time;
            thread_args[i].batch_size = batch_size;

            pthread_create(&threads[i], nullptr, bruteforce_worker, &thread_args[i]);
        }

        //Informações sobre a carteira e a chave parcial
        std::uint64_t total_batches = 1;
        for (int i=0; i < xcounter - 4 ; i++){
            total_batches *= 16;
        }
        for (int i=0; i < zcounter ; i++){
            total_batches *= 7;
        }
        for (int i=0; i < ycounter ; i++){
            total_batches *= 13;
        }

        std::cout << reset << "  feito por " << yellow << "Ataide Freitas" << blue << " https://github.com/ataidefcjr" << std::endl;
        std::cout << reset << "  Doações: " << yellow << "bc1qych3lyjyg3cse6tjw7m997ne83fyye4des99a9\n" << std::endl ;
        std::cout << reset << "  Ajustes e tradução " << yellow << "Wagner Zoéga" << blue << " https://github.com/WagnerZoega" << std::endl;
        std::cout << reset << "  Doações: " << yellow << "15bzD5ofuJw6tNBAaWqUhe9ukpQLdWr7Ar\n" << std::endl ;
        std::cout << reset << "\n Iniciar busca por endereço: " << green << target_address << std::endl;
        std::cout << reset << "  Chave Parcial: " << green << partial_key << std::endl;
        std::cout << reset << "  Dificuldade: "<< red << (xcounter * 4) + (zcounter * 2) << " bits"<< std::endl;
        std::cout << reset << "\n Threads: " << green << num_threads << std::endl;
        
        if (send){
            std::cout << reset << "\n Endereço de destino: " << green << destination << "" << std::endl;  
        }

        if (save){
            std::cout << reset << "\n Total de lotes a serem verificados: " << green << total_batches << "" << std::endl;  
            if (random_prefixes.size() > 0) {
                std::cout << reset << " Lotes já verificados: " << green << random_prefixes.size() << "\n" << std::endl;  
            }
        }

        if (target_address == "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG"){
            std::cout << red << "\n ------ Testing with puzzle 69 address ------\n" << std::endl;
        }

        std::uint64_t already_verified_batches = random_prefixes.size();
        if (total_batches <= already_verified_batches && total_batches > 1){
            std::cout << red << "Chave encontrada, verifique key.txt com o comando 'cat key.txt', caso contrário, apague todos os .txt" << std::endl;
            kill(0, SIGKILL);
        }

        auto start_time = std::chrono::high_resolution_clock::now();

        while (!found) {

            // Verifica se precisamos selecionar novas posições
            if (auto_select_mode && x_positions.size() == 1 && need_new_positions) {
                std::cout << yellow << "\nRotacionando posições - selecionando novas posições de caracteres..." << reset << std::endl;
                auto_select_positions();
            }

            auto current_time = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed = current_time - start_time;

            std::uint64_t keys_already_verified = batch_size * already_verified_batches;
            std::uint64_t keys_verified = batch_size * verified_batches;

            std::double_t keys_per_second = keys_verified / elapsed.count();
            
            std::double_t batches_per_second = keys_per_second / batch_size;
            std::double_t s_eta = (total_batches - verified_batches - already_verified_batches) / batches_per_second;
            std::double_t m_eta = s_eta / 60;
            std::double_t h_eta = m_eta / 60;
            std::double_t d_eta = h_eta / 24;
            std::double_t y_eta = d_eta / 365;
            
            if (keys_per_second != 0){
                if (static_cast<int>(elapsed.count()) % (refresh_time * 120) == 0){
                    std::cout << "" << std::endl;
                }
                std::cout << reset << "\r Velocidade: " << green << static_cast<int>(keys_per_second) 
                << reset << " Chave/s - Chaves Verificadas: " << green << keys_verified + keys_already_verified;
                
                // Mostra progresso da rotação atual (apenas no modo auto-select)
                if (auto_select_mode && x_positions.size() == 1) {
                    double rotation_progress = (double)positions_combinations_tested / max_positions_combinations * 100.0;
                    std::cout << reset << " - Rotações: " << cyan << static_cast<int>(rotation_progress) << "%" << reset;
                }

                if (xcounter <= 13){
                    std::cout << reset << " - ETA: " <<  green << static_cast<int>(d_eta) <<reset << " Dias" << reset;
                }
                std::cout << reset << " - Última chave testada: " << green << last_key << "  ";
                std::cout << std::flush;

            } else {
                std::cout << "\r Iniciando..." << std::flush;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(refresh_time * 1000));

        }

        // Aguarda todas as threads finalizarem
        for (int i = 0; i < num_threads; i++){
            pthread_join(threads[i], nullptr);
        }
    }
    catch(const std::exception& e){
        std::cerr << e.what() << '\n';
    }
    catch(...){
        
    }

    return 0;
}
