#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <ctime>

std::vector<uint8_t> generate_key(size_t size = 32) {
    std::vector<uint8_t> key(size);
    for (size_t i = 0; i < size; i++) {
        key[i] = rand() % 256;
    }
    return key;
}

uint32_t vhx_transform(uint32_t x, uint32_t key_fragment) {
    return (x * x * 7 + x * 19 + key_fragment) % 997;
}

std::vector<uint8_t> encrypt_vhx(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> encrypted(data.size());
    for (size_t i = 0; i < data.size(); i++) {
        encrypted[i] = (vhx_transform(data[i], key[i % key.size()]) ^ key[i % key.size()]) & 0xFF;
    }
    return encrypted;
}

std::vector<uint8_t> decrypt_vhx(const std::vector<uint8_t>& encrypted, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> decrypted(encrypted.size());
    for (size_t i = 0; i < encrypted.size(); i++) {
        decrypted[i] = (encrypted[i] ^ key[i % key.size()]) & 0xFF;
    }
    return decrypted;
}

int main() {
    srand(time(0));

    std::string input_text = "hello, vhx encryption!";
    std::vector<uint8_t> data(input_text.begin(), input_text.end());

    std::vector<uint8_t> key = generate_key();

    std::vector<uint8_t> encrypted = encrypt_vhx(data, key);
    std::vector<uint8_t> decrypted = decrypt_vhx(encrypted, key);

    std::cout << "original text: " << input_text << std::endl;

    std::cout << "encrypted data: ";
    for (uint8_t byte : encrypted) {
        std::cout << std::hex << (int)byte << " ";
    }
    std::cout << std::endl;

    std::cout << "decrypted text: ";
    for (uint8_t byte : decrypted) {
        std::cout << (char)byte;
    }
    std::cout << std::endl;

    return 0;
}
