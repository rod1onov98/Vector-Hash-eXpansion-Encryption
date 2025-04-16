#include <iostream>
#include <vector>
#include <cstdint>
#include <random>
#include <ctime>
#include <cmath>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>


#define ROTL32(blob, shift) (((blob) << (shift)) | ((blob) >> (32 - (shift))))
#define ROTR32(blob, shift) (((blob) >> (shift)) | ((blob) << (32 - (shift))))

uint64_t power_mod(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    while (exp) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

// rsa decrypt
uint64_t unscramble_with_rsa(uint64_t data, uint64_t exponent, uint64_t modulus) {
    return power_mod(data, exponent, modulus);
}

// aes realization(take from client-side)
const uint8_t substitution_box[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0x0F, 0x61,
    0x77, 0xC1, 0x20, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87,
    0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D,
    0x0E, 0xB0, 0x54, 0xBB, 0x16, 0x2B, 0xE8, 0x1C, 0xA6, 0xB9, 0xF4, 0x74, 0x1F, 0x4B, 0xBD, 0x8B,
    0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0C, 0x7B, 0xDF, 0x54
};

const uint8_t inverse_substitution_box[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

void inverse_substitute_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = inverse_substitution_box[state[i]];
    }
}

void inverse_shift_rows(uint8_t state[16]) {
    uint8_t temp;
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

uint8_t galois_multiply(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void inverse_mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        uint8_t a = state[i * 4];
        uint8_t b = state[i * 4 + 1];
        uint8_t c = state[i * 4 + 2];
        uint8_t d = state[i * 4 + 3];
        state[i * 4] = (uint8_t)(galois_multiply(a, 0x0e) ^ galois_multiply(b, 0x0b) ^
            galois_multiply(c, 0x0d) ^ galois_multiply(d, 0x09));
        state[i * 4 + 1] = (uint8_t)(galois_multiply(a, 0x09) ^ galois_multiply(b, 0x0e) ^
            galois_multiply(c, 0x0b) ^ galois_multiply(d, 0x0d));
        state[i * 4 + 2] = (uint8_t)(galois_multiply(a, 0x0d) ^ galois_multiply(b, 0x09) ^
            galois_multiply(c, 0x0e) ^ galois_multiply(d, 0x0b));
        state[i * 4 + 3] = (uint8_t)(galois_multiply(a, 0x0b) ^ galois_multiply(b, 0x0d) ^
            galois_multiply(c, 0x09) ^ galois_multiply(d, 0x0e));
    }
}

void expand_key(const uint8_t key[16], uint8_t round_keys[176]) {
    const uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
    for (int i = 0; i < 16; i++) {
        round_keys[i] = key[i];
    }
    for (int i = 16; i < 176; i += 4) {
        uint8_t temp[4];
        for (int j = 0; j < 4; j++) {
            temp[j] = round_keys[i - 4 + j];
        }
        if (i % 16 == 0) {
            // rotword
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // subword
            for (int j = 0; j < 4; j++) {
                temp[j] = substitution_box[temp[j]];
            }
            // rcon
            temp[0] ^= rcon[i / 16 - 1];
        }
        for (int j = 0; j < 4; j++) {
            round_keys[i + j] = round_keys[i - 16 + j] ^ temp[j];
        }
    }
}

void decrypt_block(uint8_t ciphertext[16], const uint8_t key[16]) {
    uint8_t state[16];
    uint8_t round_keys[176];
    expand_key(key, round_keys);
    for (int i = 0; i < 16; i++) {
        state[i] = ciphertext[i] ^ round_keys[160 + i];
    }
    // 9 rounds
    for (int round = 9; round >= 1; round--) {
        inverse_shift_rows(state);
        inverse_substitute_bytes(state);
        for (int i = 0; i < 16; i++) {
            state[i] ^= round_keys[round * 16 + i];
        }
        if (round != 9) {
            inverse_mix_columns(state);
        }
    }
    inverse_shift_rows(state);
    inverse_substitute_bytes(state);
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_keys[i];
    }
    for (int i = 0; i < 16; i++) {
        ciphertext[i] = state[i];
    }
}

// sha256 realization(take from client-side)
const uint32_t hash_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

std::string create_hash(const std::string& input) {
    uint32_t hash_state[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    std::vector<uint8_t> message(input.begin(), input.end());
    uint64_t original_bit_length = message.size() * 8;
    message.push_back(0x80);
    while ((message.size() * 8) % 512 != 448) {
        message.push_back(0);
    }
    for (int i = 7; i >= 0; i--) {
        message.push_back((original_bit_length >> (i * 8)) & 0xFF);
    }
    for (size_t chunk = 0; chunk < message.size(); chunk += 64) {
        uint32_t words[64];
        uint32_t a, b, c, d, e, f, g, h;

        for (int i = 0; i < 16; i++) {
            words[i] = (message[chunk + i * 4] << 24) |
                (message[chunk + i * 4 + 1] << 16) |
                (message[chunk + i * 4 + 2] << 8) |
                message[chunk + i * 4 + 3];
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROTR32(words[i - 15], 7) ^ ROTR32(words[i - 15], 18) ^ (words[i - 15] >> 3);
            uint32_t s1 = ROTR32(words[i - 2], 17) ^ ROTR32(words[i - 2], 19) ^ (words[i - 2] >> 10);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        a = hash_state[0]; b = hash_state[1]; c = hash_state[2]; d = hash_state[3];
        e = hash_state[4]; f = hash_state[5]; g = hash_state[6]; h = hash_state[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + hash_constants[i] + words[i];
            uint32_t S0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }
        hash_state[0] += a; hash_state[1] += b; hash_state[2] += c; hash_state[3] += d;
        hash_state[4] += e; hash_state[5] += f; hash_state[6] += g; hash_state[7] += h;
    }
    std::ostringstream hash_stream;
    for (int i = 0; i < 8; i++) {
        hash_stream << std::hex << std::setw(8) << std::setfill('0') << hash_state[i];
    }
    return hash_stream.str();
}

// structure of data(example)
struct SecretPackage {
    std::vector<uint8_t> encrypted_data;
    uint64_t encrypted_key_part1;
    uint64_t encrypted_key_part2;
    std::string hash_digest;
};

struct DecryptedPackage {
    std::string message;
    bool is_valid;
};

// main decrypt function(i'ts just example, if you use this on your server, change to your realization of decrypt)
DecryptedPackage decrypt_secret_message(
    uint64_t private_key,
    uint64_t modulus,
    const SecretPackage& package) {
    DecryptedPackage result;
    // decrypt 2 parts of aes key
    uint64_t decrypted_key_part1 = unscramble_with_rsa(package.encrypted_key_part1, private_key, modulus);
    uint64_t decrypted_key_part2 = unscramble_with_rsa(package.encrypted_key_part2, private_key, modulus);
    // gen aes key
    uint8_t aes_key[16];
    *reinterpret_cast<uint64_t*>(aes_key) = decrypted_key_part1;
    *reinterpret_cast<uint64_t*>(aes_key + 8) = decrypted_key_part2;
    // decrypt data
    std::vector<uint8_t> decrypted_data = package.encrypted_data;
    for (size_t i = 0; i < decrypted_data.size(); i += 16) {
        decrypt_block(decrypted_data.data() + i, aes_key);
    }
    size_t message_length = 0;
    while (message_length < decrypted_data.size() && decrypted_data[message_length] != 0) {
        message_length++;
    }
    result.message = std::string(decrypted_data.begin(), decrypted_data.begin() + message_length);
    // validate hash
    result.is_valid = (create_hash(result.message) == package.hash_digest);
    return result;
}

int main() {
    // example for use on server-side
    uint64_t server_private_key = 0x1234567890ABCDEF; // change to real private key
    uint64_t server_modulus = 0xFEDCBA0987654321;     // change to real module
    // received packet from client (in real using needs take from network/file)
    SecretPackage received_package;
    // message decrypt
    DecryptedPackage decrypted = decrypt_secret_message(
        server_private_key,
        server_modulus,
        received_package
    );
    if (decrypted.is_valid) {
        std::cout << "message successfully decrypted:\n";
        std::cout << decrypted.message << "\n";
    }
    return 0;
}