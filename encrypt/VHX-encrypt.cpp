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

bool is_probably_prime(uint64_t suspect, int checks = 5) {
    if (suspect < 2) return false;
    if (suspect % 2 == 0) return suspect == 2;

    uint64_t decrement = suspect - 1;
    uint64_t twist = 0;
    while ((decrement & 1) == 0) {
        decrement >>= 1;
        twist++;
    }

    std::mt19937_64 twist_engine(std::time(0));
    for (int round = 0; round < checks; round++) {
        uint64_t witness = 2 + twist_engine() % (suspect - 3);
        uint64_t x = power_mod(witness, decrement, suspect);
        if (x == 1 || x == suspect - 1) continue;

        for (uint64_t i = 0; i < twist - 1; i++) {
            x = power_mod(x, 2, suspect);
            if (x == suspect - 1) goto next_round;
        }
        return false;
    next_round:;
    }
    return true;
}

uint64_t generate_big_prime() {
    std::mt19937_64 prime_engine(std::time(0));
    while (true) {
        uint64_t candidate = prime_engine() % (1 << 16) + (1 << 15);
        if (is_probably_prime(candidate)) return candidate;
    }
}

// rsa realization
struct SecretCombo {
    uint64_t modulus;
    uint64_t public_exponent;
    uint64_t private_exponent;
};

SecretCombo create_secret_combo() {
    uint64_t first_prime = generate_big_prime();
    uint64_t second_prime = generate_big_prime();
    uint64_t modulus = first_prime * second_prime;
    uint64_t euler = (first_prime - 1) * (second_prime - 1);
    uint64_t public_exp = 65537;
    uint64_t x = 1, y = 0, gcd = public_exp, old_gcd = euler;
    while (old_gcd) {
        uint64_t quotient = gcd / old_gcd;
        uint64_t remainder = gcd - quotient * old_gcd;
        gcd = old_gcd;
        old_gcd = remainder;
        uint64_t temp = x - quotient * y;
        x = y;
        y = temp;
    }
    if (x < 0) x += euler;
    return { modulus, public_exp, x };
}

uint64_t scramble_with_rsa(uint64_t data, uint64_t exponent, uint64_t modulus) {
    return power_mod(data, exponent, modulus);
}

// sha256 realization
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
    uint32_t hash_state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    std::vector<uint8_t> message(input.begin(), input.end());
    uint64_t original_bit_length = message.size() * 8;
    message.push_back(0x80);
    // add 0 before len (448 mod 512)
    while ((message.size() * 8) % 512 != 448) {
        message.push_back(0);
    }

    // add message len (64 bit)
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
        // transform to 64 words 
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
    // gen hash after all magic
    std::ostringstream hash_stream;
    for (int i = 0; i < 8; i++) {
        hash_stream << std::hex << std::setw(8) << std::setfill('0') << hash_state[i];
    }
    return hash_stream.str();
}

// aes realization
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

void substitute_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = substitution_box[state[i]];
    }
}

void shift_rows(uint8_t state[16]) {
    uint8_t temp;

    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

void mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        uint8_t a = state[i * 4];
        uint8_t b = state[i * 4 + 1];
        uint8_t c = state[i * 4 + 2];
        uint8_t d = state[i * 4 + 3];
        state[i * 4] = (uint8_t)((0x02 * a) ^ (0x03 * b) ^ c ^ d);
        state[i * 4 + 1] = (uint8_t)(a ^ (0x02 * b) ^ (0x03 * c) ^ d);
        state[i * 4 + 2] = (uint8_t)(a ^ b ^ (0x02 * c) ^ (0x03 * d));
        state[i * 4 + 3] = (uint8_t)((0x03 * a) ^ b ^ c ^ (0x02 * d));
    }
}

void add_round_key(uint8_t state[16], const uint8_t round_key[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

void expand_key(const uint8_t key[16], uint8_t round_keys[176]) {
    const uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
    // first 16 bytes is source key
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

void encrypt_block(uint8_t plaintext[16], const uint8_t key[16]) {
    uint8_t state[16];
    uint8_t round_keys[176];
    expand_key(key, round_keys);
    for (int i = 0; i < 16; i++) {
        state[i] = plaintext[i] ^ round_keys[i];
    }
    // 9 rounds
    for (int round = 1; round <= 9; round++) {
        substitute_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * 16);
    }
    // final encrypt round (without mixcolumns)
    substitute_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys + 160);
    for (int i = 0; i < 16; i++) {
        plaintext[i] = state[i];
    }
}

struct SecretPackage {
    std::vector<uint8_t> encrypted_data;
    uint64_t encrypted_key;
    std::string hash_digest;
};

SecretPackage encrypt_secret_message(uint64_t server_key, uint64_t server_modulus, const std::string& message) {
    SecretPackage package;
    uint8_t aes_key[16];
    std::mt19937_64 key_engine(std::time(0));
    for (int i = 0; i < 16; i++) {
        aes_key[i] = key_engine() % 256;
    }
    // encrypt aes keys with rsa
    uint64_t key_part1 = *reinterpret_cast<uint64_t*>(aes_key);
    uint64_t key_part2 = *reinterpret_cast<uint64_t*>(aes_key + 8);
    package.encrypted_key = scramble_with_rsa(key_part1, server_key, server_modulus);
    std::vector<uint8_t> message_data(message.begin(), message.end());
    size_t padded_length = ((message_data.size() + 15) / 16) * 16;
    message_data.resize(padded_length, 0);
    for (size_t i = 0; i < message_data.size(); i += 16) {
        encrypt_block(message_data.data() + i, aes_key);
    }
    package.encrypted_data = message_data;
    package.hash_digest = create_hash(message);
    return package;
}

int main() {
    // gen rsa keys
    SecretCombo server_keys = create_secret_combo();
    // data for encrypt, in example its message
    std::string secret_message = "very secret message";
    // encrypt data
    SecretPackage encrypted = encrypt_secret_message(
        server_keys.public_exponent,
        server_keys.modulus,
        secret_message
    );
    std::cout << "encrypted key: " << encrypted.encrypted_key << "\n";
    std::cout << "encrypted data size: " << encrypted.encrypted_data.size() << " bytes\n";
    std::cout << "message hash: " << encrypted.hash_digest << "\n";
    return 0;
}