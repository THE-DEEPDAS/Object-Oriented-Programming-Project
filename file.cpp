#include <iostream>
#include <cstring>
#include <stdexcept>
#include <vector>
#include <random>

class AES {
public:
    AES(const std::vector<uint8_t>& key) {
        if (key.size() != 16) {
            throw std::invalid_argument("Key must be 16 bytes (128 bits)");
        }
        std::copy(key.begin(), key.end(), this->key);
    }

    void encrypt(const uint8_t* plaintext, uint8_t* ciphertext) {
        // Simple AES encryption logic (not a full implementation)
        for (size_t i = 0; i < 16; ++i) {
            ciphertext[i] = plaintext[i] ^ key[i]; // XOR with key (not secure)
        }
    }

    void decrypt(const uint8_t* ciphertext, uint8_t* decryptedText) {
        // Simple AES decryption logic (not a full implementation)
        for (size_t i = 0; i < 16; ++i) {
            decryptedText[i] = ciphertext[i] ^ key[i]; // XOR with key (not secure)
        }
    }

private:
    uint8_t key[16]; // 128-bit key
};

class ECC {
public:
    ECC() {
        // Generate a simple key pair (not secure)
        generateKeyPair();
    }

    void generateKeyPair() {
        // Simple key generation (not secure)
        privateKey = rand() % 100; // Random private key
        publicKey = privateKey * 2; // Simple public key (not secure)
    }

    int sign(int message) {
        // Simple signing (not secure)
        return message + privateKey; // Just adding private key (not secure)
    }

    bool verify(int message, int signature) {
        // Simple verification (not secure)
        return (signature == message + privateKey);
    }

private:
    int privateKey;
    int publicKey;
};

int main() {
    // Example usage of AES
    std::vector<uint8_t> key = { 't', 'h', 'i', 's', 'i', 's', 'a', '1', '6', 'b', 'y', 't', 'e', 'k', 'e', 'y' };
    AES aes(key);

    const char* plaintext = "Hello, World!!"; // 16 bytes
    uint8_t ciphertext[16];
    uint8_t decryptedText[16];

    aes.encrypt(reinterpret_cast<const uint8_t*>(plaintext), ciphertext);
    aes.decrypt(ciphertext, decryptedText);

    std::cout << "AES Decrypted text: ";
    for (int i = 0; i < 16; i++) {
        std::cout << static_cast<char>(decryptedText[i]);
    }
    std::cout << std::endl;

    // Example usage of ECC
    ECC ecc;

    int message = 42; // Example message
    int signature = ecc.sign(message);

    std::cout << "Signature: " << signature << std::endl;

    if (ecc.verify(message, signature)) {
        std::cout << "Signature verified!" << std::endl;
    } else {
        std::cout << "Signature verification failed!" << std::endl;
    }

    return 0;
}