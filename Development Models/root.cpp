#include <iostream>
// #include <openssl/aes.h>
// #include <openssl/ec.h>
// #include <openssl/obj_mac.h>
#include <cstring>
#include <cmath>

// // AES class for encryption and decryption
// class AES {
// public:
//     AES(const unsigned char* key) {
//         AES_set_encrypt_key(key, 128, &encryptKey);  // Set the encryption key (128-bit)
//         AES_set_decrypt_key(key, 128, &decryptKey);  // Set the decryption key
//     }

//     void encrypt(const unsigned char* plaintext, unsigned char* ciphertext) {
//         AES_encrypt(plaintext, ciphertext, &encryptKey);
//     }

//     void decrypt(const unsigned char* ciphertext, unsigned char* decryptedText) {
//         AES_decrypt(ciphertext, decryptedText, &decryptKey);
//     }

// private:
//     AES_KEY encryptKey, decryptKey;
// };

// // ECC class for encryption and decryption (using OpenSSL)
// class ECC {
// public:
//     ECC() {
//         // Initialize elliptic curve key
//         ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
//         EC_KEY_generate_key(ecKey);
//     }

//     ~ECC() {
//         EC_KEY_free(ecKey);
//     }

//     void encrypt() {
//         // ECC typically used in ECDH or ECDSA
//         std::cout << "ECC encryption operation (placeholder)\n";
//     }

//     void decrypt() {
//         // ECC decryption example
//         std::cout << "ECC decryption operation (placeholder)\n";
//     }

// private:
//     EC_KEY* ecKey;
// };

// Custom RSA class (without any library)
class RSA {
public:
    RSA(int p, int q) {
        n = p * q;  // modulus
        phi = (p - 1) * (q - 1);

        e = 3;  // Small odd number for e, co-prime with phi
        while (gcd(e, phi) != 1) {
            e += 2;  // Find next odd number if e and phi are not co-prime
        }

        d = modInverse(e, phi);  // Calculate the private key d
    }

    int encrypt(int message) {
        return modExp(message, e, n);  // Ciphertext = (message^e) % n
    }

    int decrypt(int ciphertext) {
        return modExp(ciphertext, d, n);  // Plaintext = (ciphertext^d) % n
    }

private:
    int n, phi, e, d;

    // Euclidean Algorithm to find GCD
    int gcd(int a, int b) {
        return b == 0 ? a : gcd(b, a % b);
    }

    // Extended Euclidean Algorithm to find modular inverse
    int modInverse(int a, int m) {
        int m0 = m, t, q;
        int x0 = 0, x1 = 1;

        if (m == 1)
            return 0;

        while (a > 1) {
            q = a / m;
            t = m;

            m = a % m;
            a = t;
            t = x0;

            x0 = x1 - q * x0;
            x1 = t;
        }

        if (x1 < 0)
            x1 += m0;

        return x1;
    }

    // Modular exponentiation (base^exp % mod)
    int modExp(int base, int exp, int mod) {
        int result = 1;
        base = base % mod;
        while (exp > 0) {
            if (exp % 2 == 1) {
                result = (result * base) % mod;
            }
            exp = exp >> 1;
            base = (base * base) % mod;
        }
        return result;
    }
};

int main() {
    // // AES Testing
    // unsigned char key[16] = "0123456789abcdef";  // AES key (128 bits)
    // unsigned char plaintext[16] = "HelloAESWorld12";  // Test plaintext
    // unsigned char ciphertext[16];
    // unsigned char decryptedText[16];

    // AES aes(key);
    // aes.encrypt(plaintext, ciphertext);
    // aes.decrypt(ciphertext, decryptedText);

    // std::cout << "AES Decrypted text: ";
    // for (int i = 0; i < 16; i++) {
    //     std::cout << decryptedText[i];
    // }
    // std::cout << std::endl;

    // // ECC Testing
    // ECC ecc;
    // ecc.encrypt();
    // ecc.decrypt();

    // RSA Testing
    int p = 61, q = 53;  // Two large prime numbers
    RSA rsa(p, q);

    int message = 65;  // Example message
    int encryptedMessage = rsa.encrypt(message);
    int decryptedMessage = rsa.decrypt(encryptedMessage);

    std::cout << "RSA Encrypted: " << encryptedMessage << std::endl;
    std::cout << "RSA Decrypted: " << decryptedMessage << std::endl;

    return 0;
}
