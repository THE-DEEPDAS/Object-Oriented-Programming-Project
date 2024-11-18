#include <bits/stdc++.h>
using namespace std;

class DES
{
    bitset<64> key;

    void setKey(const string &keyStr)
    {
        for (int i = 0; i < 8; ++i)
        {
            key[i * 8] = keyStr[i] >> 7 & 1;
            key[i * 8 + 1] = keyStr[i] >> 6 & 1;
            key[i * 8 + 2] = keyStr[i] >> 5 & 1;
            key[i * 8 + 3] = keyStr[i] >> 4 & 1;
            key[i * 8 + 4] = keyStr[i] >> 3 & 1;
            key[i * 8 + 5] = keyStr[i] >> 2 & 1;
            key[i * 8 + 6] = keyStr[i] >> 1 & 1;
            key[i * 8 + 7] = keyStr[i] & 1;
        }
    }

    string padInput(const string &input)
    {
        int paddedLength = ((input.length() / 8) + 1) * 8;
        string paddedInput(paddedLength, '\0');
        memcpy(&paddedInput[0], input.c_str(), input.length());
        return paddedInput;
    }

    string unpadOutput(const string &output)
    {
        return output.substr(0, output.find('\0'));
    }

    string encryptBlock(const string &block)
    {
        string encryptedBlock = block;
        return encryptedBlock;
    }

    string decryptBlock(const string &block)
    {
        string decryptedBlock = block;
        return decryptedBlock;
    }

    public:
    DES(const string &key)
    {
        setKey(key);
    }

    string encrypt(const string &plaintext)
    {
        string paddedInput = padInput(plaintext);
        string ciphertext;

        for (size_t i = 0; i < paddedInput.size(); i += 8)
        {
            ciphertext += encryptBlock(paddedInput.substr(i, 8));
        }

        return ciphertext;
    }

    string decrypt(const string &ciphertext)
    {
        string plaintext;

        for (size_t i = 0; i < ciphertext.size(); i += 8)
        {
            plaintext += decryptBlock(ciphertext.substr(i, 8));
        }

        return unpadOutput(plaintext);
    }
};

int main()
{
    string key = "12345678";
    string message = "Hello, World!";

    DES des(key);

    string encrypted = des.encrypt(message);
    string decrypted = des.decrypt(encrypted);

    cout << "Original: " << message << endl;
    cout << "Encrypted: ";
    for (unsigned char c : encrypted)
    {
        cout << hex << (int)c;
    }
    cout << endl;
    cout << "Decrypted: " << decrypted << endl;

    return 0;
}