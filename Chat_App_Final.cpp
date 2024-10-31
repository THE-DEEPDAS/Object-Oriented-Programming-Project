#include <bits/stdc++.h>
using namespace std;

// DES Encryption/Decryption (simplified for example purposes)
class DES {
    string key;

    void setKey(const string &keyStr) {
        key = keyStr.substr(0, 8); // Use the first 8 characters as the key
    }

public:
    DES(const string &keyStr) {
        setKey(keyStr);
    }

    string encrypt(const string &plaintext) {
        string ciphertext = plaintext;
        for (size_t i = 0; i < ciphertext.size(); ++i) {
            ciphertext[i] ^= key[i % key.size()]; // Simple XOR encryption
        }
        return ciphertext;
    }

    string decrypt(const string &ciphertext) {
        return encrypt(ciphertext); // XOR decryption is the same as encryption
    }
};

// AES Encryption/Decryption (simplified for example purposes)
class AES {
    string key;

public:
    AES(const string &keyStr) : key(keyStr.substr(0, 16)) {} // Use first 16 characters

    string encrypt(const string &plaintext) {
        string ciphertext = plaintext;
        for (size_t i = 0; i < ciphertext.size(); ++i) {
            ciphertext[i] ^= key[i % key.size()];
        }
        return ciphertext;
    }

    string decrypt(const string &ciphertext) {
        return encrypt(ciphertext);
    }
};

// ECC Encryption/Decryption (simplified for example purposes)
class ECC {
    int privateKey;
    int publicKey;

public:
    ECC() {
        privateKey = rand() % 100;
        publicKey = privateKey * 2;
    }

    string encrypt(const string &plaintext) {
        string ciphertext = plaintext;
        for (char &ch : ciphertext) {
            ch += publicKey % 256;
        }
        return ciphertext;
    }

    string decrypt(const string &ciphertext) {
        string plaintext = ciphertext;
        for (char &ch : plaintext) {
            ch -= publicKey % 256;
        }
        return plaintext;
    }
};

// Main chat application structure
namespace chatapp {
    using String = string;
    template <typename T> using Vector = vector<T>;
    using Map = unordered_map<String, String>;

    class Message {
    public:
        String sender;
        String content;
        String algorithm;
        String timestamp;
        Message(const String &sender, const String &content, const String &algorithm)
            : sender(sender), content(content), algorithm(algorithm), timestamp(getTimestamp()) {}

    private:
        static String getTimestamp() {
            time_t now = time(0);
            char dt[20];
            strftime(dt, sizeof(dt), "%Y-%m-%d %H:%M:%S", localtime(&now));
            return String(dt);
        }
    };

    class Person {
        String username;
        String password;
        Vector<Message> inbox;

    public:
        Person(const String &user, const String &pass) : username(user), password(pass) {}

        String getUsername() const { return username; }
        bool checkPassword(const String &pass) const { return password == pass; }

        void sendMessage(Person &recipient, const String &content, const String &algorithm) {
            recipient.inbox.push_back(Message(username, content, algorithm));
            cout << "Message sent to " << recipient.getUsername() << endl;
        }

        void viewInbox(DES &des, AES &aes, ECC &ecc) {
            for (auto &msg : inbox) {
                String decryptedMessage;
                
                if (msg.algorithm == "DES") decryptedMessage = des.decrypt(msg.content);
                else if (msg.algorithm == "AES") decryptedMessage = aes.decrypt(msg.content);
                else if (msg.algorithm == "ECC") decryptedMessage = ecc.decrypt(msg.content);
                
                cout << "From " << msg.sender << " (" << msg.algorithm << "): " 
                     << decryptedMessage << " [" << msg.timestamp << "]\n";
            }
            inbox.clear();
        }
    };

    Map userPasswords;
    Vector<Person> users;

    void createAccount(const String &username, const String &password) {
        users.push_back(Person(username, password));
        userPasswords[username] = password;
    }

    Person* login(const String &username, const String &password) {
        for (auto &user : users) {
            if (user.getUsername() == username && user.checkPassword(password)) {
                return &user;
            }
        }
        cout << "Invalid username or password.\n";
        return nullptr;
    }
}

int main() {
    chatapp::createAccount("user1", "pass1");
    chatapp::createAccount("user2", "pass2");

    DES des("12345678");
    AES aes("A1B2C3D4E5F6G7H8");
    ECC ecc;

    chatapp::Person *user1 = chatapp::login("user1", "pass1");
    chatapp::Person *user2 = chatapp::login("user2", "pass2");

    if (user1 && user2) {
        string message;
        cout << "Enter a message: (please put 1st a space first)";
        cin.ignore();
        getline(cin, message);

        string encryptedMessageDES = des.encrypt(message);
        string encryptedMessageAES = aes.encrypt(message);
        string encryptedMessageECC = ecc.encrypt(message);

        cout << "\n--- Encrypted Messages ---\n";
        cout << "DES Encrypted: " << encryptedMessageDES << endl;
        cout << "AES Encrypted: " << encryptedMessageAES << endl;
        cout << "ECC Encrypted: " << encryptedMessageECC << endl;

        user1->sendMessage(*user2, encryptedMessageDES, "DES");
        user1->sendMessage(*user2, encryptedMessageAES, "AES");
        user1->sendMessage(*user2, encryptedMessageECC, "ECC");

        cout << "\n--- Inbox for user2 ---\n";
        user2->viewInbox(des, aes, ecc);
    }
    return 0;
}
