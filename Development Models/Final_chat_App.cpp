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
       
    public:
         String username;
        String password;
        Vector<Message> inbox;

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

    void saveUsersToFile() {
        ofstream file("users.dat", ios::binary);
        if (!file.is_open()) return;

        size_t userCount = users.size();
        file.write(reinterpret_cast<char*>(&userCount), sizeof(userCount));

        for (const auto &user : users) {
            size_t usernameLength = user.getUsername().size();
            size_t passwordLength = user.password.size();

            file.write(reinterpret_cast<char*>(&usernameLength), sizeof(usernameLength));
            file.write(user.getUsername().c_str(), usernameLength);
            file.write(reinterpret_cast<char*>(&passwordLength), sizeof(passwordLength));
            file.write(user.password.c_str(), passwordLength);
        }
        file.close();
    }

    void loadUsersFromFile() {
        ifstream file("users.dat", ios::binary);
        if (!file.is_open()) return;

        size_t userCount;
        file.read(reinterpret_cast<char*>(&userCount), sizeof(userCount));

        for (size_t i = 0; i < userCount; ++i) {
            size_t usernameLength;
            file.read(reinterpret_cast<char*>(&usernameLength), sizeof(usernameLength));
            String username(usernameLength, '\0');
            file.read(&username[0], usernameLength);

            size_t passwordLength;
            file.read(reinterpret_cast<char*>(&passwordLength), sizeof(passwordLength));
            String password(passwordLength, '\0');
            file.read(&password[0], passwordLength);

            users.push_back(Person(username, password));
            userPasswords[username] = password;
        }
        file.close();
    }
}

int main() {
    chatapp::loadUsersFromFile(); // Load existing users from file

    DES des("12345678");
    AES aes("A1B2C3D4E5F6G7H8");
    ECC ecc;

    while (true) {
        Gate:
        
        if(chatapp::users.empty()) {
            cout << "No Users Yet" << endl;
        } else {
            cout << "Available usernames:\n";
            for (const auto &user : chatapp::users) {
                cout << "- " << user.getUsername() << endl;
            }
        }
        
        cout << "1. Sign Up" << endl;
        cout << "2. Log In" << endl;
        cout << "3. Exit" << endl;
        cout << "Select an option : ";
        int choice;
        cin >> choice;

        if(choice == 1) {
            chatapp::String username, password;
            cout << "Enter a username: ";
            cin >> username;
            cout << "Enter a password: ";
            cin >> password;
            chatapp::createAccount(username, password);
            chatapp::saveUsersToFile();
            continue;
        } else if (choice == 3) {
            cout << "Exiting..." << endl;
            return 0;
        } else if (choice != 2) {
            cout << "Invalid option. Please try again.";
            goto Gate;
        }

        chatapp::String selectedUsername;
        cout << "Select your username: ";
        cin >> selectedUsername;
        chatapp::String password;
        cout << "Enter your password: ";
        cin >> password;

        chatapp::Person *loggedInUser = chatapp::login(selectedUsername, password);
        if (!loggedInUser)
            continue; // If login fails, start again

        while (true) { // Inner loop for logged-in user actions
            cout << "\n1. View Inbox\n";
            cout << "2. Send Message\n";
            cout << "3. Logout\n";
            cout << "4. Exit\n";
            cout << "Select an option: ";
            int choice;
            cin >> choice;

            switch (choice) {
            case 1:
                loggedInUser->viewInbox(des, aes, ecc);
                break;
            case 2: {
                chatapp::String recipientUsername, messageContent;
                cout << "Enter recipient username: ";
                cin >> recipientUsername;

                cout << "Enter your message: ";
                cin.ignore();
                getline(cin, messageContent);

                // Encrypt the message using the chosen algorithm
                cout << "Select encryption algorithm (1: DES, 2: AES, 3: ECC): ";
                int algoChoice;
                cin >> algoChoice;

                if (algoChoice == 1) {
                    string encryptedMessage = des.encrypt(messageContent);
                    loggedInUser->sendMessage(*chatapp::login(recipientUsername, chatapp::userPasswords[recipientUsername]), encryptedMessage, "DES");
                } else if (algoChoice == 2) {
                    string encryptedMessage = aes.encrypt(messageContent);
                    loggedInUser->sendMessage(*chatapp::login(recipientUsername, chatapp::userPasswords[recipientUsername]), encryptedMessage, "AES");
                } else if (algoChoice == 3) {
                    string encryptedMessage = ecc.encrypt(messageContent);
                    loggedInUser->sendMessage(*chatapp::login(recipientUsername, chatapp::userPasswords[recipientUsername]), encryptedMessage, "ECC");
                } else {
                    cout << "Invalid encryption algorithm.\n";
                }
                break;
            }
            case 3:
                loggedInUser = nullptr; // Log out
                cout << "Logged out.\n";
                goto Gate;
            case 4:
                cout << "Exiting..." << endl;
                return 0;
            default:
                cout << "Invalid option. Please try again.\n";
                break;
            }
        }
    }
}