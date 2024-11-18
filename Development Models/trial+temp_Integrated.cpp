#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <ctime>
#include <algorithm>
#include <bitset>
#include <cstring>


// Custom namespace to replace std
namespace chatapp {
    using String = std::string;
    template<typename T>
    using Vector = std::vector<T>;
    using Pair = std::pair<String, String>;
    using Map = std::unordered_map<String, String>;

    // Utility to generate a timestamp
    String getTimestamp() {
        std::time_t now = std::time(0);
        char* dt = ctime(&now);
        return dt;
    }

    // Simulated password hashing function (in reality use secure libraries)
    String hashPassword(const String& password) {
        return "hashed_" + password; // Simple mock hash function
    }

    // DES Encryption class
    class DES {
        std::bitset<64> key;

        void setKey(const String &keyStr) {
            for (int i = 0; i < 8; ++i) {
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

        String padInput(const String &input) {
            int paddedLength = ((input.length() / 8) + 1) * 8;
            String paddedInput(paddedLength, '\0');
            memcpy(&paddedInput[0], input.c_str(), input.length());
            return paddedInput;
        }

        String unpadOutput(const String &output) {
            return output.substr(0, output.find('\0'));
        }

        String encryptBlock(const String &block) {
            String encryptedBlock = block;
            // Simple mock encryption; actual DES logic will be complex
            return encryptedBlock;
        }

        String decryptBlock(const String &block) {
            String decryptedBlock = block;
            // Simple mock decryption
            return decryptedBlock;
        }

    public:
        DES(const String &key) {
            setKey(key);
        }

        String encrypt(const String &plaintext) {
            String paddedInput = padInput(plaintext);
            String ciphertext;

            for (size_t i = 0; i < paddedInput.size(); i += 8) {
                ciphertext += encryptBlock(paddedInput.substr(i, 8));
            }

            return ciphertext;
        }

        String decrypt(const String &ciphertext) {
            String plaintext;

            for (size_t i = 0; i < ciphertext.size(); i += 8) {
                plaintext += decryptBlock(ciphertext.substr(i, 8));
            }

            return unpadOutput(plaintext);
        }
    };

    // Message class to hold individual messages
    class Message {
    public:
        String sender;
        String content;
        String timestamp;

        Message(const String& sender, const String& content) 
            : sender(sender), content(content), timestamp(getTimestamp()) {}
    };

    // Person class to represent individual users
    class Person {
    private:
        String username;
        String password;
        Vector<String> friends;
        Vector<String> friendRequests;
        Vector<Message> inbox;
        DES des;  // DES instance for this user

    public:
        Person(const String& user, const String& pass) 
            : username(user), password(hashPassword(pass)), des("12345678") {}  // Default DES key

        String getUsername() const { return username; }

        bool checkPassword(const String& pass) const {
            return password == hashPassword(pass);
        }

        void sendMessage(Person& recipient, const String& content) {
            if (isFriend(recipient.getUsername())) {
                String encryptedMessage = des.encrypt(content);
                recipient.inbox.push_back(Message(username, encryptedMessage));
                std::cout << "Message sent to " << recipient.getUsername() << " (encrypted).\n";
            } else {
                std::cout << recipient.getUsername() << " is not your friend. Add them first.\n";
            }
        }

        void sendFriendRequest(Person& recipient) {
            if (!isFriend(recipient.getUsername()) && !recipient.hasFriendRequest(username)) {
                recipient.friendRequests.push_back(username);
                std::cout << "Friend request sent to " << recipient.getUsername() << "\n";
            } else {
                std::cout << "Friend request already pending or you are already friends.\n";
            }
        }

        void acceptFriendRequest(const String& requester) {
            auto it = std::find(friendRequests.begin(), friendRequests.end(), requester);
            if (it != friendRequests.end()) {
                friends.push_back(requester);
                friendRequests.erase(it);
                std::cout << "Friend request from " << requester << " accepted.\n";
            } else {
                std::cout << "No friend request from " << requester << ".\n";
            }
        }

        void viewInbox() {
            if (inbox.empty()) {
                std::cout << "Inbox is empty.\n";
            } else {
                for (const auto& msg : inbox) {
                    String decryptedMessage = des.decrypt(msg.content);
                    std::cout << "Message from " << msg.sender << ": " << decryptedMessage << " [" << msg.timestamp << "]\n";
                }
                inbox.clear();
            }
        }

        bool isFriend(const String& friendName) const {
            return std::find(friends.begin(), friends.end(), friendName) != friends.end();
        }

        bool hasFriendRequest(const String& sender) const {
            return std::find(friendRequests.begin(), friendRequests.end(), sender) != friendRequests.end();
        }

        void saveToFile(std::ofstream& file) const {
            file << username << "\n" << password << "\n";
            file << friends.size() << "\n";
            for (const auto& friendName : friends) file << friendName << "\n";
            file << friendRequests.size() << "\n";
            for (const auto& req : friendRequests) file << req << "\n";
        }

        void loadFromFile(std::ifstream& file) {
            size_t count;
            file >> count;
            for (size_t i = 0; i < count; ++i) {
                String friendName;
                file >> friendName;
                friends.push_back(friendName);
            }
            file >> count;
            for (size_t i = 0; i < count; ++i) {
                String req;
                file >> req;
                friendRequests.push_back(req);
            }
        }
    };

    // Group class to hold group chats
    class Group {
    private:
        String groupName;
        Vector<String> members;
        Vector<Message> messages;
        DES des;  // DES instance for group messages

    public:
        Group(const String& name) : groupName(name), des("12345678") {}  // Default DES key for group

        void addMember(const Person& person) {
            members.push_back(person.getUsername());
            std::cout << person.getUsername() << " added to group " << groupName << "\n";
        }

        void sendMessage(const Person& sender, const String& content) {
            if (std::find(members.begin(), members.end(), sender.getUsername()) != members.end()) {
                String encryptedMessage = des.encrypt(content);
                messages.push_back(Message(sender.getUsername(), encryptedMessage));
                std::cout << "Message sent to group " << groupName << " (encrypted).\n";
            } else {
                std::cout << sender.getUsername() << " is not a member of this group.\n";
            }
        }

        void viewMessages() {
            for (const auto& msg : messages) {
                String decryptedMessage = des.decrypt(msg.content);
                std::cout << "[" << msg.timestamp << "] " << msg.sender << ": " << decryptedMessage << "\n";
            }
        }
    };

    // Global user map for managing users
    Map userPasswords;
    Vector<Person> users;

    void createAccount(const String& username, const String& password) {
        if (userPasswords.find(username) == userPasswords.end()) {
            users.push_back(Person(username, password));
            userPasswords[username] = hashPassword(password);
            std::cout << "Account created for " << username << "\n";
        } else {
            std::cout << "Username " << username << " already exists.\n";
        }
    }

    Person* login(const String& username, const String& password) {
        auto it = userPasswords.find(username);
        if (it != userPasswords.end() && it->second == hashPassword(password)) {
            for (auto& user : users) {
                if (user.getUsername() == username) {
                    std::cout << username << " logged in successfully!\n";
                    return &user;
                }
            }
        }
        std::cout << "Invalid username or password.\n";
        return nullptr;
    }

    void saveUsersToFile() {
        std::ofstream file("users.txt");
        file << users.size() << "\n";
        for (const auto& user : users) {
            user.saveToFile(file);
        }
    }

    void loadUsersFromFile() {
        std::ifstream file("users.txt");
        if (!file.is_open()) return;

        size_t userCount;
        file >> userCount;
        for (size_t i = 0; i < userCount; ++i) {
            String username, password;
            file >> username >> password;
            Person user(username, password);
            user.loadFromFile(file);
            users.push_back(user);
            userPasswords[username] = password;
        }
    }
}

int main() {
    chatapp::loadUsersFromFile();

    chatapp::createAccount("alice", "password123");
    chatapp::createAccount("bob", "password456");

    chatapp::Person* alice = chatapp::login("alice", "password123");
    chatapp::Person* bob = chatapp::login("bob", "password456");

    if (alice && bob) {
        alice->sendFriendRequest(*bob);
        bob->acceptFriendRequest("alice");
        alice->sendMessage(*bob, "Hello Bob!");

        bob->viewInbox();

        chatapp::Group myGroup("Study Group");
        myGroup.addMember(*alice);
        myGroup.addMember(*bob);

        alice->sendMessage(*bob, "This is a test message.");
        myGroup.sendMessage(*alice, "Hello Group!");

        myGroup.viewMessages();
    }

    chatapp::saveUsersToFile();

    return 0;
}
