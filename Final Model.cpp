#include <bits/stdc++.h>
using namespace std;

// DES Encryption/Decryption (simplified for example purposes)   hell no
class DES
{
    string key;

    void setKey(const string &keyStr)
    {
        key = keyStr.substr(0, 8); // Use the first 8 characters as the key
    }

public:
    DES(const string &keyStr)
    {
        setKey(keyStr);
    }

    string encrypt(const string &plaintext)
    {
        string ciphertext = plaintext;
        for (size_t i = 0; i < ciphertext.size(); ++i)
        {
            ciphertext[i] ^= key[i % key.size()]; // Simple XOR encryption
        }
        return ciphertext;
    }

    string decrypt(const string &ciphertext)
    {
        return encrypt(ciphertext); // XOR decryption is the same as encryption
    }
};

// AES Encryption Class
// Implements simplified AES functionality with a key size of 16 characters.
class AES
{
    string key;

public:
    // Constructor to initialize the key (first 16 characters used).
    AES(const string &keyStr) : key(keyStr.substr(0, 16)) {}

    // Encrypts the plaintext using XOR.
    string encrypt(const string &plaintext)
    {
        string ciphertext = plaintext;
        for (size_t i = 0; i < ciphertext.size(); ++i)
        {
            ciphertext[i] ^= key[i % key.size()]; // XOR each character with the key.
        }
        return ciphertext;
    }

    // Decrypts the ciphertext (same as encryption due to XOR properties).
    string decrypt(const string &ciphertext)
    {
        return encrypt(ciphertext); // XOR decrypts by reapplying the same operation.
    }
};

// ECC Encryption/Decryption Class
// Implements a simplified version of Elliptic Curve Cryptography (ECC) for example purposes.
// This class uses basic integer arithmetic for "encryption" and "decryption."

class ECC
{
    int privateKey; // Represents the private key, randomly generated.
    int publicKey;  // Represents the public key, derived from the private key.

public:
    // Constructor
    // Initializes the private key with a random value and computes the public key as twice the private key.
    ECC()
    {
        privateKey = rand() % 100;  // Random private key in the range [0, 99].
        publicKey = privateKey * 2; // Public key is a simple function of the private key.
    }

    // Encrypt Function
    // Encrypts a plaintext string by shifting each character using the modulus of the public key.
    string encrypt(const string &plaintext)
    {
        string ciphertext = plaintext;
        for (char &ch : ciphertext)
        {
            ch += publicKey % 256; // Shift character by `publicKey % 256`.
        }
        return ciphertext;
    }

    // Decrypt Function
    // Decrypts a ciphertext string by reversing the shift applied during encryption.
    string decrypt(const string &ciphertext)
    {
        string plaintext = ciphertext;
        for (char &ch : plaintext)
        {
            ch -= publicKey % 256; // Reverse the shift using `publicKey % 256`.
        }
        return plaintext;
    }
};

namespace chatapp
{
    // alias set karela che.
    using String = string;
    template <typename T>
    using Vector = vector<T>;
    using Map = unordered_map<String, String>;

    class Message
    {
    public:
        String sender;
        String content;
        String algorithm;
        String timestamp;
        bool isGroupMessage;
        String targetGroup; // Empty if not a group message

        Message(const String &sender, const String &content, const String &algorithm,
                bool isGroup = false, const String &group = "")
            : sender(sender), content(content), algorithm(algorithm),
              timestamp(getTimestamp()), isGroupMessage(isGroup), targetGroup(group) {}

    private:
        static String getTimestamp()
        {
            time_t now = time(0);
            char dt[20];
            strftime(dt, sizeof(dt), "%Y-%m-%d %H:%M:%S", localtime(&now));
            return String(dt);
        }
    };

    class Group
    {
    public:
        String name;
        String admin;
        Vector<String> members;
        Vector<String> pendingRequests;
        bool isActive; // Flag to mark if group is deleted

        Group(const String &groupName, const String &adminUsername)
            : name(groupName), admin(adminUsername), isActive(true)
        {
            members.push_back(adminUsername);
        }

        bool isMember(const String &username) const
        {
            return find(members.begin(), members.end(), username) != members.end();
        }

        bool hasPendingRequest(const String &username) const
        {
            return find(pendingRequests.begin(), pendingRequests.end(), username) != pendingRequests.end();
        }

        void addMember(const String &username)
        {
            if (!isMember(username))
            {
                members.push_back(username);
                auto it = find(pendingRequests.begin(), pendingRequests.end(), username);
                if (it != pendingRequests.end())
                {
                    pendingRequests.erase(it);
                }
            }
        }

        bool removeMember(const String &username)
        {
            if (username == admin)
                return false; // Can't remove admin
            auto it = find(members.begin(), members.end(), username);
            if (it != members.end())
            {
                members.erase(it);
                return true;
            }
            return false;
        }

        void addRequest(const String &username)
        {
            if (!isMember(username) && !hasPendingRequest(username))
            {
                pendingRequests.push_back(username);
            }
        }
    };

    class Person
    {
    public:
        String username;
        String password;
        Vector<Message> inbox;
        Vector<String> groupMemberships; // Groups the user is part of

        Person(const String &user, const String &pass) : username(user), password(pass) {}

        String getUsername() const { return username; }
        bool checkPassword(const String &pass) const { return password == pass; }

        void sendMessage(Person &recipient, const String &content, const String &algorithm)
        {
            recipient.inbox.push_back(Message(username, content, algorithm));
            cout << "Message sent to " << recipient.getUsername() << endl;
        }

        void sendGroupMessage(Vector<Person> &users, const String &groupName,
                              const String &content, const String &algorithm)
        {
            for (auto &user : users)
            {
                if (user.getUsername() != username)
                { // Don't send to self
                    user.inbox.push_back(Message(username, content, algorithm, true, groupName));
                }
            }
            cout << "Message sent to group " << groupName << endl;
        }

        void viewInbox(DES &des, AES &aes, ECC &ecc)
        {
            for (auto &msg : inbox)
            {
                String decryptedMessage;

                if (msg.algorithm == "DES")
                    decryptedMessage = des.decrypt(msg.content);
                else if (msg.algorithm == "AES")
                    decryptedMessage = aes.decrypt(msg.content);
                else if (msg.algorithm == "ECC")
                    decryptedMessage = ecc.decrypt(msg.content);

                if (msg.isGroupMessage)
                {
                    cout << "[Group: " << msg.targetGroup << "] ";
                }
                cout << "From: " << msg.sender << " (" << msg.algorithm << "): "
                     << decryptedMessage << " [" << msg.timestamp << "]\n";
            }
            inbox.clear();
        }
    };

    Map userPasswords;
    Vector<Person> users;
    Vector<Group> groups;

    void createAccount(const String &username, const String &password)
    {
        users.push_back(Person(username, password));
        userPasswords[username] = password;
    }

    Person *login(const String &username, const String &password)
    {
        for (auto &user : users)
        {
            if (user.getUsername() == username && user.checkPassword(password))
            {
                return &user;
            }
        }
        cout << "Invalid username or password.\n";
        return nullptr;
    }

    Group *findGroup(const String &groupName)
    {
        for (auto &group : groups)
        {
            if (group.name == groupName)
            {
                return &group;
            }
        }
        return nullptr;
    }

    void createGroup(const String &groupName, const String &admin)
    {
        if (findGroup(groupName) == nullptr)
        {
            groups.push_back(Group(groupName, admin));
            cout << "Group '" << groupName << "' created successfully.\n";
        }
        else
        {
            cout << "Group with this name already exists.\n";
        }
    }

    void saveUsersToFile()
    {
        ofstream file("users.dat", ios::binary);
        if (!file.is_open())
            return;

        size_t userCount = users.size();
        // this will treat the memory as the address and that is the counter type = pointer then this is prefered.
        file.write(reinterpret_cast<char *>(&userCount), sizeof(userCount));

        for (const auto &user : users)
        {
            size_t usernameLength = user.getUsername().size();
            size_t passwordLength = user.password.size();

            // Write the length of the username to the file
            file.write(reinterpret_cast<char *>(&usernameLength), sizeof(usernameLength));

            // Write the username data (as raw characters) to the file
            file.write(user.getUsername().c_str(), usernameLength);

            // Write the length of the password to the file
            file.write(reinterpret_cast<char *>(&passwordLength), sizeof(passwordLength));

            // Write the password data (as raw characters) to the file
            file.write(user.password.c_str(), passwordLength);
        }
        file.close();
    }

    void loadUsersFromFile()
    {
        ifstream file("users.dat", ios::binary);
        if (!file.is_open())
            return;

        size_t userCount;
        file.read(reinterpret_cast<char *>(&userCount), sizeof(userCount));

        for (size_t i = 0; i < userCount; ++i)
        {
            size_t usernameLength;
            file.read(reinterpret_cast<char *>(&usernameLength), sizeof(usernameLength));
            String username(usernameLength, '\0');
            file.read(&username[0], usernameLength);

            size_t passwordLength;
            file.read(reinterpret_cast<char *>(&passwordLength), sizeof(passwordLength));
            String password(passwordLength, '\0');
            file.read(&password[0], passwordLength);

            users.push_back(Person(username, password));
            userPasswords[username] = password;
        }
        file.close();
    }

    void saveGroupsToFile()
    {
        ofstream file("groups.dat", ios::binary);
        if (!file.is_open())
            return;

        size_t groupCount = groups.size();
        file.write(reinterpret_cast<char *>(&groupCount), sizeof(groupCount));

        for (const auto &group : groups)
        {
            if (!group.isActive)
                continue; // Skip deleted groups

            size_t nameLength = group.name.size();
            size_t adminLength = group.admin.size();
            size_t memberCount = group.members.size();
            size_t requestCount = group.pendingRequests.size();

            // Write group name and admin
            file.write(reinterpret_cast<char *>(&nameLength), sizeof(nameLength));
            file.write(group.name.c_str(), nameLength);
            file.write(reinterpret_cast<char *>(&adminLength), sizeof(adminLength));
            file.write(group.admin.c_str(), adminLength);

            // Write members
            file.write(reinterpret_cast<char *>(&memberCount), sizeof(memberCount));
            for (const auto &member : group.members)
            {
                size_t memberLength = member.size();
                file.write(reinterpret_cast<char *>(&memberLength), sizeof(memberLength));
                file.write(member.c_str(), memberLength);
            }

            // Write pending requests
            file.write(reinterpret_cast<char *>(&requestCount), sizeof(requestCount));
            for (const auto &request : group.pendingRequests)
            {
                size_t requestLength = request.size();
                file.write(reinterpret_cast<char *>(&requestLength), sizeof(requestLength));
                file.write(request.c_str(), requestLength);
            }
        }
        file.close();
    }

    void loadGroupsFromFile()
    {
        ifstream file("groups.dat", ios::binary);
        if (!file.is_open())
            return;

        size_t groupCount;
        file.read(reinterpret_cast<char *>(&groupCount), sizeof(groupCount));

        for (size_t i = 0; i < groupCount; ++i)
        {
            size_t nameLength, adminLength;

            // Read group name
            file.read(reinterpret_cast<char *>(&nameLength), sizeof(nameLength));
            String groupName(nameLength, '\0');
            file.read(&groupName[0], nameLength);

            // Read admin
            file.read(reinterpret_cast<char *>(&adminLength), sizeof(adminLength));
            String admin(adminLength, '\0');
            file.read(&admin[0], adminLength);

            Group newGroup(groupName, admin);

            // Read members
            size_t memberCount;
            file.read(reinterpret_cast<char *>(&memberCount), sizeof(memberCount));
            for (size_t j = 0; j < memberCount; ++j)
            {
                size_t memberLength;
                file.read(reinterpret_cast<char *>(&memberLength), sizeof(memberLength));
                String member(memberLength, '\0');
                file.read(&member[0], memberLength);
                if (member != admin)
                    newGroup.addMember(member);
            }

            // Read pending requests
            size_t requestCount;
            file.read(reinterpret_cast<char *>(&requestCount), sizeof(requestCount));
            for (size_t j = 0; j < requestCount; ++j)
            {
                size_t requestLength;
                file.read(reinterpret_cast<char *>(&requestLength), sizeof(requestLength));
                String request(requestLength, '\0');
                file.read(&request[0], requestLength);
                newGroup.addRequest(request);
            }

            groups.push_back(newGroup);
        }
        file.close();
    }

    void manageGroup(Person *loggedInUser, Group *group)
    {
        while (true)
        {
            cout << "\nGroup Management - " << group->name << endl;
            cout << "1. View Members\n";
            cout << "2. Remove Member\n";
            cout << "3. View Pending Requests\n";
            cout << "4. Delete Group\n";
            cout << "5. Back\n";
            cout << "Select an option: ";

            int choice;
            cin >> choice;

            switch (choice)
            {
            case 1:
            {
                cout << "\nGroup Members:\n";
                for (const auto &member : group->members)
                {
                    cout << "- " << member << (member == group->admin ? " (Admin)" : "") << endl;
                }
                break;
            }
            case 2:
            {
                cout << "\nSelect member to remove:\n";
                for (const auto &member : group->members)
                {
                    if (member != group->admin)
                    { // Don't show admin in removal list
                        cout << "- " << member << endl;
                    }
                }
                String memberToRemove;
                cout << "Enter username (or 'cancel'): ";
                cin >> memberToRemove;

                if (memberToRemove != "cancel")
                {
                    if (group->removeMember(memberToRemove))
                    {
                        cout << "Member removed successfully.\n";
                        saveGroupsToFile();
                    }
                    else
                    {
                        cout << "Failed to remove member. Check if username is correct and not admin.\n";
                    }
                }
                break;
            }
            case 3:
            {
                if (group->pendingRequests.empty())
                {
                    cout << "No pending requests.\n";
                }
                else
                {
                    cout << "\nPending Requests:\n";
                    for (const auto &request : group->pendingRequests)
                    {
                        cout << "- " << request << endl;
                        cout << "Accept? (y/n): ";
                        char response;
                        cin >> response;
                        if (response == 'y' || response == 'Y')
                        {
                            group->addMember(request);
                            cout << "User added to group.\n";
                            saveGroupsToFile();
                        }
                    }
                }
                break;
            }
            case 4:
            {
                cout << "Are you sure you want to delete this group? (y/n): ";
                char response;
                cin >> response;
                if (response == 'y' || response == 'Y')
                {
                    group->isActive = false;
                    saveGroupsToFile();
                    cout << "Group deleted successfully.\n";
                    return;
                }
                break;
            }
            case 5:
                return;
            default:
                cout << "Invalid option.\n";
                break;
            }
        }
    }

    void groupOperations(Person *loggedInUser)
    {
        cout << "\n1. Create Group\n";
        cout << "2. Join Group\n";
        cout << "3. View My Groups\n";
        cout << "4. Manage Groups\n";
        cout << "5. Back\n";
        cout << "Select an option: ";

        int choice;
        cin >> choice;

        switch (choice)
        {
        case 1:
        {
            String groupName;
            cout << "Enter group name: ";
            cin >> groupName;
            createGroup(groupName, loggedInUser->getUsername());
            saveGroupsToFile();
            break;
        }
        case 2:
        {
            cout << "Available groups:\n";
            for (const auto &group : groups)
            {
                if (group.isActive)
                {
                    cout << "- " << group.name << " (Admin: " << group.admin << ")\n";
                }
            }

            String groupName;
            cout << "Enter group name to join: ";
            cin >> groupName;

            auto group = findGroup(groupName);
            if (group && group->isActive)
            {
                group->addRequest(loggedInUser->getUsername());
                saveGroupsToFile();
                cout << "Join request sent to group admin.\n";
            }
            else
            {
                cout << "Group not found.\n";
            }
            break;
        }
        case 3:
        {
            cout << "Groups you're a member of:\n";
            for (const auto &group : groups)
            {
                if (group.isActive && group.isMember(loggedInUser->getUsername()))
                {
                    cout << "- " << group.name << (group.admin == loggedInUser->getUsername() ? " (Admin)" : "") << endl;
                }
                else
                {
                    cout << "You are currently in no group." << endl;
                }
            }
            break;
        }
        case 4:
        {
            cout << "Groups you are admin of:\n";
            Vector<Group *> adminGroups;
            for (auto &group : groups)
            {
                if (group.isActive && group.admin == loggedInUser->getUsername())
                {
                    cout << adminGroups.size() + 1 << ". " << group.name << endl;
                    adminGroups.push_back(&group);
                }
            }

            if (!adminGroups.empty())
            {
                cout << "Select group to manage (1-" << adminGroups.size() << "): ";
                int groupChoice;
                cin >> groupChoice;

                if (groupChoice > 0 && groupChoice <= static_cast<int>(adminGroups.size()))
                {
                    manageGroup(loggedInUser, adminGroups[groupChoice - 1]);
                }
                else
                {
                    cout << "Invalid selection.\n";
                }
            }
            else
            {
                cout << "You don't admin any groups.\n";
            }
            break;
        }
        case 5:
            return;
        default:
            cout << "Invalid option.\n";
            break;
        }
    }

    void messageOperations(Person *loggedInUser, DES &des, AES &aes, ECC &ecc)
    {
        cout << "\n1. Send Direct Message\n";
        cout << "2. Send Group Message\n";
        cout << "3. Back\n";
        cout << "Select an option: ";

        int choice;
        cin >> choice;

        switch (choice)
        {
        case 1:
        {
            String recipientUsername, messageContent;
            cout << "Enter recipient username: ";
            cin >> recipientUsername;

            cout << "Enter your message: ";
            cin.ignore();
            getline(cin, messageContent);

            cout << "Select encryption algorithm (1: DES, 2: AES, 3: ECC): ";
            int algoChoice;
            cin >> algoChoice;

            String encryptedMessage;
            String algorithm;

            if (algoChoice == 1)
            {
                encryptedMessage = des.encrypt(messageContent);
                algorithm = "DES";
            }
            else if (algoChoice == 2)
            {
                encryptedMessage = aes.encrypt(messageContent);
                algorithm = "AES";
            }
            else if (algoChoice == 3)
            {
                encryptedMessage = ecc.encrypt(messageContent);
                algorithm = "ECC";
            }
            else
            {
                cout << "Invalid encryption algorithm.\n";
                return;
            }

            loggedInUser->sendMessage(*login(recipientUsername, userPasswords[recipientUsername]),
                                      encryptedMessage, algorithm);
            break;
        }
        case 2:
        {
            cout << "Your groups:\n";
            for (const auto &group : groups)
            {
                if (group.isMember(loggedInUser->getUsername()))
                {
                    cout << "- " << group.name << endl;
                }
            }

            String groupName, messageContent;
            cout << "Enter group name: ";
            cin >> groupName;

            auto group = findGroup(groupName);
            if (!group || !group->isMember(loggedInUser->getUsername()))
            {
                cout << "Group not found or you're not a member.\n";
                return;
            }

            cout << "Enter your message: ";
            cin.ignore();
            getline(cin, messageContent);

            cout << "Select encryption algorithm (1: DES, 2: AES, 3: ECC): ";
            int algoChoice;
            cin >> algoChoice;

            String encryptedMessage;
            String algorithm;

            if (algoChoice == 1)
            {
                encryptedMessage = des.encrypt(messageContent);
                algorithm = "DES";
            }
            else if (algoChoice == 2)
            {
                encryptedMessage = aes.encrypt(messageContent);
                algorithm = "AES";
            }
            else if (algoChoice == 3)
            {
                encryptedMessage = ecc.encrypt(messageContent);
                algorithm = "ECC";
            }
            else
            {
                cout << "Invalid encryption algorithm.\n";
                return;
            }

            loggedInUser->sendGroupMessage(users, groupName, encryptedMessage, algorithm);
            break;
        }
        case 3:
            return;
        default:
            cout << "Invalid option.\n";
            break;
        }
    }
}

int main()
{
    chatapp::loadUsersFromFile();

    DES des("12345678");
    AES aes("A1B2C3D4E5F6G7H8");
    ECC ecc;

    while (true)
    {
    Gate:
        if (chatapp::users.empty())
        {
            cout << "No Users Yet" << endl;
        }
        else
        {
            cout << "Available usernames:\n";
            for (const auto &user : chatapp::users)
            {
                cout << "- " << user.getUsername() << endl;
            }
        }

        cout << "1. Sign Up" << endl;
        cout << "2. Log In" << endl;
        cout << "3. Exit" << endl;
        cout << "Select an option : ";
        int choice;
        cin >> choice;

        if (choice == 1)
        {
            chatapp::String username, password;
            cout << "Enter a username: ";
            cin >> username;
            cout << "Enter a password: ";
            cin >> password;
            chatapp::createAccount(username, password);
            chatapp::saveUsersToFile();
            continue;
        }
        else if (choice == 3)
        {
            cout << "Exiting..." << endl;
            return 0;
        }
        else if (choice != 2)
        {
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
            continue;

        while (true)
        {
            cout << "\n1. View Inbox\n";
            cout << "2. Messages\n";
            cout << "3. Group Operations\n";
            cout << "4. Logout\n";
            cout << "5. Exit\n";
            cout << "Select an option: ";
            int choice;
            cin >> choice;

            switch (choice)
            {
            case 1:
                loggedInUser->viewInbox(des, aes, ecc);
                break;
            case 2:
                chatapp::messageOperations(loggedInUser, des, aes, ecc);
                break;
            case 3:
                chatapp::groupOperations(loggedInUser);
                break;
            case 4:
                loggedInUser = nullptr;
                cout << "Logged out.\n";
                goto Gate;
            case 5:
                cout << "Exiting..." << endl;
                return 0;
            default:
                cout << "Invalid option. Please try again.\n";
                break;
            }
        }
    }
}