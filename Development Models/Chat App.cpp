#include<bits/stdc++.h>
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

DES des("12345678");

namespace chatapp
{
    using String = string;
    template <typename T>
    using Vector = vector<T>;
    using Map = unordered_map<String, String>;

    // Utility to generate a timestamp
    String getTimestamp()
    {
        time_t now = time(0);
        char dt[20];
        strftime(dt, sizeof(dt), "%Y-%m-%d %H:%M:%S", localtime(&now));
        return String(dt);
    }

    // Message class to hold individual messages
    class Message
    {
    public:
        String sender;
        String content;
        String timestamp;

        Message(const String &sender, const String &content)
            : sender(sender), content(content), timestamp(getTimestamp()) {}
    };

    // Person class to represent individual users
    class Person
    {
    private:
        String username;
        String password;
        Vector<String> friends;
        Vector<Message> inbox;

    public:
        Person(const String &user, const String &pass)
            : username(user), password(pass) {}

        String getUsername() const { return username; }

        String getPass() const { return password; }

        bool checkPassword(const String &pass) const
        {
            return password == pass; // Password check simplified
        }

        void sendMessage(Person &recipient, const String &content)
        {
            if (this->isFriend(recipient.username))
            {
                recipient.inbox.push_back(Message(username, content));
                cout << "Message sent to " << recipient.getUsername() << "\n";
            }
            else
            {
                cout << recipient.getUsername() << " not your freind\n";
            }
        }

        void addFriend(const String &friendName)
        {
            if (!isFriend(friendName))
            {
                friends.push_back(friendName);
                cout << friendName << " added as a friend.\n";
            }
            else
            {
                cout << friendName << " is already your friend.\n";
            }
        }

        bool isFriend(const String &friendName) const
        {
            return find(friends.begin(), friends.end(), friendName) != friends.end();
        }

        void viewInbox()
        {
            if (inbox.empty())
            {
                cout << "Inbox is empty.\n";
            }
            else
            {
                for (const auto &msg : inbox)
                {
                    cout << "Message from " << msg.sender << ": " << des.decrypt(msg.content) << " [" << msg.timestamp << "]\n";
                }
                inbox.clear();
            }
        }

        void viewFriends() const
        {
            cout << "Friends: ";
            if (friends.empty())
            {
                cout << "None\n";
            }
            else
            {
                for (const auto &friendName : friends)
                {
                    cout << friendName << " ";
                }
                cout << "\n";
            }
        }
    };

    // Global user map for managing users
    Map userPasswords;
    Vector<Person> users;

    void createAccount(const String &username, const String &password)
    {
        if (userPasswords.find(username) == userPasswords.end())
        {
            users.push_back(Person(username, password));
            userPasswords[username] = password; // Store plain password for now
            cout << "Account created for " << username << "\n";
        }
        else
        {
            cout << "Username " << username << " already exists.\n";
        }
    }

    Person *login(const String &username, const String &password)
    {
        auto it = userPasswords.find(username);
        if (it != userPasswords.end() && it->second == password)
        {
            for (auto &user : users)
            {
                if (user.getUsername() == username)
                {
                    return &user;
                }
            }
        }
        cout << "Invalid username or password.\n";
        return nullptr;
    }

    void saveUsersToFile()
    {
        ofstream file("users.txt");
        if (!file.is_open())
            return;

        file << users.size() << "\n";
        for (const auto &user : users)
        {
            file << user.getUsername() << "\n"
                 << user.getPass() << "\n";
        }
    }

    void loadUsersFromFile()
    {
        ifstream file("users.txt");
        if (!file.is_open())
            return;

        size_t userCount;
        file >> userCount;
        file.ignore(); // Ignore newline character after userCount

        for (size_t i = 0; i < userCount; ++i)
        {
            String username, password;
            getline(file, username);
            getline(file, password);

            users.push_back(Person(username, password));
            userPasswords[username] = password;
        }
    }
}

int main()
{
    chatapp::loadUsersFromFile(); // Load existing users from file

    while (true)
    { // Outer loop to allow logging in from multiple accounts
        if(chatapp::users.empty())
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

        if(choice == 1)
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
            cout << "Invalid option. Please try again.\n";
            continue;
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

        while (true)
        { // Inner loop for logged-in user actions
            cout << "\n1. View Friends\n";
            cout << "2. Send Friend Request\n";
            cout << "3. Send Message\n";
            cout << "4. View Inbox\n";
            cout << "5. Logout\n";
            cout << "6. Exit\n";
            cout << "Select an option: ";
            int choice;
            cin >> choice;

            switch (choice)
            {
            case 1:
                loggedInUser->viewFriends();
                break;
            case 2:
            {
                chatapp::String friendUsername;
                cout << "Enter username to add as friend: ";
                cin >> friendUsername;
                if (chatapp::userPasswords.find(friendUsername) != chatapp::userPasswords.end())
                {
                    loggedInUser->addFriend(friendUsername);
                }
                else
                {
                    cout << "User does not exist.\n";
                }
                break;
            }
            case 3:
            {
                chatapp::String recipientUsername;
                cout << "Enter recipient username: ";
                cin >> recipientUsername;
                if (chatapp::userPasswords.find(recipientUsername) != chatapp::userPasswords.end())
                {
                    chatapp::String messageContent;
                    cout << "Enter your message: ";
                    cin.ignore();
                    getline(cin, messageContent);
                    loggedInUser->sendMessage(*chatapp::login(recipientUsername, chatapp::userPasswords[recipientUsername]), des.encrypt(messageContent));
                }
                else
                {
                    cout << "User does not exist.\n";
                }
                break;
            }
            case 4:
                loggedInUser->viewInbox();
                break;
            case 5: // Logout action
                cout << "Logging out...\n";
                goto outer_loop; // Exit inner loop to outer loop
            case 6:              // Exit the program
                cout << "Exiting...\n";
                return 0;
            default:
                cout << "Invalid option. Please try again.\n";
            }
        }
    outer_loop:
        continue; // Label for goto to resume outer loop
    }
    return 0;
}