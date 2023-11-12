#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <thread>
#include <vector>
#include <map>

#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>


using namespace std;

string serverPK = "";

class User {
private:
    static map<string, User*> userList;
    string username;
    string publicKey;
    string ip;
    int port;
    bool onlineStatus;
    int balance;
    static const int DEFAULT_BALANCE = 10000;
public:
    User (string username, string publicKey, string ip, int port) {
        if (userList.find(username) != userList.end()) {
            throw "210 FAIL";
        }
        this->username = username;
        this->publicKey = publicKey;
        this->ip = ip;
        this->port = port;
        this->balance = User::DEFAULT_BALANCE;
        this->onlineStatus = true;
        userList.insert(pair<string, User*>(username, this));
    }

    string listUsers()
    {
        string result = "";
        result += (to_string(balance) + "\n" + serverPK + "\n" + to_string(userList.size()) + "\n"); 
        for (auto it = userList.begin(); it != userList.end(); it++)
        {
            result += (it->first + "#" + it->second->ip + "#" + to_string(it->second->port) + "\n");
        }
        return result;
    }
    string userLogin(string ip, int port) {
        this->onlineStatus = true;
        this->ip = ip;
        this->port = port;
        return "100 OK";
    }
    string userLogout() {
        if (userList.find(this->username) == userList.end()) {
            return "220 AUTH_FAIL";
        }
        this->onlineStatus = false;
        return "Bye";
    }
    string transfer(string receiver, int amount, string username) {
        if (receiver != username)
            return "220 AUTH_FAIL";
        if (userList.find(receiver) == userList.end()) {
            return "220 AUTH_FAIL";
        }
        if (userList.find(username) == userList.end()) {
            return "404 Not Found";
        }
        if (userList[username]->balance < amount) {
            return "420 TRANSFER_FAIL";
        }
        userList[username]->balance -= amount;
        userList[receiver]->balance += amount;
        return "Transfer OK";
    }
    static User* findUser(string username) {
        if (userList.find(username) == userList.end()) {
            return NULL;
        }
        return userList[username];
    }
};

struct connection {
    int socket;
    string ip;
    int port;
};

void connThread(connection* conn) {
    int socket = conn->socket;
    string ip = conn->ip;
    int port = conn->port;

    char clientBuffer[1024] = {0};
    char serverBuffer[1024] = {0};

    while (true)
    {
        if (recv(socket, clientBuffer, sizeof(clientBuffer), 0) > 0) {
            string clientMessage = string(clientBuffer);
            string serverMessage = ""; 
            User* currUser = NULL;

            int firstSign = clientMessage.find("#");
            int secondSign = (firstSign != string::npos)? clientMessage.find("#", firstSign + 1) : string::npos;


            if (clientMessage.find("REGISTER") != string::npos) {
                try {
                    string username = clientMessage.substr(clientMessage.find("#"));
                    string publicKey = "";
                    currUser = new User(username, publicKey, ip, port);
                    serverMessage = "100 OK";
                } catch (const char* e) {
                    serverMessage = e;
                } catch (exception& e) {
                    serverMessage = "500 Internal Server Error";
                }
            } else if (currUser == NULL) {
                serverMessage = "220 AUTH_FAIL";
            } 
            else if (clientMessage.find("List") != string::npos) {
                serverMessage = currUser->listUsers();
            } else if (clientMessage.find("Exit") != string::npos) {
                serverMessage = currUser->userLogout();
            } else if (firstSign != string::npos) {
                if (secondSign != string::npos) {
                    try {
                        string username = clientMessage.substr(0, firstSign);
                        int amount = stoi(clientMessage.substr(firstSign + 1, secondSign - firstSign - 1));
                        string receiver = clientMessage.substr(secondSign + 1);
                        serverMessage = currUser->transfer(receiver, amount, username);
                    } catch (exception& e) {
                        serverMessage = "500 Internal Server Error";
                    }
                } else {
                    try {
                        string username = clientMessage.substr(0, firstSign);
                        currUser = User::findUser(username);
                        if (currUser == NULL) {
                            serverMessage = "220 AUTH_FAIL";
                        }
                        else
                            serverMessage = currUser->userLogin(ip, port);
                        
                    } catch (exception& e) {
                        serverMessage = "500 Internal Server Error";
                    }
                }
            } else {
                serverMessage = "400 Wrong Command";
            }

            strcpy(serverBuffer, serverMessage.c_str());
            send(socket, serverBuffer, strlen(serverBuffer), 0);
            if (serverMessage == "Bye") {
                break;
            }
            memset(clientBuffer, 0, sizeof(clientBuffer));
            memset(serverBuffer, 0, sizeof(serverBuffer));
        }
    }
}   

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: ./server <port>" << endl;
        return 1;
    }
    int port = atoi(argv[1]);
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        cout << "Socket creation error" << endl;
        return 0;
    }
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cout << "Binding error" << endl;
        return 0;
    }
    if (listen(serverSocket, 5) < 0) {
        cout << "Listening error" << endl;
        return 0;
    }
    while (true) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket < 0) {
            cout << "Accepting error" << endl;
            return 0;
        }
        connection* conn = new connection();
        conn->socket = clientSocket;
        conn->ip = inet_ntoa(clientAddr.sin_addr);
        conn->port = ntohs(clientAddr.sin_port);
        cout << "New connection from " << conn->ip << ":" << conn->port << endl;
        thread t(connThread, conn);
        t.detach();
    }
    return 0;
}