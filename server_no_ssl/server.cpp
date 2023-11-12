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
class User;
map<string, User*> userList;

class User {
private:
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
    string transfer(string from, int amount) {
        if (userList.find(from) == userList.end()) {
            return "220 AUTH_FAIL";
        }
        if (userList[from]->balance < amount) {
            return "420 TRANSFER_FAIL";
        }
        userList[from]->balance -= amount;
        this->balance += amount;
        return "Transfer OK";
    }

    string getUserName() {
        return this->username;
    }

    ~User() {
        userList.erase(this->username);
    }
};

User* findUser(string username) {
    if (userList.find(username) == userList.end()) {
        return NULL;
    }
    return userList[username];
}

struct connection {
    int socket;
    string ip;
    int port;
};

void connThread(connection* conn, bool verbose = false) {
    int socket = conn->socket;
    string ip = conn->ip;
    int port = conn->port;

    char clientBuffer[1024] = {0};
    char serverBuffer[1024] = {0};
    User* currUser = NULL;

    while (true)
    {
        if (recv(socket, clientBuffer, sizeof(clientBuffer), 0) > 0) {
            string clientMessage = string(clientBuffer);
            string serverMessage = ""; 

            int firstSign = clientMessage.find("#");
            int secondSign = (firstSign != string::npos)? clientMessage.find("#", firstSign + 1) : string::npos;


            if (clientMessage.find("REGISTER") != string::npos) {
                try {
                    string username = clientMessage.substr(firstSign + 1);
                    string publicKey = "";

                    if (verbose)
                        cout << username << " register" << endl;

                    currUser = new User(username, publicKey, ip, port);
                    serverMessage = "100 OK";
                } catch (const char* e) {
                    serverMessage = e;
                } catch (exception& e) {
                    serverMessage = "500 Internal Server Error";
                }
            } else if (currUser == NULL) {
                serverMessage = "220 AUTH_FAIL\nNot logged in";
            } 
            else if (clientMessage.find("List") != string::npos) {

                if (verbose)
                    cout << currUser->getUserName() << " list" << endl;

                serverMessage = currUser->listUsers();
            } else if (clientMessage.find("Exit") != string::npos) {

                if (verbose)
                    cout << currUser->getUserName() << " exit" << endl;

                serverMessage = currUser->userLogout();
            } else if (firstSign != string::npos) {
                if (secondSign != string::npos) {
                    try {
                        string username = clientMessage.substr(0, firstSign);
                        int amount = stoi(clientMessage.substr(firstSign + 1, secondSign - firstSign - 1));
                        string receiver = clientMessage.substr(secondSign + 1);
                        
                        if (verbose)
                            cout << username << " transfer " << amount << " to " << receiver << endl;
                        if (receiver != currUser->getUserName()) {
                            serverMessage = "220 AUTH_FAIL";
                        }
                        else
                            serverMessage = currUser->transfer(username, amount);
                        if (verbose)
                            cout << serverMessage << endl;

                    } catch (exception& e) {
                        serverMessage = "500 Internal Server Error";
                    }
                } else {
                    try {
                        string username = clientMessage.substr(0, firstSign);
                        int transferPort = stoi(clientMessage.substr(firstSign + 1));
                        if (verbose)
                            cout << username << " login" << endl;
                        currUser = findUser(username);
                        if (currUser == NULL) {
                            serverMessage = "220 AUTH_FAIL\nNot Registered";
                        }
                        else
                            serverMessage = currUser->userLogin(ip, transferPort);
                        
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
    close (conn->socket);
}   

int main(int argc, char* argv[]) {
    if (argc == 1 || (argc == 3 && strcmp(argv[2], "-verbose") != 0) || argc > 3) {
        cout << "Usage: ./server <port> [-verbose]" << endl;
        return 1;
    }
    int port = atoi(argv[1]);
    bool verbose = (argc == 3 && strcmp(argv[2], "-verbose") == 0);
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
        thread t(connThread, conn, verbose);
        t.detach();
    }
    close (serverSocket);
    return 0;
}