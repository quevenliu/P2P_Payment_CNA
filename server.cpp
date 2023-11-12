#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <thread>
#include <vector>
#include <map>
/*
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
*/

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
    int socket;
public:
    User (string username, string publicKey, string ip, int port, int balance, int socket) {
        if (userList.find(username) != userList.end()) {
            throw "210 FAIL";
        }
        this->username = username;
        this->publicKey = publicKey;
        this->ip = ip;
        this->port = port;
        this->balance = balance;
        this->socket = socket;
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
    string userLogin(string username, string ip, int port, int socket) {
        if (userList.find(username) == userList.end()) {
            return "220 AUTH_FAIL";
        }
        if (this->onlineStatus) {
            return "100 OK";
        }
        this->onlineStatus = true;
        this->ip = ip;
        this->port = port;
        this->socket = socket;
        return "100 OK";
    }
    string userLogout(string username) {
        if (userList.find(username) == userList.end()) {
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
};