#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <thread>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/conf.h>

using namespace std;
#define CA_PATH "/home/liu/ssl"


// g++ client.cpp -o client

string sendToServer(string message, int clientSocket, bool getMessage = true)
{

    if (send(clientSocket, message.c_str(), strlen(message.c_str()), 0) == -1)
    {
        std::cerr << "Error sending data to the server" << std::endl;
        close(clientSocket);
        return "";
    }

    if (!getMessage)
    {
        return "Send success";
    }
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRead == -1)
    {
        std::cerr << "Error receiving data from the server" << std::endl;
        close(clientSocket);
        return "";
    }

    if (bytesRead == 0)
    {
        std::cout << "No message received." << std::endl;
        close(clientSocket);
        return "";
    }

    buffer[bytesRead] = '\0';

    std::string receivedData(buffer);

    memset(buffer, 0, sizeof(buffer));

    return receivedData;
}

void listener(int listenerSocket, int clientSocket)
{

    while (true)
    {
        struct sockaddr_in clientConnection;
        int clientRecv = 0;
        unsigned int len = sizeof(clientRecv);
        clientRecv = accept(listenerSocket, (struct sockaddr *) &clientConnection, &len);

        char buffer[1024] = {0};

        recv(clientRecv,buffer,sizeof(buffer),0);
        send(clientSocket,buffer,sizeof(buffer),0);

        memset(buffer, 0, sizeof(buffer));
    }

    close(listenerSocket);
}

vector<string> getReceiverIPAndPort(string receiverID, string listResult)
{

    /*
    Return value format:

    <accountBalance><CRLF>
    <serverPublicKey><CRLF>
    <number of accounts online><CRLF>
    <userAccount1>#<userAccount1_IPaddr>#<userAccount1_portNum><CRLF>
    <userAccount2>#<userAccount2_ IPaddr>#<userAccount2_portNum><CRLF>

    return format: vector([ip, port])
    */

    int pos = listResult.find(receiverID);
    if (pos == string::npos)
    {
        return vector<string>();
    }

    int pos1 = listResult.find("#", pos);
    int pos2 = listResult.find("#", pos1 + 1);
    int pos3 = listResult.find("\n", pos2 + 1);

    string receiverIP = listResult.substr(pos1 + 1, pos2 - pos1 - 1);
    string receiverPort = listResult.substr(pos2 + 1, pos3 - pos2);

    vector<string> result;
    result.push_back(receiverIP);
    result.push_back(receiverPort);

    return result;
}

string transfer(string receiver, int amount, string username, int clientSocket)
{

    string listResult = sendToServer("List", clientSocket);

    while (listResult.find("Transfer OK") != string::npos)
    {
        listResult = sendToServer("List", clientSocket);
    }

    vector<string> receiverIPAndPort = getReceiverIPAndPort(receiver, listResult);

    if (receiverIPAndPort.size() == 0)
    {
        return "Receiver not found";
    }

    string ip = receiverIPAndPort[0];
    int port = atoi(receiverIPAndPort[1].c_str());

    cout << "Receiver IP: " << ip << endl;
    cout << "Receiver port: " << port << endl;

    int receiverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (receiverSocket == -1)
    {
        std::cerr << "Error creating socket" << std::endl;
        return "Error";
    }

    struct sockaddr_in receiverAddr;
    receiverAddr.sin_family = AF_INET;
    receiverAddr.sin_port = htons(port);
    receiverAddr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(receiverSocket, (struct sockaddr *)&receiverAddr, sizeof(receiverAddr)) == -1)
    {
        std::cerr << "Error connecting to the server" << std::endl;
        close(receiverSocket);
        return "Error";
    }

    string message = username + "#" + to_string(amount) + "#" + receiver;

    string response = sendToServer(message, receiverSocket, false);

    cout << "Transfer message sent to receiver" << endl;

    if (response == "Success")
    {
        return "Transfer success";
    }
    else
    {
        return response;
    }
}

int main(int argc, char **argv)
{

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX * ctx = SSL_CTX_new(TLSv1_2_client_method()); 
    SSL * ssl;

    if(! SSL_CTX_load_verify_locations(ctx, NULL, CA_PATH)) { 
        handleFailure("Error: Could not load CA file.\n"); 
    }


    string ip;
    int port;
    int localPort;

    if (argc == 4)
    {
        ip = argv[1];
        port = atoi(argv[2]);
        localPort = atoi(argv[3]);
    }
    else
    {
        std::cerr << "Usage: ./client <server_ip> <server_port> <client_port>" << std::endl;
        return 1;
    }

    // usage: ./client <server_ip> <server_port> <client_port>
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1)
    {
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        std::cerr << "Error connecting to the server" << std::endl;
        close(clientSocket);
        return 1;
    }

    string username = "";

    int listenerSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenerSocket == -1)
    {
        std::cerr << "Error creating listener socket" << std::endl;
        close(listenerSocket);
        return 1;
    }

    struct sockaddr_in listenerAddr;
    listenerAddr.sin_family = AF_INET;
    listenerAddr.sin_port = htons(localPort);
    listenerAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenerSocket, (struct sockaddr *)&listenerAddr, sizeof(listenerAddr)) == -1)
    {
        std::cerr << "Error binding listener socket" << std::endl;
        close(listenerSocket);
    }

    if (listen(listenerSocket, 5) == -1)
    {
        std::cerr << "Error listening on port" << std::endl;
        close(listenerSocket);
    }

    cout << "Listening on port " << localPort << endl;

    std::thread listenerThread(listener, listenerSocket, clientSocket);

    char choice;

    do
    {

        std::cout << "Select an option:" << std::endl;
        std::cout << "1. Register" << std::endl;
        std::cout << "2. Login" << std::endl;
        std::cout << "3. List accounts" << std::endl;
        std::cout << "4. Transaction" << std::endl;
        std::cout << "0. Exit" << std::endl;

        cin >> choice;
        string message;
        string receiver;

        switch (choice)
        {
        case '1':
            cout << "Enter username: ";
            cin >> username;
            message = "REGISTER#" + username;
            break;
        case '2':
            cout << "Enter username: ";
            cin >> username;
            message = username + "#" + to_string(localPort);
            break;
        case '3':
            message = "List";
            break;
        case '4':
            if (username == "")
            {
                cout << "Please login first." << endl;
                break;
            }
            int amount;
            cout << "Enter receiver: ";
            cin >> receiver;
            cout << "Enter amount: ";
            cin >> amount;

            if (receiver == username)
            {
                cout << "Cannot transfer to yourself" << endl;
                break;
            }

            cout << transfer(receiver, amount, username, clientSocket) << endl;

            break;
        case '0':
            std::cout << "Exiting..." << std::endl;
            message = "Exit";
            sendToServer(message, clientSocket);
            exit(0);
            break;
        default:
            std::cout << "Invalid option. Please try again." << std::endl;
            break;
        }
        if (choice != '4')
        {
            string response = sendToServer(message, clientSocket);
            while (response.find("Transfer OK") != string::npos)
            {
                response = sendToServer(message, clientSocket);
            }
            cout << response << endl;
        }

        std::cout << "Press Enter to continue..." << std::endl;

        std::cin.ignore();
        std::cin.get();

        system("clear");

    } while (choice != '0');

    close(clientSocket);
    listenerThread.join();

    return 0;
}