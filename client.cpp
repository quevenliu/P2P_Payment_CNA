#include <iostream>
#include <string>
#include <cstdlib> 
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

using namespace std;

//g++ client.cpp -o client

string sendToServer(string message, int clientSocket, struct sockaddr_in serverAddr)
{

    if (send(clientSocket, message.c_str(), strlen(message.c_str()), 0) == -1) {
        std::cerr << "Error sending data to the server" << std::endl;
        close(clientSocket);
        return "";
    }

    char buffer[1024];
    int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesRead == -1) {
        std::cerr << "Error receiving data from the server" << std::endl;
        close(clientSocket);
        return "";
    }

    buffer[bytesRead] = '\0';

    std::string receivedData(buffer);

    return receivedData;
}

int main()
{
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        std::cerr << "Error creating socket" << std::endl;
        return 1;
    }

    string ip;
    int port;

    cout << "Enter IP address: ";
    cin >> ip;
    cout << "Enter port: ";
    cin >> port;

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port); 
    serverAddr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
            std::cerr << "Error connecting to the server" << std::endl;
            close(clientSocket);
            return 1;
    }

    string username = "";

    struct sockaddr_in localAddr;
    socklen_t addrSize = sizeof(localAddr);
    if (getsockname(clientSocket, (struct sockaddr*)&localAddr, &addrSize) == -1) {
        std::cerr << "Error getting local socket address" << std::endl;
        close(clientSocket);
        return 1;
    }
    uint16_t localPort = ntohs(localAddr.sin_port);


   char choice;
    
    do {
        system("clear"); 

        std::cout << "Select an option:" << std::endl;
        std::cout << "1. Register" << std::endl;
        std::cout << "2. Login" << std::endl;
        std::cout << "3. List accounts" << std::endl;
        std::cout << "4. Transaction"   << std::endl;
        std::cout << "0. Exit" << std::endl;
        
        cin >> choice;
        string message;
        string receiver;

        switch (choice) {
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
                if (username == "") {
                    cout << "Please login first." << endl;
                    break;
                }
                int amount;
                cout << "Enter receiver: ";
                cin >> receiver;
                cout << "Enter amount: ";
                cin >> amount;
                message = username + "#" + to_string(amount) + "#" + receiver;
                break;
            case '0':
                std::cout << "Exiting..." << std::endl;
                message = "Exit";
                break;
            default:
                std::cout << "Invalid option. Please try again." << std::endl;
                break;
        }

        cout << sendToServer(message, clientSocket, serverAddr) << endl;
        
        std::cout << "Press Enter to continue..." << std::endl;

        std::cin.ignore();
        std::cin.get();
        
        
    } while (choice != '0');
    
    return 0;

}