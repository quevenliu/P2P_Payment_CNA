#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <thread>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>

#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define CA_PATH "./server_cert"
#define KEY_FILE "./server_cert/server.key"
#define CERT_FILE "./server_cert/server.crt"
#define CA_FILE "./server_cert/server.pem"
#define BUFFER_SIZE 2048

using namespace std;

void print(const char *msg)
{
    cout << msg << endl;
}

string serverPK = "";
class User;
map<string, User *> userList;

class User
{
private:
    string username;
    string ip;
    int port;
    bool onlineStatus;
    int balance;
    static const int DEFAULT_BALANCE = 10000;

public:
    User(string username, string ip, int port)
    {
        if (userList.find(username) != userList.end())
        {
            throw "210 FAIL";
        }
        this->username = username;
        this->ip = ip;
        this->port = port;
        this->balance = User::DEFAULT_BALANCE;
        this->onlineStatus = true;
        userList.insert(pair<string, User *>(username, this));
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
    string userLogin(string ip, int port)
    {
        this->onlineStatus = true;
        this->ip = ip;
        this->port = port;
        return "100 OK";
    }
    string userLogout()
    {
        if (userList.find(this->username) == userList.end())
        {
            return "220 AUTH_FAIL";
        }
        this->onlineStatus = false;
        return "Bye";
    }
    string transfer(string from, int amount)
    {
        if (userList.find(from) == userList.end())
        {
            return "220 AUTH_FAIL";
        }
        if (userList[from]->balance < amount)
        {
            return "420 TRANSFER_FAIL";
        }
        userList[from]->balance -= amount;
        this->balance += amount;
        return "Transfer OK";
    }

    string getUserName()
    {
        return this->username;
    }

    ~User()
    {
        userList.erase(this->username);
    }
};

User *findUser(string username)
{
    if (userList.find(username) == userList.end())
    {
        return NULL;
    }
    return userList[username];
}

struct connection
{
    int socket;
    string ip;
    int port;
    SSL* ssl;
};

void connThread(connection *conn, bool verbose = false)
{
    int socket = conn->socket;
    string ip = conn->ip;
    int port = conn->port;
    SSL* ssl = conn->ssl;

    char clientBuffer[BUFFER_SIZE] = {0};
    char serverBuffer[BUFFER_SIZE] = {0};
    User *currUser = NULL;

    while (true)
    {
        if (SSL_read(ssl, clientBuffer, sizeof(clientBuffer)) > 0)
        {
            string clientMessage = string(clientBuffer);
            string serverMessage = "";

            int firstSign = clientMessage.find("#");
            int secondSign = (firstSign != string::npos) ? clientMessage.find("#", firstSign + 1) : string::npos;

            if (clientMessage.find("REGISTER") != string::npos)
            {
                try
                {
                    string username = clientMessage.substr(firstSign + 1);
                    
                    if (verbose)
                        cout << username << " register" << endl;

                    currUser = new User(username, ip, port);
                    serverMessage = "100 OK";
                }
                catch (const char *e)
                {
                    serverMessage = e;
                }
                catch (exception &e)
                {
                    serverMessage = "500 Internal Server Error";
                }
            }
            else if (currUser == NULL)
            {
                serverMessage = "220 AUTH_FAIL\nNot logged in";
            }
            else if (clientMessage.find("List") != string::npos)
            {

                if (verbose)
                    cout << currUser->getUserName() << " list" << endl;

                serverMessage = currUser->listUsers();
            }
            else if (clientMessage.find("Exit") != string::npos)
            {

                if (verbose)
                    cout << currUser->getUserName() << " exit" << endl;

                serverMessage = currUser->userLogout();
            }
            else if (firstSign != string::npos)
            {
                if (secondSign != string::npos)
                {
                    try
                    {
                        string username = clientMessage.substr(0, firstSign);
                        int amount = stoi(clientMessage.substr(firstSign + 1, secondSign - firstSign - 1));
                        string receiver = clientMessage.substr(secondSign + 1);

                        if (verbose)
                            cout << username << " transfer " << amount << " to " << receiver << endl;
                        if (receiver != currUser->getUserName())
                        {
                            serverMessage = "220 AUTH_FAIL";
                        }
                        else
                            serverMessage = currUser->transfer(username, amount);
                        if (verbose)
                            cout << serverMessage << endl;
                    }
                    catch (exception &e)
                    {
                        serverMessage = "500 Internal Server Error";
                    }
                }
                else
                {
                    try
                    {
                        string username = clientMessage.substr(0, firstSign);
                        int transferPort = stoi(clientMessage.substr(firstSign + 1));
                        if (verbose)
                            cout << username << " login" << endl;
                        currUser = findUser(username);
                        if (currUser == NULL)
                        {
                            serverMessage = "220 AUTH_FAIL\nNot Registered";
                        }
                        else
                            serverMessage = currUser->userLogin(ip, transferPort);
                    }
                    catch (exception &e)
                    {
                        serverMessage = "500 Internal Server Error";
                    }
                }
            }
            else
            {
                serverMessage = "400 Wrong Command";
            }

            strcpy(serverBuffer, serverMessage.c_str());
            SSL_write(ssl, serverBuffer, strlen(serverBuffer));
            if (serverMessage == "Bye")
            {
                break;
            }
            memset(clientBuffer, 0, sizeof(clientBuffer));
            memset(serverBuffer, 0, sizeof(serverBuffer));
        }
    }
    close(conn->socket);
}

std::string base64Encode(const unsigned char* input, int length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);

    return result;
}

std::string publicKeyToString(const std::string &filePath = CA_FILE) {
    std::ifstream fileStream(filePath.c_str(), std::ios::binary);
    if (!fileStream.is_open()) {
        std::cerr << "Error opening file." << std::endl;
        return "";
    }

    std::stringstream fileContent;
    fileContent << fileStream.rdbuf();
    std::string pemData = fileContent.str();

    BIO *bio = BIO_new_mem_buf(pemData.c_str(), -1);
    RSA *rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (rsa == nullptr) {
        std::cerr << "Error loading RSA public key." << std::endl;
        return "";
    }

    unsigned char *pemPublic = nullptr;
    int length = i2d_RSA_PUBKEY(rsa, &pemPublic);
    if (length <= 0 || pemPublic == nullptr) {
        RSA_free(rsa);
        return "";
    }

    std::string publicKeyBase64 = base64Encode(pemPublic, length);
    OPENSSL_free(pemPublic);
    RSA_free(rsa);

    return publicKeyBase64;
}


int main(int argc, char *argv[])
{

    if (argc == 1 || (argc >= 3 && strcmp(argv[2], "-verbose") != 0))
    {
        cout << "Usage: ./server <port> [-verbose]" << endl;
        return 1;
    }
    int port = atoi(argv[1]);
    bool verbose = (argc == 3 && strcmp(argv[2], "-verbose") == 0);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX * ctx = SSL_CTX_new(TLSv1_2_server_method()); 
    SSL * ssl;

    if(! SSL_CTX_load_verify_locations(ctx, NULL, CA_PATH)) { 
        print("Error: Could not load CA file.\n"); 
        return 1;
    }

    if (! SSL_CTX_set_default_verify_paths(ctx)) { 
        print("Error: Could not load CA path.\n"); 
        return 1;
    }

    if (! SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM)) { 
        print("Error: Could not load certificate file.\n"); 
        return 1;
    }

    if (! SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM)) { 
        print("Error: Could not load private key file.\n"); 
        return 1;
    }

    if (! SSL_CTX_check_private_key(ctx)) { 
        print("Error: Private key does not match the certificate public key.\n"); 
        return 1;
    }

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket < 0)
    {
        cout << "Socket creation error" << endl;
        return 0;
    }
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0)
    {
        cout << "Binding error" << endl;
        return 0;
    }
    if (listen(serverSocket, 5) < 0)
    {
        cout << "Listening error" << endl;
        return 0;
    }

    serverPK = publicKeyToString();

    while (true)
    {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, clientSocket);
        if (clientSocket < 0)
        {
            cout << "Accepting error" << endl;
            return 0;
        }
        if (SSL_accept(ssl)  < 0)
        {
            cout << "SSL connect error!\n";
            ERR_print_errors_fp(stderr);
            return 1;
        }
        else {
            SSL_get_cipher(ssl);
        }
        connection *conn = new connection();
        conn->socket = clientSocket;
        conn->ip = inet_ntoa(clientAddr.sin_addr);
        conn->port = ntohs(clientAddr.sin_port);
        conn->ssl = ssl;
        cout << "New connection from " << conn->ip << ":" << conn->port << endl;
        thread t(connThread, conn, verbose);
        t.detach();
    }
    close(serverSocket);
    return 0;
}