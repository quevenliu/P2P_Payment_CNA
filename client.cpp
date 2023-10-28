#include <iostream>
#include <string>
#include <cstdlib> 
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

using namespace std;

// Write a function that connect to a server with openssl via secure tcp connection
// The function should take a string as an argument and send it to the server
// The function should return the response from the server as a string
// The function should be able to handle errors
// Use the openssl library
// Use the openssl documentation to find the necessary functions
// Write unit tests for any unit-testable functions
// Mock the server in the unit tests

string connectToServer(string message, string ip, int port)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    BIO *bio = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(bio, ip.c_str());
    BIO_set_conn_int_port(bio, port);
    BIO_do_connect(bio);
    SSL_set_bio(ssl, bio, bio);

    BIO_write(bio, message.c_str(), message.length());

    char buf[1024];
    int len = BIO_read(bio, buf, sizeof(buf) - 1);
    buf[len] = '\0';
    string response(buf);

    // close connection
    SSL_shutdown(ssl);
    BIO_free_all(bio);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    // return response
    return response;
}

int main()
{

    string username = "";

    string ip;
    int port;

    cout << "Enter IP address: ";
    cin >> ip;
    cout << "Enter port: ";
    cin >> port;

    char choice;
    
    do {
        system("clear"); // Clear the screen (for Linux/macOS)

        // Display the menu options
        std::cout << "Select an option:" << std::endl;
        std::cout << "1. Register" << std::endl;
        std::cout << "2. Login" << std::endl;
        std::cout << "3. List accounts" << std::endl;
        std::cout << "4. Transaction"   << std::endl;
        std::cout << "0. Exit" << std::endl;
        
        choice = getchar(); 
        string message;

        switch (choice) {
            case '1':
                cin >> username;
                message = "REGISTER#" + username;
                break;
            case '2':
                cin >> username;
                message = username + "#" + port;
                break;
            case '3':
                message = "List";
                break;
            case '4':
                if (username == "") {
                    cout << "Please login first." << endl;
                    break;
                }
                string receiver;
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

        cout << connectToServer(message, ip, port) << endl;
        
        // Wait for user to press a key to continue
        std::cout << "Press Enter to continue..." << std::endl;
        getchar(); // Discard the newline character
        
    } while (choice != '0');
    
    return 0;

}