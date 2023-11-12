#include <iostream>
#include <string>
#include <cstdlib> 
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/conf.h>

using namespace std;

#define CA_PATH "/home/liu/ssl"

//g++ client.cpp -o client -I /usr/local/ssl/include -L /usr/local/ssl/lib -lssl -lcrypto -Wall

void handleFailure(string message = "Error: Failure in SSL library.\n")
{
    cout << message << endl;
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return;
    }
    std::cout << "Error code: " << err << std::endl;
    char err_buf[256];
    ERR_error_string(err, err_buf);
    std::cout << err_buf << std::endl;
}


string connectToServer(string message, char* bio_connection_string, SSL* ssl, SSL_CTX* ctx, BIO* bio)
{

    bio = BIO_new_ssl_connect(ctx); 
    BIO_get_ssl(bio, & ssl); 
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, bio_connection_string);
    if(BIO_do_connect(bio) <= 0) { handleFailure("Error: Could not connect to server.\n"); }

    if(SSL_get_verify_result(ssl) != X509_V_OK) { handleFailure("Error: Verification failed.\n"); }

    BIO_write(bio, message.c_str(), message.length());

    char buf[1024];
    int len = BIO_read(bio, buf, sizeof(buf) - 1);
    buf[len] = '\0';
    string response(buf);

    SSL_shutdown(ssl);
    BIO_free_all(bio);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return response;

}

int main()
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

    cout << "Enter IP address: ";
    cin >> ip;
    cout << "Enter port: ";
    cin >> port;

    BIO * bio;

    string bio_connection_string = ip + ":" + to_string(port);
    char bio_connection_string_c[bio_connection_string.length() + 1]; 
	strcpy(bio_connection_string_c, bio_connection_string.c_str()); 

    string username = "";


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
                message = username + "#" + to_string(port);
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

        cout << connectToServer(message, bio_connection_string_c, ssl, ctx, bio) << endl;
        
        // Wait for user to press a key to continue
        std::cout << "Press Enter to continue..." << std::endl;
        getchar(); // Discard the newline character
        
    } while (choice != '0');
    
    return 0;

}