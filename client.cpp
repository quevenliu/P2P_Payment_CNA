#include <iostream>
#include <string>
#include <cstdlib> 
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/conf.h>

using namespace std;

#define CA_PATH "/home/liu/ssl/RootCACert.pem"

// Write a function that connect to a server with openssl via secure tcp connection
// The function should take a string as an argument and send it to the server
// The function should return the response from the server as a string
// The function should be able to handle errors
// Use the openssl library
// Use the openssl documentation to find the necessary functions
// Write unit tests for any unit-testable functions
// Mock the server in the unit tests


void handleFailure(string message = "Error: Failure in SSL library.\n")
{
    cout << message << endl;
    abort();
}

void init_openssl_library()
{
  (void)SSL_library_init();

  SSL_load_error_strings();

}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

    return preverify;
}

void setup_ctx(SSL_CTX* ctx)
{
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    if (SSL_CTX_load_verify_locations(ctx, CA_PATH, NULL) <= 0)
    {
        SSL_CTX_free(ctx);
        cout << "Error loading CA file" << endl;
        exit(EXIT_FAILURE);
    }
}


void verify(SSL* ssl)
{
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) { X509_free(cert); }
    if(NULL == cert) handleFailure("Error: Could not get a certificate from: %s.\n");
    long res = SSL_get_verify_result(ssl);
    if(!(X509_V_OK == res)) handleFailure("Error: Verification failed: %i.\n");
}

string connectToServer(string message, string ip, int port, SSL* ssl, SSL_CTX* ctx)
{

    BIO *bio = BIO_new_ssl_connect(ctx);
    BIO_set_conn_hostname(bio, ip.c_str());
    BIO_set_conn_port(bio, port);
    BIO_do_connect(bio);

    long res = BIO_do_handshake(bio);
    if(!(1 == res)) handleFailure("Error: Could not build a SSL session to: %s.\n");

    SSL_set_bio(ssl, bio, bio);

    verify(ssl);

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

    BIO *web = NULL;
    SSL *ssl = NULL;

    init_openssl_library();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());

    setup_ctx(ctx);

    string username = "";

    string ip;
    int port;

    cout << "Enter IP address: ";
    cin >> ip;
    cout << "Enter port: ";
    cin >> port;

    BIO_get_ssl(web, &ssl);
    if(!(ssl != NULL)) handleFailure("Error: Could not get SSL handle.\n");

    long res = SSL_set_tlsext_host_name(ssl, ip.c_str());
    if(!(1 == res)) handleFailure("Error: Could not set TLS hostname extension.\n");

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
        string receiver;

        switch (choice) {
            case '1':
                cin >> username;
                message = "REGISTER#" + username;
                break;
            case '2':
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

        cout << connectToServer(message, ip, port, ssl, ctx) << endl;
        
        // Wait for user to press a key to continue
        std::cout << "Press Enter to continue..." << std::endl;
        getchar(); // Discard the newline character
        
    } while (choice != '0');
    
    return 0;

}