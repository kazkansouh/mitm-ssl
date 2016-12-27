#define _POSIX_SOURCE

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <pthread.h>

#include "global.h"
#include "server.h"

X509* g_x509_server = NULL;
EVP_PKEY* g_pkey_server = NULL;
SSL_CTX *g_ssl_ctx = NULL;

STATIC volatile
bool gb_error = false;

STATIC
bool loadCredentials(char* pc_cert, char* pc_key) {
  BIO* bio = BIO_new_file(pc_cert, "r");
  if (!bio) {
    fprintf(stderr, "failed to open certificate\n");
    return false;
  }
  g_x509_server = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  if (!g_x509_server) {
    fprintf(stderr, "failed to parse certificate\n");
  }
  BIO_free(bio);

  bio = BIO_new_file(pc_key, "r");
  if (!bio) {
    fprintf(stderr, "failed to open key\n");
    return false;
  }
  g_pkey_server = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  if (!g_pkey_server) {
    fprintf(stderr, "failed to parse key\n");
  }
  BIO_free(bio);

  return g_x509_server && g_pkey_server;
}

STATIC
void cleanup() {
  if(g_x509_server) {
    X509_free(g_x509_server);
    g_x509_server = NULL;
  }
  if (g_pkey_server) {
    EVP_PKEY_free(g_pkey_server);
    g_pkey_server = NULL;
  }
  if (g_ssl_ctx) {
    SSL_CTX_free(g_ssl_ctx);
    g_ssl_ctx = NULL;
  }

  FIPS_mode_set(0);
  // ENGINE_cleanup();
  // CONF_modules_unload(1);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  // ERR_remove_state();
  ERR_free_strings();
}

STATIC
bool createContext() {
  const SSL_METHOD *method;
  
  method = SSLv23_server_method();
  
  g_ssl_ctx = SSL_CTX_new(method);
  if (!g_ssl_ctx) {
    fprintf(stderr, "Unable to create SSL context\n");
    ERR_print_errors_fp(stderr);
    return false;
  }
  
  /* Set the key and cert */
  if (SSL_CTX_use_certificate(g_ssl_ctx, g_x509_server) < 0) {
    ERR_print_errors_fp(stderr);
    return false;
  }
  
  if (SSL_CTX_use_PrivateKey(g_ssl_ctx, g_pkey_server) < 0 ) {
    ERR_print_errors_fp(stderr);
    return false;
  }

  return true;
}

STATIC
int setupServer(uint16_t ui_port) {

    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(ui_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
      fprintf(stderr, "Unable to create socket\n");
      return -1;
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
      fprintf(stderr, "Unable to bind\n");
      return -1;
    }

    if (listen(s, 1) < 0) {
      fprintf(stderr, "Unable to listen\n");
      return -1;
    }

    return s;
}

STATIC
fRequestProcessor g_fClient = NULL;

STATIC
void* request_handler(void* c) {
  int client = (intptr_t)c;
  printf("processing request from client: %d\n", client);

  BIO* bssl = BIO_new_ssl(g_ssl_ctx, 0);
  SSL *ssl;
  BIO_get_ssl(bssl, &ssl);
  SSL_set_fd(ssl, client);
  
  if (BIO_do_handshake(bssl) <= 0) {
    ERR_print_errors_fp(stderr);
  }
  else {
    if (g_fClient) {
      g_fClient(bssl);
    } else {
      const char reply[] = "pani2c!!\n";
      BIO_write(bssl, reply, strlen(reply));
    }
  }
  
  BIO_free_all(bssl);
  close(client);
  return NULL;
}

STATIC
void sig_handler(int signo) {
  if (signo == SIGINT) {
    printf("received SIGINT\n");
    gb_error = true;
  }
}

int runServer(uint16_t ui_port,
              char* pc_cert,
              char* pc_key,
              fRequestProcessor fClient) {
  g_fClient = fClient;
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  if (!loadCredentials(pc_cert, pc_key)) {
    cleanup();
    return 1;
  }

  if (!createContext()) {
    cleanup();
    return 1;
  }

  int iSvrSocket = setupServer(ui_port);  
  gb_error = iSvrSocket < 0;
  
  struct sigaction act;
  act.sa_handler = sig_handler; 
  act.sa_flags = 0;
  sigfillset(&(act.sa_mask));
  act.sa_restorer = NULL;
  sigaction(SIGINT, &act, NULL); 

  /* Handle connections */
  while(!gb_error) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    int client = accept(iSvrSocket, (struct sockaddr*)&addr, &len);
    if (client < 0) {
      if (errno != EINTR) {
        fprintf(stderr, "Unable to accept: %s\n", strerror(errno));
        gb_error = true;
      }
    }
    
    if (!gb_error && client >= 0) {
      /* ensure created threads are detached */
      pthread_attr_t pthread_attr;
      pthread_attr_init(&pthread_attr);
      pthread_attr_setdetachstate(&pthread_attr,
                                  PTHREAD_CREATE_DETACHED);
      pthread_t threadid;
      if(pthread_create(&threadid,
                        &pthread_attr,
                        request_handler,
                        (void*)(intptr_t)client) != 0) {
        fprintf(stderr,"pthread_create failed\n");
        gb_error = true;
      }
    }
  }
  
  close(iSvrSocket);
  cleanup();

  return 0;
}
