
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <pthread.h>

#include "global.h"

#include "client-impl.h"

#define print(msg) \
  fprintf(stderr,"Client: " msg)

#define printerr(fmt) \
  print("Error: " fmt "\n")

typedef int (*fwriter)(BIO*, const void *, int); 
typedef int (*freader)(BIO*, void *, int); 
typedef void (*ffree)(BIO*); 

struct SBioPair {
  const char* id;
  BIO *a;
  freader fa;
  ffree free;
  BIO *b;
  fwriter fb;
};

const char*    gpc_host = "localhost";
uint16_t       gui_port = 443;
const Filter** gpf_filters = NULL;
size_t         gs_filters = 0;

STATIC
void* biobind(void* c) {
  struct SBioPair *ps_pair = (struct SBioPair*)c;
  
  void* p_ctx[gs_filters];
  for (int i = 0; i < gs_filters; i++) {
    p_ctx[i] = gpf_filters[i]->fNewCtx(gpf_filters[i]->pMode);
  }

  int len = 0;
  do {
    char buff[1024];
    len = ps_pair->fa(ps_pair->a, buff, sizeof(buff));

    if(len > 0) {
      ps_pair->fb(ps_pair->b, buff, len);
#ifdef DEBUG
      printf("%s: writing: ", ps_pair->id);
#endif
      for (int i = 0; i < len; i++) {
#ifdef DEBUG
        printf("%02X ", buff[i]);
#endif
        for (int j = 0; j < gs_filters; j++) {
          gpf_filters[j]->fUpdate(p_ctx[j], buff[i]);
        }
      }
#ifdef DEBUG
      printf("\n");
#endif
    }

  } while (len > 0 || BIO_should_retry(ps_pair->a));
  
  if (ps_pair->free) {
    ps_pair->free(ps_pair->b);
  }

  for (int i = 0; i < gs_filters; i++) {
    gpf_filters[i]->fFreeCtx(p_ctx[i]);
  }

  pthread_exit(0);
}

void requestProxy(BIO* client) {

  const SSL_METHOD* method = SSLv23_method();
  if (!method) {
    printerr("failed to create method");
    return;
  }

  SSL_CTX* ctx = SSL_CTX_new(method);
  if(!ctx) {
    printerr("failed to create context");
    return;
  }

  SSL_CTX_set_verify(ctx,
                     SSL_VERIFY_NONE,
                     NULL);

  SSL_CTX_set_verify_depth(ctx, 4);

  const long flags = \
    SSL_OP_NO_SSLv3 | \
    SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);

  BIO* web = BIO_new_ssl_connect(ctx);
  if(!ctx) {
    SSL_CTX_free(ctx);
    printerr("failed to create bio");
    return;
  }

  if (BIO_set_conn_hostname(web, gpc_host) != 1) {
    SSL_CTX_free(ctx);
    BIO_free(web);
    printerr("failed to set host");
    return;
  }

  if (BIO_set_conn_int_port(web, &gui_port) != 1) {
    SSL_CTX_free(ctx);
    BIO_free(web);
    printerr("failed to set port");
    return;
  }
  
  SSL *ssl;
  BIO_get_ssl(web, &ssl);
  if(!ssl) {
    SSL_CTX_free(ctx);
    BIO_free_all(web);    
    printerr("failed to create ssl");
    return;
  }

  const char* const PREFERRED_CIPHERS = 
    "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
  if (SSL_set_cipher_list(ssl, PREFERRED_CIPHERS) != 1) {
    SSL_CTX_free(ctx);
    BIO_free_all(web);
    SSL_free(ssl);
    printerr("failed to set ciphers");
    return;
  }

  if (SSL_set_tlsext_host_name(ssl, gpc_host) != 1) {
    SSL_CTX_free(ctx);
    BIO_free_all(web);    
    printerr("failed to set tls hostname");
    return;
  }

  if (BIO_do_connect(web) != 1) {
    ERR_print_errors_fp(stderr);

    SSL_CTX_free(ctx);
    BIO_free_all(web);
    printerr("failed to do_connect");
    return;
  }

  if (BIO_do_handshake(web) != 1) {
    SSL_CTX_free(ctx);
    BIO_free_all(web);    
    printerr("failed to do_handshake");
    return;
  }

  struct SBioPair s_ab = { "ctos" 
                           , client
                           , BIO_read 
                           , BIO_ssl_shutdown
                           , web
                           , BIO_write };
  struct SBioPair s_ba = { "stoc" 
                           , web
                           , BIO_read
                           , BIO_ssl_shutdown
                           , client
                           , BIO_write };

  pthread_t pt_ab;
  pthread_t pt_ba;

  if (pthread_create(&pt_ab, NULL, biobind, &s_ab) != 0) {
    printerr("failed to spawn thread ab");
  } else {
    if (pthread_create(&pt_ba, NULL, biobind, &s_ba) != 0) {
      printerr("failed to spawn thread ba");
    } else {
      if (pthread_join(pt_ab, NULL) != 0) {
        printerr("failed to join thread ab");
      }
      if (pthread_join(pt_ba, NULL) != 0) {
        printerr("failed to join thread ba");
      }
    }
  }

  if(web)
    BIO_free_all(web);
  if(ctx)
    SSL_CTX_free(ctx);
}



fRequestProcessor getRequestHandler(const char* const pc_host, 
                                    const uint16_t ui_port,
                                    const Filter** const pf_filters,
                                    const size_t s_filters) {
  gpc_host = pc_host;
  gui_port = ui_port;
  gpf_filters = pf_filters;
  gs_filters = s_filters;
  return requestProxy;
}
