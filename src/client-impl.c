
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
  const char* const id;
  BIO* const a;
  const freader fa;
  const ffree free;
  BIO* const b;
  const fwriter fb;
  uint64_t* const ctr;
  pthread_mutex_t* const mx_ctr;
  const uint32_t connid;
};

const char*     gpc_host = "localhost";
uint16_t        gui_port = 443;
const Filter**  gpf_filters = NULL;
size_t          gs_filters = 0;
const Mutator** gpm_mutators = NULL;
size_t          gs_mutators = 0;
STATIC
uint32_t        gui_connid = 0;
STATIC
pthread_mutex_t gmx_connid = PTHREAD_MUTEX_INITIALIZER;

#ifdef DEBUG
STATIC
void dump(const void* data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    printf("%02X ", ((unsigned char*)data)[i]);
    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char*)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");
      if ((i+1) % 16 == 0) {
	printf("|  %s \n", ascii);
      } else if (i+1 == size) {
	ascii[(i+1) % 16] = '\0';
	if ((i+1) % 16 <= 8) {
	  printf(" ");
	}
	for (j = (i+1) % 16; j < 16; ++j) {
	  printf("   ");
	}
	printf("|  %s \n", ascii);
      }
    }
  }
}
#else
#define dump(...)
#endif

STATIC
void save(uint32_t connid, uint64_t pkt, const char* id, uint8_t* buff, size_t len) {
  char fname[35];
  FILE *f = NULL;
  snprintf(fname, sizeof(fname), "%03u-%06lu-%s.dmp", connid, pkt, id);
  printf("PKT: %s\n", fname);
  f = fopen(fname, "w");
  if (f != NULL) {
    if (fwrite(buff, len, 1, f) != 1) {
      printerr("failed to write packet to file\n");
    }
    fclose(f);
  } else {
    printerr("failed to open file to save packet\n");
  }
}


STATIC
void* biobind(void* c) {
  struct SBioPair *ps_pair = (struct SBioPair*)c;
  
  void* pf_ctx[gs_filters];
  for (int i = 0; i < gs_filters; i++) {
    pf_ctx[i] = gpf_filters[i]->fNewCtx(gpf_filters[i]->pMode);
  }

  void* pm_ctx[gs_mutators];
  for (int i = 0; i < gs_mutators; i++) {
    pm_ctx[i] = gpm_mutators[i]->fNewCtx(gpm_mutators[i]->pMode);
  }

  int len = 0;
  do {
    uint8_t buff[1024];
    uint64_t ui_pkt;
    len = ps_pair->fa(ps_pair->a, buff, sizeof(buff));

    if(len > 0) {
      for (int j = 0; j < gs_mutators; j++) {
        gpm_mutators[j]->fPerform(pm_ctx[j], buff, len);
      }

      ps_pair->fb(ps_pair->b, buff, len);
#ifdef DEBUG
      printf("%s: writing:\n", ps_pair->id);
      dump(buff, len);
#endif
      pthread_mutex_lock(ps_pair->mx_ctr);
      ui_pkt = (*(ps_pair->ctr))++;
      pthread_mutex_unlock(ps_pair->mx_ctr);

      if (true) {
	/* TODO: move into a thread, needs the buffer to be
	   malloc'ed */
	save(ps_pair->connid, ui_pkt, ps_pair->id, buff, len);
      }

      for (int i = 0; i < len; i++) {
        for (int j = 0; j < gs_filters; j++) {
          gpf_filters[j]->fUpdate(pf_ctx[j], buff[i]);
        }
      }
      for (int j = 0; j < gs_filters; j++) {
        gpf_filters[j]->fCheck(pf_ctx[j]);
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
    gpf_filters[i]->fFreeCtx(pf_ctx[i]);
  }

  for (int i = 0; i < gs_mutators; i++) {
    gpm_mutators[i]->fFreeCtx(pm_ctx[i]);
  }

  pthread_exit(0);
}

void requestProxy(BIO* client) {
  uint32_t ui_connid;
  const SSL_METHOD* method = SSLv23_method();
  uint64_t ui_pkt_ctr = 0;
  pthread_mutex_t mx_pkt_ctr;

  pthread_mutex_lock(&gmx_connid);
  ui_connid = gui_connid++;
  pthread_mutex_unlock(&gmx_connid);

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

  pthread_mutex_init(&mx_pkt_ctr, NULL);

  struct SBioPair s_ab = { "ctos" 
                           , client
                           , BIO_read 
                           , BIO_ssl_shutdown
                           , web
                           , BIO_write
			   , &ui_pkt_ctr
			   , &mx_pkt_ctr
			   , ui_connid };
  struct SBioPair s_ba = { "stoc" 
                           , web
                           , BIO_read
                           , BIO_ssl_shutdown
                           , client
                           , BIO_write
			   , &ui_pkt_ctr
			   , &mx_pkt_ctr
			   , ui_connid };

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

  pthread_mutex_destroy(&mx_pkt_ctr);

  if(web)
    BIO_free_all(web);
  if(ctx)
    SSL_CTX_free(ctx);
}



fRequestProcessor getRequestHandler(const char* const pc_host, 
                                    const uint16_t ui_port,
                                    const Filter** const pf_filters,
                                    const size_t s_filters,
                                    const Mutator** const pm_mutators,
                                    const size_t s_mutators) {
  gpc_host = pc_host;
  gui_port = ui_port;
  gpf_filters = pf_filters;
  gs_filters = s_filters;
  gpm_mutators = pm_mutators;
  gs_mutators = s_mutators;
  return requestProxy;
}
