#include <stdio.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"
#include "server.h"
#include "client-impl.h"
#include "filter-string.h"

#define IS_ARG(arg)                             \
  ((strncmp(arg, argv[i], strlen(arg)) == 0) && \
   (strlen(argv[i]) > strlen(arg)))

typedef struct {
  char* pc_host;
  uint16_t ui_rport;
  uint16_t ui_lport;
  char* pc_certificate;
  char* pc_key;
} SArguments;

void printUsage(int argc, char** argv) {
  printf("usage: %s  --host=<hostname> [--rport=<port>] [--lport=<port>] [--cert=<certificate>] [--key=<key>]\n",
         basename(argv[0]));
}

bool validateArgs(int argc,
                  char** argv,
                  SArguments* s_args) {
  bool b_hostset = false;
  for (int i = 1; i < argc; i++) {
    if (IS_ARG("--host=")) {
      s_args->pc_host = argv[i] + strlen("--host=");
      b_hostset = true;
    } else if (IS_ARG("--rport=")) {
      char *pchend = NULL;
      double port = strtod(argv[i] + strlen("--rport="), &pchend);
      if (*pchend != '\0') {
        fprintf(stderr, "Error, invalid port specification\n");
        return false;
      }
      s_args->ui_rport = port; 
    } else if (IS_ARG("--lport=")) {
      char *pchend = NULL;
      double port = strtod(argv[i] + strlen("--lport="), &pchend);
      if (*pchend != '\0') {
        fprintf(stderr, "Error, invalid port specification\n");
        return false;
      }
      s_args->ui_lport = port; 
    } else if (IS_ARG("--cert=")) {
      s_args->pc_certificate = argv[i] + strlen("--cert=");
    } else if (IS_ARG("--key=")) {
      s_args->pc_key = argv[i] + strlen("--key=");
    } else {
      fprintf(stderr, "Error, unknown argument: %s\n", argv[i]);
      return false;
    }
  }
  return b_hostset;
}

int main(int argc, char** argv) {
  printf(PACKAGE_STRING "\n");
  int iret = 1;

  SArguments s_args = { "localhost" ,
                        4433 ,
                        4443 ,
                        "snakeoil/snakeoil.pem" ,
                        "snakeoil/snakeoil.key" };
  if (!validateArgs(argc, argv, &s_args)) {
    printUsage(argc, argv);
  } else {
    printf("Using configuration:\n"
           "\tServer: %s:%d\n"
           "\tListen port: %d\n",
           s_args.pc_host,
           s_args.ui_rport,
           s_args.ui_lport);
    fflush(stdout);

    const Filter* pf_filters[] = {
      filter_string_new_Filter("^Authorization:\\s\\+Basic\\s\\+[A-Za-z0-9/+=]\\+")
    };

    iret = runServer(s_args.ui_lport,
                     s_args.pc_certificate,
                     s_args.pc_key,
                     getRequestHandler(s_args.pc_host, 
                                       s_args.ui_rport,
                                       pf_filters,
                                       sizeof(pf_filters)/sizeof(Filter*)));

    for (int i = 0; i < sizeof(pf_filters)/sizeof(Filter*); i++) {
      pf_filters[i]->fFree((void*)pf_filters[i]);
    }
  }

  return iret;
}
