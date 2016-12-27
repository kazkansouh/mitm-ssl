#ifndef _SERVER_H
#define _SERVER_H

#include "client.h"

int runServer(uint16_t ui_port,
              char* pc_cert,
              char* pc_key,
              fRequestProcessor f);

#endif
