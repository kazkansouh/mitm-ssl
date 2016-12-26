#ifndef _CLIENT_IMPL_H
#define _CLIENT_IMPL_H

#include <stdint.h>

#include "client.h"

fRequestProcessor getRequestHandler(const char* const pc_host, 
                                    const uint16_t ui_port);

#endif
