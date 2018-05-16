#ifndef _CLIENT_IMPL_H
#define _CLIENT_IMPL_H

#include <stdint.h>

#include "client.h"
#include "filter.h"
#include "mutate.h"

fRequestProcessor getRequestHandler(const char* const pc_host, 
                                    const char* const pc_port,
                                    const Filter** const pf_filters,
                                    const size_t s_filters,
                                    const Mutator** const pm_mutators,
                                    const size_t s_mutators);

#endif
