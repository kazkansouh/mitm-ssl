#ifndef _MUTATOR_STRING_H
#define _MUTATOR_STRING_H

#include "mutate.h"

Mutator *mutator_string_new_Mutator(const uint8_t* const pc_prefix,
                                    const size_t s_prefix,
                                    const uint8_t* const pc_what,
                                    const uint8_t* const pc_this,
                                    const size_t s_what_this
                                    );

#endif
