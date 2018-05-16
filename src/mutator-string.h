#ifndef _MUTATOR_STRING_H
#define _MUTATOR_STRING_H

#include "mutate.h"

/*
 * Stream mutator, searches for pc_prefix in the raw bytes, if found,
 * then searches for pc_what and replaces it with pc_this. Note, both
 * pc_what and pc_this should be the same length.
 *
 * Does not support contiguious operation over multiple packets,
 * i.e. if a match lies on the boundary of two packets it will not be
 * replaced.
 */
Mutator *mutator_string_new_Mutator(const uint8_t* const pc_prefix,
                                    const size_t s_prefix,
                                    const uint8_t* const pc_what,
                                    const uint8_t* const pc_this,
                                    const size_t s_what_this
                                    );

#endif
