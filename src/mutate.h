#ifndef _MUTATE_H
#define _MUTATE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

typedef void (*fMutatorPerform)(void* ctx, uint8_t* p_buff, size_t s_buff);
typedef void* (*fMutatorContextNew)(void* mode);
typedef void (*fMutatorContextFree)(void* ctx);
typedef void (*fMutatorFree)(void* ctx);

typedef struct {
  void*              pMode;
  fMutatorPerform     fPerform;
  fMutatorContextNew  fNewCtx;
  fMutatorContextFree fFreeCtx;
  fMutatorFree        fFree;
} Mutator;

#endif
