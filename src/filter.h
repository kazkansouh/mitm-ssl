#ifndef _FILTER_H
#define _FILTER_H

#include <stdbool.h>

typedef bool (*fFilterUpdate)(void* ctx, const char c);
typedef void* (*fFilterContextNew)(void* mode);
typedef void (*fFilterContextFree)(void* ctx);
typedef void (*fFilterFree)(void* ctx);

typedef struct {
  void*              pMode;
  fFilterUpdate      fUpdate;
  fFilterContextNew  fNewCtx;
  fFilterContextFree fFreeCtx;
  fFilterFree        fFree;
} Filter;

#endif
