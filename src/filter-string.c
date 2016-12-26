
#include <stdlib.h>
#include <stdio.h>

#include "global.h"
#include "filter.h"

typedef struct {
  const char* pc_pattern;
} SFilterStringContext;

STATIC
bool filter_string_filter(SFilterStringContext *ctx, const char c) {
  printf("[%d] ", c);
  
  /**
   * TODO: Track lines, on line completion regex check 
   */

  return true;
}

STATIC
SFilterStringContext* filter_string_context_new(const char* pc_pattern) {
  SFilterStringContext* ctx = (SFilterStringContext*)malloc(sizeof(SFilterStringContext));
  ctx->pc_pattern = pc_pattern;
  return ctx;
}

STATIC
void filter_string_context_free(SFilterStringContext *ctx) {
  free(ctx);
}

Filter *filter_string_new_Filter(const char* pc_pattern) {
  Filter *f = (Filter*)malloc(sizeof(Filter));
  f->pMode    = (void*)pc_pattern;
  f->fUpdate  = (fFilterUpdate)filter_string_filter;
  f->fNewCtx  = (fFilterContextNew)filter_string_context_new;
  f->fFreeCtx = (fFilterContextFree)filter_string_context_free;
  f->fFree    = free;
  return f;
}
