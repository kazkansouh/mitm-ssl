
#include <stdlib.h>
#include <stdio.h>
#include <regex.h>
#include <stdint.h>

#include "global.h"
#include "filter.h"

#define MAX_LINE 4096

typedef struct {
  const char* pc_pattern;
  regex_t r_pattern;
  char pc_linebuf[MAX_LINE + 1];
  uint16_t ui_line_len;
} SFilterStringContext;

STATIC
bool filter_string_filter(SFilterStringContext *ctx,
                          const char c) {
  if (ctx->ui_line_len < MAX_LINE) {
    ctx->pc_linebuf[ctx->ui_line_len++] = c;
    ctx->pc_linebuf[ctx->ui_line_len] = '\0';
  }
  

  if (c == '\n' || c == '\r') {
    regmatch_t rm_result;
    if (regexec(&(ctx->r_pattern),
                ctx->pc_linebuf,
                1,
                &rm_result,
                0) == 0) {
      printf("Matched: ");
      for (int i = rm_result.rm_so; i < rm_result.rm_eo; i++) {
        putchar(*(ctx->pc_linebuf + i));
      }
      putchar('\n');
    }

    ctx->ui_line_len = 0;
    ctx->pc_linebuf[0] = '\0';
  }

  return true;
}

STATIC
SFilterStringContext* filter_string_context_new(const char* pc_pattern) {
  SFilterStringContext* ctx = (SFilterStringContext*)malloc(sizeof(SFilterStringContext));
  ctx->pc_pattern = pc_pattern;
  ctx->pc_linebuf[0] = '\0';
  ctx->ui_line_len = 0;
  if (regcomp(&(ctx->r_pattern), pc_pattern, 0) != 0) {
    fprintf(stderr, "Error, failed to compile regex.\n");
  }
  return ctx;
}

STATIC
void filter_string_context_free(SFilterStringContext *ctx) {
  regfree(&(ctx->r_pattern));
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
