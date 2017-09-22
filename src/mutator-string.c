#include <stdlib.h>

#include "global.h"
#include "mutate.h"

typedef struct {
  const uint8_t* pc_prefix;
  size_t s_prefix;
  const uint8_t* pc_what;
  const uint8_t* pc_this;
  size_t s_what_this;
} SMutatorStringMode;

typedef struct {
  const SMutatorStringMode* ps_mode;
} SMutatorStringContext;

typedef enum {
  eScan,
  eWhat
} EMutatorStringScan;

STATIC
void mutator_string_perform(SMutatorStringContext* ctx,
                            uint8_t* pc_buff,
                            size_t s_buff) {
  EMutatorStringScan state = eScan;
  int index = 0;
  for (int i = 0; i < s_buff; i++) {
    switch (state) {
    case eScan:
      if (pc_buff[i] == ctx->ps_mode->pc_prefix[index]) {
        if (++index >= ctx->ps_mode->s_prefix) {
          index = 0;
          state = eWhat;
        }
      } else {
        index = 0;
      }
      break;
    case eWhat:
      if (pc_buff[i] == ctx->ps_mode->pc_what[index]) {
        if (++index >= ctx->ps_mode->s_what_this) {
          for (int j = 0; j < ctx->ps_mode->s_what_this; j++) {
            pc_buff[i - ctx->ps_mode->s_what_this + j + 1] =
              ctx->ps_mode->pc_this[j];
          }
          index = 0;
          state = eScan;
        }
      } else {
        index = 0;
        state = eScan;
      }
      break;
    }
  }
}

STATIC
SMutatorStringContext* mutator_string_context_new(
    const SMutatorStringMode* p_mode) {
  SMutatorStringContext* ctx =
    (SMutatorStringContext*)malloc(sizeof(SMutatorStringContext));
  ctx->ps_mode = p_mode;
  return ctx;
}

STATIC
void mutator_string_context_free(SMutatorStringContext *ctx) {
  free(ctx);
}

STATIC
void mutator_string_free(Mutator *pm_mutator) {
  free(pm_mutator->pMode);
  free(pm_mutator);
}

Mutator *mutator_string_new_Mutator(const uint8_t* const pc_prefix,
                                    const size_t s_prefix,
                                    const uint8_t* const pc_what,
                                    const uint8_t* const pc_this,
                                    const size_t s_what_this
                                    ) {
  Mutator *f = (Mutator*)malloc(sizeof(Mutator));
  SMutatorStringMode *p_mode =
    (SMutatorStringMode*)malloc(sizeof(SMutatorStringMode));
  p_mode->pc_prefix   = pc_prefix;
  p_mode->s_prefix    = s_prefix;
  p_mode->pc_what     = pc_what;
  p_mode->pc_this     = pc_this;
  p_mode->s_what_this = s_what_this;
  f->pMode    = p_mode;
  f->fPerform = (fMutatorPerform)mutator_string_perform;
  f->fNewCtx  = (fMutatorContextNew)mutator_string_context_new;
  f->fFreeCtx = (fMutatorContextFree)mutator_string_context_free;
  f->fFree    = (fMutatorFree)mutator_string_free;
  return f;
}
