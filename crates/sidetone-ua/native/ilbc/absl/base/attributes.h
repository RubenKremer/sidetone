/* Minimal stand-in for Abseil's attributes.h: the C sources of iLBC only use
   ABSL_MUST_USE_RESULT. */
#ifndef SIDETONE_ABSL_ATTRIBUTES_H_
#define SIDETONE_ABSL_ATTRIBUTES_H_
#if defined(__GNUC__) || defined(__clang__)
#define ABSL_MUST_USE_RESULT __attribute__((warn_unused_result))
#else
#define ABSL_MUST_USE_RESULT
#endif
#endif
