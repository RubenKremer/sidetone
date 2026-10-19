/* C replacements for the two C++ files of libilbc (rtc_base/checks.cc and
   common_audio/signal_processing/dot_product_with_scale.cc), so the codec
   builds with a C compiler only. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

void rtc_FatalMessage(const char* file, int line, const char* msg) {
  fprintf(stderr, "iLBC check failed: %s:%d: %s\n", file, line, msg);
  abort();
}

int32_t WebRtcSpl_DotProductWithScale(const int16_t* vector1,
                                      const int16_t* vector2,
                                      size_t length,
                                      int scaling) {
  int64_t sum = 0;
  size_t i;
  for (i = 0; i < length; i++) {
    sum += (vector1[i] * vector2[i]) >> scaling;
  }
  if (sum > INT32_MAX) return INT32_MAX;
  if (sum < INT32_MIN) return INT32_MIN;
  return (int32_t)sum;
}
