/* <math.h> for libopus's fixed-point build: clang builtins (wasm instructions) where there are any;
   the rest, if the linker asks for them, come from opus/src/lib.rs. */
#ifndef SIGNAL_OPUS_MATH_H
#define SIGNAL_OPUS_MATH_H
#define floor(x) __builtin_floor(x)
#define floorf(x) __builtin_floorf(x)
#define ceil(x) __builtin_ceil(x)
#define ceilf(x) __builtin_ceilf(x)
#define sqrt(x) __builtin_sqrt(x)
#define sqrtf(x) __builtin_sqrtf(x)
#define fabs(x) __builtin_fabs(x)
#define fabsf(x) __builtin_fabsf(x)
double exp(double);
double log(double);
double pow(double, double);
double cos(double);
double sin(double);
double atan(double);
double atan2(double, double);
float expf(float);
float logf(float);
float powf(float, float);
float cosf(float);
float sinf(float);
float atan2f(float, float);
long lrint(double);
long lrintf(float);
#define M_PI 3.14159265358979323846
#endif
