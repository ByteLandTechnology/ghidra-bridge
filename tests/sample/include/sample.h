#ifndef GHIDRA_BRIDGE_SAMPLE_H
#define GHIDRA_BRIDGE_SAMPLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct Point {
  int x;
  int y;
};

enum Color {
  COLOR_RED = 1,
  COLOR_GREEN = 2,
  COLOR_BLUE = 4
};

typedef int (*binary_op)(int, int);

extern int g_counter;
extern const char g_banner[];
extern uint8_t g_lookup_table[16];
extern struct Point g_origin;

/* checksum.c */
uint32_t checksum_bytes(const uint8_t *data, size_t length);
const char *color_name(enum Color color);

/* records.c */
int add_ints(int a, int b);
int multiply_ints(int a, int b);
int apply_op(binary_op op, int a, int b);
int sum_points(const struct Point *points, size_t count);
void bump_counter(int amount);

/* bridge.cpp */
double cpp_total_area(int scale);

#ifdef __cplusplus
}
#endif

#endif
