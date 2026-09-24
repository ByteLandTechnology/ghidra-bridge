#include "sample.h"

int g_counter = 42;
const char g_banner[] = "ghidra-bridge-sample";
struct Point g_origin = {0, 0};

int add_ints(int a, int b) {
  return a + b;
}

int multiply_ints(int a, int b) {
  return a * b;
}

int apply_op(binary_op op, int a, int b) {
  return op(a, b);
}

int sum_points(const struct Point *points, size_t count) {
  int total = g_origin.x + g_origin.y;
  for (size_t index = 0; index < count; index++) {
    total = add_ints(total, points[index].x + points[index].y);
  }
  return total;
}

void bump_counter(int amount) {
  g_counter += amount;
}
