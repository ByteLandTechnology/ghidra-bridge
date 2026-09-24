#include <stdio.h>

#include "sample.h"

int main(int argc, char **argv) {
  (void)argv;
  struct Point points[3] = {{1, 2}, {3, 4}, {5, 6}};

  bump_counter(argc);
  int sum = sum_points(points, 3);
  int product = apply_op(multiply_ints, sum, 2);
  uint32_t check = checksum_bytes(g_lookup_table, sizeof(g_lookup_table));
  double area = cpp_total_area(argc);

  printf("%s %d %d %u %.2f %s\n", g_banner, g_counter, product, (unsigned)check, area,
         color_name(COLOR_GREEN));
  return 0;
}
