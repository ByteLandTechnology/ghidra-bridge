#include "sample.h"

uint8_t g_lookup_table[16] = {0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
                              0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f};

uint32_t checksum_bytes(const uint8_t *data, size_t length) {
  uint32_t hash = 2166136261u;
  for (size_t index = 0; index < length; index++) {
    hash ^= data[index];
    hash *= 16777619u;
  }
  return hash;
}

const char *color_name(enum Color color) {
  switch (color) {
    case COLOR_RED:
      return "red";
    case COLOR_GREEN:
      return "green";
    case COLOR_BLUE:
      return "blue";
    default:
      return "unknown";
  }
}
