#include <memory>
#include <vector>

#include "sample.h"
#include "shapes.hpp"

extern "C" double cpp_total_area(int scale) {
  std::vector<std::unique_ptr<sample::Shape>> shapes;
  shapes.push_back(std::make_unique<sample::Circle>(1.5));
  shapes.push_back(std::make_unique<sample::Rectangle>(2.0, 3.0));

  double total = 0.0;
  for (const auto &shape : shapes) {
    total += shape->area();
  }
  // Call back into C code from C++.
  bump_counter(add_ints(scale, 1));
  return sample::scaled(total, scale);
}
