#include "shapes.hpp"

namespace sample {

Shape::~Shape() = default;

Circle::Circle(double radius) : radius_(radius) {}

double Circle::area() const {
  return 3.14159 * radius_ * radius_;
}

Rectangle::Rectangle(double width, double height) : width_(width), height_(height) {}

double Rectangle::area() const {
  return width_ * height_;
}

}  // namespace sample
