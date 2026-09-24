#ifndef GHIDRA_BRIDGE_SAMPLE_SHAPES_HPP
#define GHIDRA_BRIDGE_SAMPLE_SHAPES_HPP

namespace sample {

class Shape {
 public:
  virtual ~Shape();
  virtual double area() const = 0;
};

class Circle : public Shape {
 public:
  explicit Circle(double radius);
  double area() const override;

 private:
  double radius_;
};

class Rectangle : public Shape {
 public:
  Rectangle(double width, double height);
  double area() const override;

 private:
  double width_;
  double height_;
};

template <typename T>
T scaled(T value, int factor) {
  return value * static_cast<T>(factor);
}

}  // namespace sample

#endif
