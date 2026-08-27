#include <stdio.h>

volatile int global_value = 7;

__attribute__((noinline)) static void marker(void)
{
  global_value = 42;
  puts("marker reached");
}

int main(void)
{
  marker();
  return global_value == 42 ? 0 : 1;
}
