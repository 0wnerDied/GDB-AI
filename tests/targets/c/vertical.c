#include <stdio.h>
#include <unistd.h>

volatile int global_value = 7;
struct pair { int left; int right; } global_pair = {1, 2};
unsigned char large_buffer[4 * 1024 * 1024] = {0x5a};

__attribute__((noinline)) static void marker(void)
{
  global_value = 42;
  puts("marker reached");
}

int main(void)
{
  alarm(30);
  marker();
  (void) getchar();
  return global_value == 42 ? 0 : 1;
}
