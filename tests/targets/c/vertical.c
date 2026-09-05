#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

volatile int global_value = 7;
struct pair { int left; int right; } global_pair = {1, 2};
unsigned char large_buffer[4 * 1024 * 1024] = {0x5a};

__attribute__((noinline)) static void marker(void)
{
  global_value = 42;
  puts("marker reached");
}

__attribute__((noinline)) static void report_input(int input)
{
  printf("input received: %c\n", input);
}

int main(int argc, char **argv)
{
  const char *environment = getenv("GDB_AI_TEST_ENV");
  int input;

  /* 2026-08-29: TCG can keep this fixture stopped for over 30 seconds.
     Leave the alarm as a final guard without racing debugger deadlines. */
  alarm(300);
  printf("environment: %s\n", environment ? environment : "unset");
  for (int i = 1; i < argc; ++i) {
    printf("argument: ");
    for (const unsigned char *c = (const unsigned char *)argv[i]; *c; ++c)
      printf("%02x", *c);
    puts("");
  }
  marker();
#ifdef GDB_AI_REPEAT_MARKER
  global_value = 8;
  marker();
#endif
  input = getchar();
  report_input(input);
  return global_value == 42 ? 0 : 1;
}
