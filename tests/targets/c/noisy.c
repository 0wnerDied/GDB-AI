#include <string.h>
#include <unistd.h>

__attribute__((noinline)) static void marker(void)
{
  __asm__ volatile ("" ::: "memory");
}

int main(void)
{
  char block[16 * 1024];
  memset(block, 'A', sizeof block);

  for (int i = 0; i < 512; ++i)
    if (write(STDOUT_FILENO, block, sizeof block) != (ssize_t) sizeof block)
      return 1;

  marker();
  return 0;
}
