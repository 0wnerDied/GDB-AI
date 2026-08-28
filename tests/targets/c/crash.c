#include <signal.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  if (argc > 1 && argv[1][0] == 'a')
    abort();
  raise(SIGSEGV);
  return 0;
}
