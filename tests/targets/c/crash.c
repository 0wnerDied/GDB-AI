#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

static void *idle(void *unused)
{
  (void)unused;
  pause();
  return NULL;
}

int main(int argc, char **argv)
{
  pthread_t thread;
  if (pthread_create(&thread, NULL, idle, NULL) != 0)
    return 2;
  if (argc > 1 && argv[1][0] == 'a')
    abort();
  raise(SIGSEGV);
  return 0;
}
