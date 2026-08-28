#include <pthread.h>

static void *worker(void *argument)
{
  return argument;
}

int main(void)
{
  pthread_t threads[8];
  for (int index = 0; index < 8; ++index)
    pthread_create(&threads[index], 0, worker, (void *)(long) index);
  for (int index = 0; index < 8; ++index)
    pthread_join(threads[index], 0);
  return 0;
}
