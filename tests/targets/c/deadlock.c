#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static pthread_mutex_t first = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t second = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t ready;

static void *worker_left(void *argument)
{
  pthread_mutex_lock(&first);
  pthread_barrier_wait(&ready);
  pthread_mutex_lock(&second);
  return argument;
}

static void *worker_right(void *argument)
{
  pthread_mutex_lock(&second);
  pthread_barrier_wait(&ready);
  pthread_mutex_lock(&first);
  return argument;
}

int main(void)
{
  pthread_t left, right;
  alarm(60);
  /* The barrier makes opposite lock ownership reproducible on every run. */
  pthread_barrier_init(&ready, NULL, 3);
  pthread_create(&left, NULL, worker_left, NULL);
  pthread_create(&right, NULL, worker_right, NULL);
  pthread_barrier_wait(&ready);
  puts("workers started");
  fflush(stdout);
  pthread_join(left, NULL);
  pthread_join(right, NULL);
  return 0;
}
