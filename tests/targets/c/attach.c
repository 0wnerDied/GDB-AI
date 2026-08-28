#include <sys/prctl.h>
#include <unistd.h>

int main(void)
{
  if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0) != 0)
    return 1;
  alarm(30);
  for (;;)
    pause();
}
