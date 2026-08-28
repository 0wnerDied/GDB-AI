#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
  pid_t child = fork();
  if (child == 0)
    execl("/bin/true", "true", (char *)0);
  if (child < 0)
    return 1;
  return waitpid(child, 0, 0) < 0;
}
