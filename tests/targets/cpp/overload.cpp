#include <string>

static int parse(const char *value) { return value[0]; }
static int parse(const std::string &value) { return value.at(0); }

int main()
{
  return parse("a") == parse(std::string("a")) ? 0 : 1;
}
