/* SPDX-License-Identifier: GPL-3.0-or-later */

struct summary { int accepted; int rejected; };

static int finish(int total)
{
  int expected = 10;
  __builtin_trap();
  return total == expected;
}

static int collect(int requested)
{
  struct summary counts = {requested, 1};
  int total = counts.accepted + counts.rejected;
  return finish(total);
}

int main(void)
{
  int requested = 8;
  return collect(requested);
}
