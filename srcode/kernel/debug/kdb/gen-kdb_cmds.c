#include <linux/stddef.h>
#include <linux/init.h>
static __initdata char kdb_cmd0[] = "defcmd dumpcommon \"\" \"Common kdb debugging\"\n";
static __initdata char kdb_cmd1[] = "  set BTAPROMPT 0\n";
static __initdata char kdb_cmd2[] = "  set LINES 10000\n";
static __initdata char kdb_cmd3[] = "  -summary\n";
static __initdata char kdb_cmd4[] = "  -cpu\n";
static __initdata char kdb_cmd5[] = "  -ps\n";
static __initdata char kdb_cmd6[] = "  -dmesg 600\n";
static __initdata char kdb_cmd7[] = "  -bt\n";
static __initdata char kdb_cmd8[] = "endefcmd\n";
static __initdata char kdb_cmd9[] = "defcmd dumpall \"\" \"First line debugging\"\n";
static __initdata char kdb_cmd10[] = "  pid R\n";
static __initdata char kdb_cmd11[] = "  -dumpcommon\n";
static __initdata char kdb_cmd12[] = "  -bta\n";
static __initdata char kdb_cmd13[] = "endefcmd\n";
static __initdata char kdb_cmd14[] = "defcmd dumpcpu \"\" \"Same as dumpall but only tasks on cpus\"\n";
static __initdata char kdb_cmd15[] = "  pid R\n";
static __initdata char kdb_cmd16[] = "  -dumpcommon\n";
static __initdata char kdb_cmd17[] = "  -btc\n";
static __initdata char kdb_cmd18[] = "endefcmd\n";
extern char *kdb_cmds[]; char __initdata *kdb_cmds[] = {
  kdb_cmd0,
  kdb_cmd1,
  kdb_cmd2,
  kdb_cmd3,
  kdb_cmd4,
  kdb_cmd5,
  kdb_cmd6,
  kdb_cmd7,
  kdb_cmd8,
  kdb_cmd9,
  kdb_cmd10,
  kdb_cmd11,
  kdb_cmd12,
  kdb_cmd13,
  kdb_cmd14,
  kdb_cmd15,
  kdb_cmd16,
  kdb_cmd17,
  kdb_cmd18,
  NULL
};
