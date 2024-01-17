/*{{ '{:-^80}'.format('config') }}*/
#if __has_include("{{ config }}")
#    include "{{ config }}"
#endif

#ifndef CIRCBUF_BITS
#    define CIRCBUF_BITS 12
#endif
#ifndef CTXTABLE_BITS
#    define CTXTABLE_BITS 12
#endif
#ifndef MSG_MAXSZ
#    define MSG_MAXSZ 0x400
#endif
#ifdef CHECK_DEPRECATED
#    undef CHECK_DEPRECATED
#    define CHECK_DEPRECATED 1
#else
#    define CHECK_DEPRECATED 0
#endif
#ifdef FILTER_COVERAGE
#    undef FILTER_COVERAGE
#    define FILTER_COVERAGE 1
#else
#    define FILTER_COVERAGE 0
#endif
#ifndef FILTER_MAX_DEPTH
#    define FILTER_MAX_DEPTH 0
#endif
#ifndef FILTER_POLICY
#    define FILTER_POLICY 0
#endif
// clang-format off
{% for path, funs in libs.items() %}
    {% for offset, name in funs.items() %}
#ifndef FILTER_RULE_{{ name.alias }}
#    define FILTER_RULE_{{ name.alias }} -1
#endif
#ifdef URETPROBE_DISABLE_{{ name.alias }}
#    undef URETPROBE_DISABLE_{{ name.alias }}
#    define URETPROBE_DISABLE_{{ name.alias }} 1
#else
#    define URETPROBE_DISABLE_{{ name.alias }} 0
#endif
    {% endfor %}
{% endfor %}
// clang-format on

/*{{ '{:-^80}'.format('text') }}*/
#define pr_fmt(fmt) KBUILD_MODNAME ":%s: " fmt "\n", __func__
#include <linux/dcache.h>
#include <linux/debugfs.h>
#include <linux/hashtable.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/pid_namespace.h>
#include <linux/printk.h>
#include <linux/ptrace.h>
#include <linux/rwlock.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/sprintf.h>
#include <linux/uaccess.h>
#include <linux/uprobes.h>
#include <linux/wait.h>

struct uprobe_custom_consumer {
    struct uprobe_consumer uc;
    char *name;
    char *alias;
    int rule;
    int deprecated;
    unsigned short rno[2];
};

static int uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs);
static int uretprobe_handler(struct uprobe_consumer *uc, unsigned long fun, struct pt_regs *regs);

static struct {
    char *path;
    struct inode *inode;
} libs[] = {
// clang-format off
{% for path, funs in libs.items() %}
    {"{{ path }}", NULL},
{% endfor %}
// clang-format on
};

static struct {
    struct inode **inode;
    loff_t offset;
    struct uprobe_custom_consumer ucc;
} uprobe_args_list[] = {
#define E(l, o, n, a, r0, r1)                                                    \
    {                                                                            \
        .inode = &l.inode,                                                       \
        .offset = o,                                                             \
        .ucc = {                                                                 \
            .uc = {                                                              \
                .handler = uprobe_handler,                                       \
                .ret_handler = URETPROBE_DISABLE_##a ? NULL : uretprobe_handler, \
            },                                                                   \
            .name = n,                                                           \
            .alias = #a,                                                         \
            .rule = FILTER_RULE_##a,                                             \
            .deprecated = 0,                                                     \
            .rno = {r0, r1},                                                     \
        },                                                                       \
    }
// clang-format off
{% for path, funs in libs.items() %}
    {% with i = loop.index0 %}
    {% for offset, name in funs.items() %}
    E(libs[{{ i }}], {{ offset }}, "{{ name.real }}", {{ name.alias }}, {{ rand(0, 0xffff) }}, {{ rand(0, 0xffff) }}),
    {% endfor %}
    {% endwith %}
{% endfor %}
// clang-format on
#undef E
};

#define UPROBE_ARGS_LIST_LEN (sizeof(uprobe_args_list) / sizeof(uprobe_args_list[0]))

static int uprobe_start(void)
{
    for (int i = 0; i < sizeof(libs) / sizeof(libs[0]); i++) {
        int err = 0;
        struct path path;

        if ((err = kern_path(libs[i].path, LOOKUP_FOLLOW, &path)) < 0)
            break;

        if ((libs[i].inode = igrab(d_real_inode(path.dentry))) == NULL)
            err = -ENOENT;

        path_put(&path);

        if (err < 0)
            return err;
    }

    for (int i = 0; i < UPROBE_ARGS_LIST_LEN; i++)
        uprobe_register(*uprobe_args_list[i].inode, uprobe_args_list[i].offset, &uprobe_args_list[i].ucc.uc);

    return 0;
}

static void uprobe_stop(void)
{
    for (int i = 0; i < UPROBE_ARGS_LIST_LEN; i++)
        uprobe_unregister(*uprobe_args_list[i].inode, uprobe_args_list[i].offset, &uprobe_args_list[i].ucc.uc);
}

static struct {
    unsigned int pidns;
    pid_t pid;
} target;

static void target_init(void)
{
    target.pidns = task_active_pid_ns(current)->ns.inum;
}

static int target_ok(void)
{
    return target.pidns == task_active_pid_ns(current)->ns.inum &&
           target.pid == task_tgid_vnr(current);
}

struct context {
    struct hlist_node node;
    pid_t pid;
    unsigned long depth;
    struct {
        unsigned long rules;
        unsigned int count;
    } filter;
    unsigned short prev;
};

#define CONTEXT_RULES_LEN (sizeof(((struct context *)0)->filter.rules) * 8)

static struct {
    rwlock_t lock;
    DECLARE_HASHTABLE(table, CTXTABLE_BITS);
} ctxtable;

static void ctxtable_init(void)
{
    rwlock_init(&ctxtable.lock);
    hash_init(ctxtable.table);
}

static void ctxtable_clear(void)
{
    unsigned int bkt;
    struct hlist_node *tmp;
    struct context *found;

    write_lock(&ctxtable.lock);

    hash_for_each_safe (ctxtable.table, bkt, tmp, found, node) {
        hash_del(&found->node);
        kfree(found);
    }

    write_unlock(&ctxtable.lock);
}

static void context_init(struct context *ctx, pid_t pid)
{
    ctx->pid = pid;
    ctx->depth = 0;
    ctx->filter.rules = 0;
    ctx->filter.count = 0;
    ctx->prev = 0;
}

static struct context *context_get(void)
{
    struct context *found = NULL, *new = NULL;
    pid_t pid = task_pid_nr(current);

    read_lock(&ctxtable.lock);

    hash_for_each_possible (ctxtable.table, found, node, pid)
        if (pid == found->pid)
            break;

    read_unlock(&ctxtable.lock);

    if (found)
        goto EXIT;

    if ((new = kmalloc(GFP_KERNEL, sizeof(struct context))) == NULL)
        goto EXIT;

    context_init(new, pid);
    write_lock(&ctxtable.lock);

    hash_for_each_possible (ctxtable.table, found, node, pid)
        if (pid == found->pid)
            break;

    if (found == NULL) {
        hash_add(ctxtable.table, &new->node, pid);
        found = new;
        new = NULL;
    }

    write_unlock(&ctxtable.lock);

EXIT:
    kfree(new);
    return found;
}

static int rule_exists(struct uprobe_custom_consumer *ucc)
{
    return ucc->rule >= 0;
}

static void filter_push(struct context *ctx, unsigned int rule)
{
    if (ctx->filter.count < CONTEXT_RULES_LEN)
        ctx->filter.rules = (ctx->filter.rules << 1) | rule;

    ctx->filter.count++;
}

static void filter_pop(struct context *ctx)
{
    if (ctx->filter.count) {
        if (ctx->filter.count <= CONTEXT_RULES_LEN)
            ctx->filter.rules >>= 1;

        ctx->filter.count--;
    }
}

static int filter_allow(struct context *ctx)
{
    return (ctx->filter.count ? ctx->filter.rules & 1 : FILTER_POLICY) == 0;
}

static unsigned char coverage[0x10000 >> 3] = {0};

static void coverage_clear(void)
{
    for (int i = 0; i < sizeof(coverage); i++)
        coverage[i] = 0;
}

static int coverage_has_passed(struct context *ctx, unsigned long ip, unsigned short rno)
{
    unsigned short cur = ip ^ rno;
    unsigned short key = ctx->prev ^ cur;
    ctx->prev = cur >> 1;
    int i = key >> 3;
    int j = key & 7;
    int old = coverage[i] >> j & 1;
    coverage[i] |= 1 << j;
    return old;
}

struct record {
    pid_t pid;
    char *name;
    unsigned long ip;
    unsigned long depth;
    unsigned int type;
    union {
        unsigned long args[6];
        unsigned long retval;
    };
};

#define RCDTYPE_CALL 0
#define RCDTYPE_BP 1
#define RCDTYPE_RET 2

static void record_set(struct record *rcd, struct uprobe_custom_consumer *ucc, struct context *ctx, unsigned long ip)
{
    rcd->pid = ctx->pid;
    rcd->name = ucc->name;
    rcd->ip = ip;
    rcd->depth = ctx->depth;
}

static int memory_x(unsigned long p)
{
    struct mm_struct *mm = current->mm;

    if (mm == NULL)
        return 0;

    mmap_write_lock(mm);

    struct vm_area_struct *vma = find_vma(mm, p);
    int err = vma == NULL ||
              vma->vm_start > p ||
              vma->vm_file == NULL ||
              (vma->vm_flags & (VM_MAYEXEC | VM_HUGETLB | VM_MAYSHARE | VM_WRITE)) != VM_MAYEXEC;

    mmap_write_unlock(mm);

    if (err)
        return 0;

    return 1;
}

#ifdef CONFIG_X86
static void arch_record_set(struct record *rcd, unsigned int type, struct pt_regs *regs)
{
    rcd->type = type;

    switch (type) {
    case RCDTYPE_CALL:
    case RCDTYPE_BP:
        rcd->args[0] = regs->di;
        rcd->args[1] = regs->si;
        rcd->args[2] = regs->dx;
        rcd->args[3] = regs->cx;
        rcd->args[4] = regs->r8;
        rcd->args[5] = regs->r9;
        break;

    case RCDTYPE_RET:
        rcd->retval = regs->ax;
        break;
    }
}

static unsigned long return_address(struct pt_regs *regs)
{
    unsigned long p;

    if (copy_from_user(&p, (void __user *)regs->sp, user_64bit_mode(regs) ? 8 : 4))
        return 0;

    return p;
}
#endif

static void record_put(struct record *rcd);

static int uprobe_handler(struct uprobe_consumer *uc, struct pt_regs *regs)
{
    struct uprobe_custom_consumer *ucc = (struct uprobe_custom_consumer *)uc;

    if (target_ok()) {
        struct context *ctx;
        if ((ctx = context_get()) == NULL)
            return 0;

        unsigned long ra = 0;
        if (ucc->uc.ret_handler) {
            if (rule_exists(ucc))
                filter_push(ctx, ucc->rule);

            if (CHECK_DEPRECATED || FILTER_COVERAGE)
                ra = return_address(regs);

            if (CHECK_DEPRECATED && !ucc->deprecated && !(ra && memory_x(ra)))
                ucc->deprecated = 1;
        }

        unsigned long ip = instruction_pointer(regs);

        if (filter_allow(ctx) &&
            (!FILTER_COVERAGE || !coverage_has_passed(ctx, ra ? ra : ip, ucc->rno[0])) &&
            (!FILTER_MAX_DEPTH || ctx->depth <= FILTER_MAX_DEPTH)) {

            struct record rcd;
            record_set(&rcd, ucc, ctx, ip);
            arch_record_set(&rcd, ucc->uc.ret_handler ? RCDTYPE_CALL : RCDTYPE_BP, regs);
            record_put(&rcd);
        }

        if (ucc->uc.ret_handler)
            ctx->depth++;
    }

    return 0;
}

static int uretprobe_handler(struct uprobe_consumer *uc, unsigned long fun, struct pt_regs *regs)
{
    struct uprobe_custom_consumer *ucc = (struct uprobe_custom_consumer *)uc;

    if (target_ok()) {
        struct context *ctx;
        if ((ctx = context_get()) == NULL)
            return 0;

        if (ctx->depth)
            ctx->depth--;

        unsigned long ip = instruction_pointer(regs);

        if (filter_allow(ctx) &&
            (!FILTER_COVERAGE || !coverage_has_passed(ctx, ip, ucc->rno[1])) &&
            (!FILTER_MAX_DEPTH || ctx->depth <= FILTER_MAX_DEPTH)) {

            struct record rcd;
            record_set(&rcd, ucc, ctx, ip);
            arch_record_set(&rcd, RCDTYPE_RET, regs);
            record_put(&rcd);
        }

        if (rule_exists(ucc))
            filter_pop(ctx);
    }

    return 0;
}

static struct {
    spinlock_t getlock;
    spinlock_t putlock;
    int head;
    int tail;
    struct record buf[1 << CIRCBUF_BITS];
    wait_queue_head_t queue;
} circbuf;

#define CIRCBUF_LEN (sizeof(circbuf.buf) / sizeof(circbuf.buf[0]))
#define CIRCBUF_NONBLOCKING 0
#define CIRCBUF_BLOCKING 1

static void circbuf_init(void)
{
    spin_lock_init(&circbuf.getlock);
    spin_lock_init(&circbuf.putlock);
    circbuf.head = 0;
    circbuf.tail = 0;
    init_waitqueue_head(&circbuf.queue);
}

static void circbuf_clear(void)
{
    spin_lock(&circbuf.getlock);
    spin_lock(&circbuf.putlock);

    circbuf.head = 0;
    circbuf.tail = 0;

    spin_unlock(&circbuf.putlock);
    spin_unlock(&circbuf.getlock);
}

static int record_get(struct record *rcd, int blocking)
{
    int err = 0;
    DEFINE_WAIT(wait);

    while (1) {
        spin_lock(&circbuf.getlock);

        unsigned long head = smp_load_acquire(&circbuf.head);
        unsigned long tail = circbuf.tail;

        if (((head - tail) & (CIRCBUF_LEN - 1)) >= 1) {
            *rcd = circbuf.buf[tail];
            smp_store_release(&circbuf.tail, (tail + 1) & (CIRCBUF_LEN - 1));
            spin_unlock(&circbuf.getlock);
            break;
        }
        else {
            spin_unlock(&circbuf.getlock);

            if (!blocking) {
                err = -EAGAIN;
                break;
            }

            prepare_to_wait(&circbuf.queue, &wait, TASK_INTERRUPTIBLE);

            if (signal_pending(current)) {
                err = -EINTR;
                break;
            }

            schedule();
            continue;
        }
    }

    finish_wait(&circbuf.queue, &wait);
    return err;
}

static void record_put(struct record *rcd)
{
    while (1) {
        spin_lock(&circbuf.putlock);

        unsigned long head = circbuf.head;
        unsigned long tail = READ_ONCE(circbuf.tail);

        if (((tail - head - 1) & (CIRCBUF_LEN - 1)) >= 1) {
            circbuf.buf[head] = *rcd;
            smp_store_release(&circbuf.head, (head + 1) & (CIRCBUF_LEN - 1));
            spin_unlock(&circbuf.putlock);
            break;
        }
        else {
            spin_unlock(&circbuf.putlock);

            if (spin_trylock(&circbuf.getlock)) {
                unsigned long head = smp_load_acquire(&circbuf.head);
                unsigned long tail = circbuf.tail;

                if (((head - tail) & (CIRCBUF_LEN - 1)) >= 1)
                    smp_store_release(&circbuf.tail, (tail + 1) & (CIRCBUF_LEN - 1));

                spin_unlock(&circbuf.getlock);
                pr_devel("overwritten unread record");
            }

            continue;
        }
    }

    wake_up(&circbuf.queue);
}

static int log_open(struct inode *inode, struct file *file);
static ssize_t log_read(struct file *file, char __user *buf, size_t len, loff_t *pos);

static struct file_operations log_fops = {
    .open = log_open,
    .read = log_read,
};

static int log_open(struct inode *inode, struct file *file)
{
    circbuf_clear();
    if (FILTER_COVERAGE)
        coverage_clear();

    return 0;
}

static ssize_t log_read(struct file *file, char __user *buf, size_t len, loff_t *pos)
{
    int err = 0;
    struct record rcd;
    char msg[MSG_MAXSZ];

    if ((err = record_get(&rcd, CIRCBUF_BLOCKING)) < 0)
        return err;

    switch (rcd.type) {
    case RCDTYPE_CALL:
    case RCDTYPE_BP:
        err = snprintf(msg, sizeof(msg),
                       "%d,\"%s\",%d,%ld,%#lx,"
                       "%#lx,%#lx,%#lx,%#lx,%#lx,%#lx",
                       rcd.pid, rcd.name, rcd.type, rcd.depth, rcd.ip,
                       rcd.args[0], rcd.args[1], rcd.args[2], rcd.args[3], rcd.args[4], rcd.args[5]);
        break;

    case RCDTYPE_RET:
        err = snprintf(msg, sizeof(msg),
                       "%d,\"%s\",%d,%ld,%#lx,"
                       "%#lx",
                       rcd.pid, rcd.name, rcd.type, rcd.depth, rcd.ip,
                       rcd.retval);
        break;
    }

    if (err >= sizeof(msg))
        err = sizeof(msg) - 1;

    err++;
    err = err > len ? len : err;

    if (err)
        msg[err - 1] = '\n';

    if (copy_to_user(buf, msg, err))
        err = -EFAULT;

    return err;
}

static int deprecated_open(struct inode *inode, struct file *file);
static void *deprecated_start(struct seq_file *m, loff_t *pos);
static void deprecated_stop(struct seq_file *m, void *v);
static void *deprecated_next(struct seq_file *m, void *v, loff_t *pos);
static int deprecated_show(struct seq_file *m, void *v);

static struct file_operations deprecated_fops = {
    .open = deprecated_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};

static struct seq_operations deprecated_seqops = {
    .start = deprecated_start,
    .stop = deprecated_stop,
    .next = deprecated_next,
    .show = deprecated_show,
};

static int deprecated_open(struct inode *inode, struct file *file)
{
    return seq_open(file, &deprecated_seqops);
}

static void *deprecated_start(struct seq_file *m, loff_t *pos)
{
    struct uprobe_custom_consumer *ucc = NULL;

    for (; *pos < UPROBE_ARGS_LIST_LEN && ucc == NULL; (*pos)++)
        if (uprobe_args_list[*pos].ucc.deprecated)
            ucc = &uprobe_args_list[*pos].ucc;

    return (void *)ucc;
}

static void deprecated_stop(struct seq_file *m, void *v) {}

static void *deprecated_next(struct seq_file *m, void *v, loff_t *pos)
{
    return deprecated_start(m, pos);
}

static int deprecated_show(struct seq_file *m, void *v)
{
    struct uprobe_custom_consumer *ucc = (struct uprobe_custom_consumer *)v;

    seq_puts(m, ucc->alias);
    seq_putc(m, '\n');
    return 0;
}

MODULE_LICENSE("GPL");
static int __init ucallg_init(void);
static void __exit ucallg_exit(void);
module_init(ucallg_init);
module_exit(ucallg_exit);

static struct dentry *debugfs_dir;

static int __init ucallg_init(void)
{
    int err = 0;

    pr_devel("start");
    ctxtable_init();
    circbuf_init();

    if ((debugfs_dir = debugfs_create_dir(module_name(THIS_MODULE), NULL)) == NULL)
        return -ENOMEM;

    if (sizeof(target.pid) == sizeof(u64))
        debugfs_create_u64("pid", 0600, debugfs_dir, (u64 *)&target.pid);

    if (sizeof(target.pid) == sizeof(u32))
        debugfs_create_u32("pid", 0600, debugfs_dir, (u32 *)&target.pid);

    debugfs_create_file("log", 0600, debugfs_dir, NULL, &log_fops);
    debugfs_create_file("deprecated", 0600, debugfs_dir, NULL, &deprecated_fops);

    target_init();

    if ((err = uprobe_start()) < 0)
        debugfs_remove_recursive(debugfs_dir);

    return err;
}

static void __exit ucallg_exit(void)
{
    uprobe_stop();
    debugfs_remove_recursive(debugfs_dir);
    circbuf_clear();
    ctxtable_clear();
    pr_devel("stop");
}
