#include <linux/dcache.h>
#include <linux/debugfs.h>
#include <linux/hashtable.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/pid_namespace.h>
#include <linux/ptrace.h>
#include <linux/rwlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uprobes.h>
#include <linux/wait.h>

#if __has_include("{{ conf }}")
#include "{{ conf }}"
#endif

#ifndef CIRCBUF_BITS
#define CIRCBUF_BITS 12
#endif

#ifndef CTXTABLE_BITS
#define CTXTABLE_BITS 12
#endif

#ifdef DEBUG
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ":%s: " fmt, __func__
#include <linux/printk.h>
#endif

#ifndef FILTER_POLICY
#define FILTER_POLICY 0
#endif

struct context {
    struct hlist_node node;
    pid_t pid;
    long depth;
    long bottom;
    struct {
        unsigned long rules;
        unsigned int count;
    } filter;
};

#define CONTEXT_RULES_LEN (sizeof(((struct context *)0)->filter.rules) * 8)

static inline void context_init(struct context *ctx, pid_t pid)
{
    ctx->pid = pid;
    ctx->depth = 0;
    ctx->bottom = 0;
    ctx->filter.rules = 0;
    ctx->filter.count = 0;
}

static inline void context_update_call(struct context *ctx)
{
    ctx->depth++;
}

static inline void context_update_ret(struct context *ctx)
{
    ctx->depth--;
    ctx->bottom = ctx->bottom > ctx->depth ? ctx->depth : ctx->bottom;
}

static inline void filter_push(struct context *ctx, unsigned int rule)
{
    if (ctx->filter.count < CONTEXT_RULES_LEN)
        ctx->filter.rules = (ctx->filter.rules << 1) | rule;

    ctx->filter.count++;
}

static inline void filter_pop(struct context *ctx)
{
    if (ctx->filter.count) {
        if (ctx->filter.count <= CONTEXT_RULES_LEN)
            ctx->filter.rules >>= 1;

        ctx->filter.count--;
    }
}

static inline int filter_allow(struct context *ctx)
{
    return (ctx->filter.count ? ctx->filter.rules & 1 : FILTER_POLICY) == 0;
}

#define UH(name) uprobe_handler_##name
#define URH(name) uretprobe_handler_##name

// clang-format off
#if !defined(COMPILENO) || COMPILENO > 0

int is_target(void);
struct context *context_get(void);
int tracef(const char *format, ...);

static inline unsigned long retaddr(struct pt_regs *regs)
{
    unsigned long p;
    if (copy_from_user(&p, (void __user *)regs->sp, user_64bit_mode(regs) ? 8 : 4))
        return -1;

    return p;
}

static inline unsigned long calladdr(struct pt_regs *regs)
{
    unsigned long p;
    if ((p = retaddr(regs)) == -1)
        return -1;

    /* call opecode */
    /* 0xE8 */
    /* 0xFF 0b??010??? */
    /* 0xFF 0b??011??? */
    /* 0b01001??? 0xFF 0b??011??? */
    unsigned char insn[6];
    if (copy_from_user(insn, (void __user *)(p - sizeof(insn)), sizeof(insn)))
        return -1;

    if (insn[sizeof(insn) - 5] == 0xE8 &&
        (p + insn[sizeof(insn) - 4] + (insn[sizeof(insn) - 3] << 8) + (insn[sizeof(insn) - 2] << 16) + (insn[sizeof(insn) - 1] << 24)) == regs->ip)
        return p - 5;

    for (int i = sizeof(insn) - 1; i--;)
        if (insn[i] == 0xFF &&
            ((insn[i + 1] & 0x10) == 0x10 || (insn[i + 1] & 0x18) == 0x18))
            return p - sizeof(insn) + i;

#ifdef DEBUG
    pr_notice("call opecode not found");
#endif

    return p;
}

#define uprobef(name, ctx, regs) ({                                              \
    tracef(                                                                      \
        "%d," #name ",0,%d,0x%px,"                                               \
        "0x%px,0x%px,0x%px,0x%px,0x%px,0x%px",                                   \
        (ctx)->pid, (ctx)->depth - (ctx)->bottom, calladdr(regs),                \
        (regs)->di, (regs)->si, (regs)->dx, (regs)->cx, (regs)->r8, (regs)->r9); \
})

#define uretprobef(name, ctx, regs) ({                        \
    tracef(                                                   \
        "%d," #name ",1,%d,0x%px,"                            \
        "0x%px",                                              \
        (ctx)->pid, (ctx)->depth - (ctx)->bottom, (regs)->ip, \
        (regs)->ax);                                          \
})

{% for path, funs in libs.items() %}
/*{{ '{:-^80}'.format(path) }}*/
#if !defined(COMPILENO) || COMPILENO == {{ loop.index }}

    {% for offset, name in funs.items() %}
int UH({{ name.alias }})(struct uprobe_consumer *self, struct pt_regs *regs)
{
    if (is_target()) {
        struct context *ctx;
        if ((ctx = context_get()) == NULL)
            return 0;

#ifdef FILTER_RULE_{{ name.alias }}
        filter_push(ctx, FILTER_RULE_{{ name.alias }});
#endif

        if (filter_allow(ctx))
            uprobef("{{ name.real }}", ctx, regs);

        context_update_call(ctx);
    }

    return 0;
}

int URH({{ name.alias }})(struct uprobe_consumer *self, unsigned long fun, struct pt_regs *regs)
{
    if (is_target()) {
        struct context *ctx;
        if ((ctx = context_get()) == NULL)
            return 0;

        context_update_ret(ctx);

        if (filter_allow(ctx))
            uretprobef("{{ name.real }}", ctx, regs);

#ifdef FILTER_RULE_{{ name.alias }}
        filter_pop(ctx);
#endif
    }

    return 0;
}

    {% endfor %}
#endif

{% endfor %}
#undef uprobef
#undef uretprobef
#endif

#if !defined(COMPILENO) || COMPILENO == 0

static struct {
    char *path;
    struct inode *inode;
} libs[] = {
{% for path, funs in libs.items() %}
    {"{{ path }}", NULL},
{% endfor %}
};

#define LIBS_LEN (sizeof(libs) / sizeof(libs[0]))

{% for path, funs in libs.items() %}
    {% for offset, name in funs.items() %}
int UH({{ name.alias }})(struct uprobe_consumer *self, struct pt_regs *regs);
int URH({{ name.alias }})(struct uprobe_consumer *self, unsigned long fun, struct pt_regs *regs);
    {% endfor %}
{% endfor %}

static struct {
    struct inode **inode;
    loff_t offset;
    struct uprobe_consumer uc;
    int registered;
} uprobe_args_list[] = {
#define E(i, o, h, r) {&i.inode, o, {.handler = h, .ret_handler = r}, 0}
{% for path, funs in libs.items() %}
    {% with i = loop.index0 %}
    {% for offset, name in funs.items() %}
    E(libs[{{ i }}], {{ offset }}, UH({{ name.alias }}), URH({{ name.alias }})),
    {% endfor %}
    {% endwith %}
{% endfor %}
#undef E
};

#define UPROBE_ARGS_LIST_LEN (sizeof(uprobe_args_list) / sizeof(uprobe_args_list[0]))
#endif
// clang-format on

#undef UH
#undef URH

#if !defined(COMPILENO) || COMPILENO == 0

static struct {
    unsigned int pidns;
    pid_t pid;
} target;

int is_target(void)
{
    return target.pidns == task_active_pid_ns(current)->ns.inum &&
           target.pid == task_tgid_vnr(current);
}

static struct {
    rwlock_t lock;
    DECLARE_HASHTABLE(table, CTXTABLE_BITS);
} ctxtable __read_mostly;

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

struct context *context_get(void)
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

static int uprobe_register_all(void)
{
    int err = 0;

    target.pidns = task_active_pid_ns(current)->ns.inum;

    for (int i = 0; i < LIBS_LEN; i++) {
        struct path path;

        if ((err = kern_path(libs[i].path, LOOKUP_FOLLOW, &path)) < 0)
            break;

        if ((libs[i].inode = igrab(d_real_inode(path.dentry))) == NULL)
            err = -ENOENT;

        path_put(&path);

        if (err < 0)
            break;
    }

    if (err < 0)
        return err;

    for (int i = 0; i < UPROBE_ARGS_LIST_LEN; i++) {
        err = uprobe_register(*uprobe_args_list[i].inode, uprobe_args_list[i].offset, &uprobe_args_list[i].uc);
        uprobe_args_list[i].registered = err >= 0;
    }

    return 0;
}

static void uprobe_unregister_all(void)
{
    for (int i = 0; i < UPROBE_ARGS_LIST_LEN; i++)
        if (uprobe_args_list[i].registered)
            uprobe_unregister(*uprobe_args_list[i].inode, uprobe_args_list[i].offset, &uprobe_args_list[i].uc);
}

static struct {
    spinlock_t getlock;
    spinlock_t putlock;
    int head;
    int tail;
    char *buf[1 << CIRCBUF_BITS];
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

static int circbuf_get(char **data, int blocking)
{
    int err = 0;
    DEFINE_WAIT(wait);

    while (1) {
        spin_lock(&circbuf.getlock);

        unsigned long head = smp_load_acquire(&circbuf.head);
        unsigned long tail = circbuf.tail;

        if (((head - tail) & (CIRCBUF_LEN - 1)) >= 1) {
            *data = circbuf.buf[tail];
            circbuf.buf[tail] = NULL;
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

static void circbuf_put(char *data)
{
    while (1) {
        spin_lock(&circbuf.putlock);

        unsigned long head = circbuf.head;
        unsigned long tail = READ_ONCE(circbuf.tail);

        if (((tail - head - 1) & (CIRCBUF_LEN - 1)) >= 1) {
            circbuf.buf[head] = data;
            smp_store_release(&circbuf.head, (head + 1) & (CIRCBUF_LEN - 1));
            spin_unlock(&circbuf.putlock);
            break;
        }
        else {
            spin_unlock(&circbuf.putlock);

            if (spin_trylock(&circbuf.getlock)) {
                unsigned long head = smp_load_acquire(&circbuf.head);
                unsigned long tail = circbuf.tail;
                char *old = NULL;

                if (((head - tail) & (CIRCBUF_LEN - 1)) >= 1) {
                    old = circbuf.buf[tail];
                    circbuf.buf[tail] = NULL;
                    smp_store_release(&circbuf.tail, (tail + 1) & (CIRCBUF_LEN - 1));
                }

                spin_unlock(&circbuf.getlock);
                kfree(old);

#ifdef DEBUG
                pr_notice("overwritten unread data");
#endif
            }

            continue;
        }
    }

    wake_up(&circbuf.queue);
}

static void circbuf_clear(void)
{
    char *data;
    while (circbuf_get(&data, CIRCBUF_NONBLOCKING) >= 0)
        kfree(data);
}

int tracef(const char *format, ...)
{
    int err = 0;
    va_list args;
    char *msg;

    va_start(args, format);

    if ((msg = kvasprintf(GFP_KERNEL, format, args)))
        circbuf_put(msg);
    else
        err = -ENOMEM;

    va_end(args);
    return err;
}

static int file_open(struct inode *inode, struct file *file);
static ssize_t file_read(struct file *file, char __user *buf, size_t len, loff_t *offset);

static struct file_operations fops = {
    .open = file_open,
    .read = file_read,
};

static int file_open(struct inode *inode, struct file *file)
{
    circbuf_clear();
    return 0;
}

static ssize_t file_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    int err = 0;
    char *msg;

    if ((err = circbuf_get(&msg, CIRCBUF_BLOCKING)) < 0)
        return err;

    if (msg) {
        size_t n = strlen(msg) + 1;
        n = n > len ? len : n;

        if (n)
            msg[n - 1] = '\n';

        err = n;

        if (copy_to_user(buf, msg, n))
            err = -EFAULT;
    }
    else {
        err = 0;
    }

    kfree(msg);
    return err;
}

static struct dentry *debugfs_dir;

static int __init ucallg_init(void)
{
    ctxtable_init();
    circbuf_init();

    if ((debugfs_dir = debugfs_create_dir(module_name(THIS_MODULE), NULL)) == NULL)
        return -ENOMEM;

    if (sizeof(target.pid) == sizeof(u64))
        debugfs_create_u64("pid", 0600, debugfs_dir, (u64 *)&target.pid);

    if (sizeof(target.pid) == sizeof(u32))
        debugfs_create_u32("pid", 0600, debugfs_dir, (u32 *)&target.pid);

    debugfs_create_file("log", 0600, debugfs_dir, NULL, &fops);

    return uprobe_register_all();
}

static void __exit ucallg_exit(void)
{
    uprobe_unregister_all();
    debugfs_remove_recursive(debugfs_dir);
    circbuf_clear();
    ctxtable_clear();
}

MODULE_LICENSE("GPL");
module_init(ucallg_init);
module_exit(ucallg_exit);
#endif
