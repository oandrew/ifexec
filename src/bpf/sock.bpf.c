#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// #include <asm/socket.h>
// #include <asm-generic/socket.h>
#define SO_BINDTODEVICE     25
#define SO_BINDTOIFINDEX    62
#define SO_MARK             36

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u32 dev_if = 0;
const volatile u32 mark = 0;


SEC("cgroup/sock_create")
int sock_create(struct bpf_sock* ctx) {
    if (dev_if != 0) {
        ctx->bound_dev_if = dev_if;
    }
    if (mark != 0) {
        ctx->mark = mark;
    }
    return 1;
}

SEC("cgroup/setsockopt")
int setsockopt(struct bpf_sockopt* ctx) {
    s32 optname = ctx->optname;
    if (optname == SO_BINDTODEVICE || optname == SO_BINDTOIFINDEX || optname == SO_MARK) {
        ctx->optlen = -1;
    }
    return 1;
}

