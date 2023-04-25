#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// #include <asm/socket.h>
// #include <asm-generic/socket.h>
#define SO_BINDTODEVICE      25
#define SO_BINDTOIFINDEX    62

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile u32 dev_if = 0;


SEC("cgroup/sock_create")
int sock_create(struct bpf_sock* ctx) {
	ctx->bound_dev_if = dev_if;
	// bpf_printk("sock bound_dev_if=%d.\n", ctx->bound_dev_if);
	return 1;
}

SEC("cgroup/setsockopt")
int setsockopt(struct bpf_sockopt* ctx) {
	s32 optname = ctx->optname;
	if (optname == SO_BINDTODEVICE || optname == SO_BINDTOIFINDEX) {
		ctx->optlen = -1;
	}
	return 1;
}

