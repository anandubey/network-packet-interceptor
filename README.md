# Network Packet Interceptor

eBPF is an event driven, sandboxed program hooked inside kernel space which executes user-defined programs in the kernel without recompiling the kernel. eBPF is basically an extended and modern variation of BPF which is like a virtual machine inside the Linux kernel.These programs can be executed in various hook points but in this demo we will focus on XDP.

## Goal -
Drop the packet based on it's protocol i.e. drop all the TCP packets.
### What is XDP?
XDP provides a data path for network packets, which an eBPF program can intercept or even edit on the fly. This execution can happen in 3 different places depending on the setup or the need:
- Offloaded - NIC: eBPF program can be offloaded to the network card itself, provided that the card supports XDP offloading.
- Native - NIC Driver: eBPF will fallback to the driver if your card doesn't support offloading. The good news is that most drivers support this and performance is still impressive since the driver initialization happens before the packet entering the Linux network stack.
- Generic - Linux Network Stack: This is the last option if the mentioned methods are not supported. Performance is not as good since the packet has entered the network stack.

### Fate of the packet
After performing the required operations to the packetThe fate of packets is decided by action codes that your program returns:
- XDP_PASS: let the packet continue through the network stack
- XDP_DROP: silently drop the packet
- XDP_ABORTED: drop the packet with trace point exception
- XDP_TX: bounce the packet back to the same NIC it arrived on
- XDP_REDIRECT: redirect the packet to another NIC or user space socket via the AF_XDP address family


## Why do we need the python script?
The python script uses BCC toolkit which makes it easier to hook the eBPF program in kernel space and analyze the stack trace.
![](/output/kernel-stacktrace.png "BCC Stack Trace")
