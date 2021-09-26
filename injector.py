from bcc import BPF
import time
import os

DEVICE = "lo"

def attach_ebpf(ebpf_file):
    bpf_obj = BPF(src_file=ebpf_file)
    fn = bpf_obj.load_func("tcpfilter", BPF.XDP)
    bpf_obj.attach_xdp(DEVICE, fn, 0)
    return bpf_obj


def detach_ebpf(bpf_obj):
    bpf_obj.remove_xdp(DEVICE, 0)


def main():
    bpf_obj = attach_ebpf(ebpf_file=os.getcwd()+"/tcpfilter.c")
    try:
        bpf_obj.trace_print()
    except KeyboardInterrupt:
        pass 

    detach_ebpf(bpf_obj)


if __name__ == "__main__":
    main()
