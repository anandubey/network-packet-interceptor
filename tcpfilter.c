#define KBUILD_MODNAME "TCPfilter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

BPF_HASH(portdata, u64, u64, 10240);

int tcpfilter(struct xdp_md *ctx)
{
    bpf_trace_printk("Packet Received.\n");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
    {
        return XDP_PASS;
    }
    else
    {
        struct iphdr *ipv4 = data + sizeof(*eth);

        if ((void*)ipv4 + sizeof(*ipv4) > data_end) {
            return XDP_PASS;
        }
        else{
            if (ipv4->protocol == IPPROTO_TCP){
                struct tcphdr *tcp = (void*)ipv4 + sizeof(*ipv4);
                if ((void*)tcp + sizeof(*tcp) <= data_end) {
                    u64 key = ipv4 -> protocol;
                    u64 def_port = 4040, *port_no;
                    port_no = portdata.lookup_or_try_init(&key, &def_port);
                    if (port_no){
                        if (ntohs(tcp -> dest) == *port_no)
                        {
                            bpf_trace_printk("Defective PORT. Packet Dropped at port number - %d\n", ntohs(tcp -> dest));
                            return XDP_DROP;
                        }
                        else
                        {
                            bpf_trace_printk("TCP packet allowed to pass at port number - %d\n", ntohs(tcp -> dest));
                            return XDP_PASS;
                        }
                    }       
                }
            }
        }
    }
    bpf_trace_printk("Connection packet SENT.\n");
    return XDP_PASS;
}
