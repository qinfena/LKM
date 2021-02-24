#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/if_packet.h>

MODULE_LICENSE("GPL");

#define NIPQUAD(addr) \
  ((unsigned char *)&addr)[0], \
  ((unsigned char *)&addr)[1], \
  ((unsigned char *)&addr)[2], \
  ((unsigned char *)&addr)[3]

struct nf_hook_ops post_hook;    /* Outgoing */
#if 0
static int have_pair = 0;	/* Marks if we already have pair */
#endif

static unsigned int watch_out(void *priv, struct sk_buff *skb,\
								const struct nf_hook_state *state) {
	struct sk_buff *sb = skb;
	struct tcphdr *tcp;
	struct iphdr * iph;

	//printk("post routing");
    /* Make sure this is a TCP packet first */
	if (ip_hdr(sb)->protocol != IPPROTO_TCP)
		return NF_ACCEPT;    /* Nope, not TCP */
		
	tcp = (struct tcphdr *)((sb->data) + (ip_hdr(sb)->ihl * 4));
	iph = ip_hdr(sb);

    /* Now check to see if it's an HTTP packet */
	if (tcp->dest != htons(80))
		return NF_ACCEPT;    /* Nope, not FTP */

    /* Parse the HTTP packet for relevant information if we don't already
	 * have a username and passwd pair. */
	 //if (!have_pair) {

		 //printk("check http dest : %d, source : %d ", tcp->dest, tcp->source);
		 printk("check http source : %d.%d.%d.%d:%d, dest : %d.%d.%d.%d:%d ", NIPQUAD(iph->saddr), tcp->source, NIPQUAD(iph->daddr), tcp->dest);
	 //}
    /* We are finished with the packet, let it go on its way */
	return NF_ACCEPT;
}

int init_module() {
	//struct net *net = NULL;
	post_hook.hook		= watch_out;
	post_hook.pf		= PF_INET;
	post_hook.priority	= NF_IP_PRI_FIRST;
	post_hook.hooknum	= NF_INET_POST_ROUTING;

	nf_register_net_hook(&init_net, &post_hook);
	return 0;
}

void cleanup_module() {
	//struct net * net = NULL;
	nf_unregister_net_hook(&init_net, &post_hook);

	return ;
}
