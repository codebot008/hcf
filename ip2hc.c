#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#define BUFFERSIZE 10

struct pair 
{
  unsigned int hcount;
  unsigned int ip;
}ip2hc[BUFFERSIZE];

unsigned int receivedHopCount, flag;
unsigned int i, mid, initialTTL;
unsigned int initialTTLSet[6] = {30, 32, 60, 64, 128, 255};
//todo
static unsigned int findInitialTTL(unsigned int ttl, unsigned int l, unsigned int h)
{
    while(l <= h)
    { 
        mid  = (l + h) / 2;
        if(ttl > initialTTLSet[mid] && ttl < initialTTLSet[mid + 1])
        {
            printk(KERN_INFO "The inferred initial TTL is : %u", initialTTLSet[mid + 1]);
            return initialTTLSet[mid + 1];
        }
        else if(ttl < initialTTLSet[mid])
        {
            h = mid - 1;
        }
        else if(ttl > initialTTLSet[mid + 1])
        {
            l = mid + 1;
        }
    }
}


static unsigned int hopCountCompute(unsigned int ttl)
{
    intialTTL = findInitialTTL(ttl);
    return (intialTTL - ttl);
}


static unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff *))
{

  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb); 
  printk(KERN_ALERT "Packet coming in from %u", ip_header->saddr);
  receivedHopCount = hopCountCompute(ip_header->ttl);
  
}
static struct nf_hook_ops nfho = {
    .hook       = hook_func,
    .hooknum    = 1, /* NF_IP_LOCAL_IN */
    .pf         = PF_INET,
    .priority   = NF_IP_PRI_FIRST,
};

static int __init init_nf(void)
{
    printk(KERN_INFO "Register netfilter module.\n");
    nf_register_hook(&nfho);
    
    return 0;
}

static void __exit exit_nf(void)
{
    printk(KERN_INFO "Unregister netfilter module.\n");
    nf_unregister_hook(&nfho); 
}
  /*1. collect traces of its clients to obtain both IP ad-dresses and the corresponding hop-count values
    2.After the initial population of the mapping table and activation,
    HCF will continue adding new entries to the mapping table
    when requests with previously unseen legitimate IP addresses
    are sighted
   */

