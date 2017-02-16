#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#define BUFFERSIZE 10

extern struct pair ip2hc[BUFFERSIZE];
unsigned int receivedHopCount, flag;
unsigned int i, mid, initialTTL;
unsigned int initialTTLSet[6] = {30, 32, 60, 64, 128, 255};

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

static unsigned int hopCount(unsigned int source)
{
	flag = 0;
	for(i = 0; i < BUFFERSIZE; i++)
	{
		if(ip2hc[i].ip == source)
		{
			return ip2hc[i].hcount;
		}
	}
	return 0;		
}

static unsigned int hopCountCompute(unsigned int ttl)
{
    intialTTL = findInitialTTL(ttl);
    return (intialTTL - ttl);
}

static unsigned int exceptionHopCountCompute(unsigned int ttl)
{
    //TODO
}


static unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff *))
{

    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);    
    flag = 0;
    printk(KERN_ALERT "Packet coming in from %u", ip_header->saddr);
    receivedHopCount = hopCountCompute(ip_header->ttl);
    if(hopCount(ip_header->saddr) == receivedHopCount)
    {
        return NF_ACCEPT; //Packet is legitimate
    }
    else  //Checking for corner cases of initial TTL.
    {
        initialTTL = findInitialTTL(ip_header->ttl);
        if(initialTTL == 30)
        {
            if(32 - ip_header->ttl == hopCount(ip_header->saddr))
            {
                flag = 1;
            }
        }
        else if(initialTTL == 32)
        {
            if(60 - ip_header->ttl == hopCount(ip_header->saddr))
            {
                flag = 1;
            }
        }
        else if(initialTTL == 60)
        {
            if(64 - ip_header->ttl == hopCount(ip_header->saddr))
            {
                flag = 1;
            }
        }
        if(flag == 1)
        {
            return NF_ACCEPT;
        }
        else
        {
            return NF_DROP;
        }
    }
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

module_init(init_nf);
module_exit(exit_nf);
MODULE_LICENSE("GPL");
