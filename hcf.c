#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include<linux/jiffies.h>
#define BUFFERSIZE 10
#define SAMPLESIZE 10000


extern struct pair ip2hc[BUFFERSIZE];
extern double expDistribution[SAMPLESIZE];
unsigned int hcfState;  // 0 = Learning, 1 = Filtering.
static unsigned int packetCounter = 0;
static unsigned int sampleCounter = 0;
static unsigned int errorCounter = 0;
unsigned int receivedHopCount, flag;
unsigned int i, mid, initialTTL;
unsigned int initialTTLSet[6] = {30, 32, 60, 64, 128, 255};
unsigned long start_time;
unsigned long total_time;
unsigned long errorAvg, learnThreshold, filterThreshold;

//Make an initialisation function for learn and filter states


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

static unsigned int checkErrorAverage(unsigned int errorCount)
{
    total_time = jiffies - start_time;
    errorAvg = errorCount / total_time;
    if(errorAvg > learnThreshold)
        return 1;
    else
        return 0;
}

static unsigned int hcfLearn(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
    packetCounter++;
    if(packetCounter == expDistribution[sampleCounter])
    {
        sampleCounter++;
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
            if(initialTTL == initialTTLSet[0])
            {
                if(initialTTLSet[1] - ip_header->ttl == hopCount(ip_header->saddr))
                {
                    flag = 1;
                }
            }
            else if(initialTTL == initialTTLSet[1])
            {
                if(initialTTLSet[2] - ip_header->ttl == hopCount(ip_header->saddr))
                {
                    flag = 1;
                }
            }
            else if(initialTTL == initialTTLSet[2])
            {
                if(initialTTLSet[3] - ip_header->ttl == hopCount(ip_header->saddr))
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
                errorCounter++;
                if(checkErrorAverage(errorCounter))
                {
                    hcfState = 1;
                }
                else
                {
                    return NF_ACCEPT;
                }
            }
        }
    }
    else
    {
        return NF_ACCEPT;
    }
    
}


static unsigned int hcfFilter(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
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
            if(initialTTL == initialTTLSet[0])
            {
                if(initialTTLSet[1] - ip_header->ttl == hopCount(ip_header->saddr))
                {
                    flag = 1;
                }
            }
            else if(initialTTL == initialTTLSet[1])
            {
                if(initialTTLSet[2] - ip_header->ttl == hopCount(ip_header->saddr))
                {
                    flag = 1;
                }
            }
            else if(initialTTL == initialTTLSet[2])
            {
                if(initialTTLSet[3] - ip_header->ttl == hopCount(ip_header->saddr))
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
                             


static unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff *))
{
    while(1)
    {
        if(!hcfState)
        {
            hcfLearn(hooknum, skb, in, out);
        }
        else
        {
            hcfFilter(hooknum, skb, in, out);
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
    start_time = jiffies;
    //learnThreshold = ;
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
