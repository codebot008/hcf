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

i=0;
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

//updating hop count..if same ip address(already in the table) comes with a new hop count then update the table
static unsigned int updateIP2HC(struct sk_buff *skb)
{
  int flag,j;
  flag=0;
  
    if((skb -> sk) -> sk_state == TCP_ESTABLISHED)
    {
        //Update the appropriate hop count entry in the IP2HC
        //collect ip address see if in the table then update
        struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb); 
        printk(KERN_ALERT "Packet coming in from %u", ip_header->saddr);
        receivedHopCount = hopCountCompute(ip_header->ttl);
        
        for(j=0;j<BUFFERSIZE && flag==0 ;j++)
        {
          if(ip_header->saddr==ip2hc[j].ip)
          {
            ip2hc[j].hcount=receivedHopCount;
            flag=1;
          }
        }
    }
}

static unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn) (struct sk_buff *))
{

  struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb); 
  printk(KERN_ALERT "Packet coming in from %u", ip_header->saddr);
  receivedHopCount = hopCountCompute(ip_header->ttl);
  if(i<BUFFERSIZE)
  {
    /*1.if same if header and differnt hop count then use link list to put new hop counts for same ipheader but this case wont arise as for same 
    ip address we have a single hop count value.. but if we were make a cluster such that for a same hop count we have many ip addresses then
    our purpose will of giving importance to ip address will not be fruitful*/
    //2.for initailization we are not considering the case that same ip address will have differnt hop count value
    ip2hc[i].hcount=receivedHopCount;
    ip2hc[i].ip=ip_header->saddr;
    i++;
  }
  else
  {
    printk(KERN_ALERT "size of table exhausted");
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
  /*1. collect traces of its clients to obtain both IP ad-dresses and the corresponding hop-count values
    2.After the initial population of the mapping table and activation,
    HCF will continue adding new entries to the mapping table
    when requests with previously unseen legitimate IP addresses
    are sighted
   */

