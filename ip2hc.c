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
  //todo
  /*1. collect traces of its clients to obtain both IP ad-dresses and the corresponding hop-count values
    2.After the initial population of the mapping table and activation,
    HCF will continue adding new entries to the mapping table
    when requests with previously unseen legitimate IP addresses
    are sighted
   */

