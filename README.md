Communication Protocols Course \
HOMEWORK 1 - Router forwarding 

April, 2021

Bianca Necula \
Faculty of Automatic Control and Computer Science \
325CA 

# Info
```bash
git clone https://github.com/BiancaNecula/Router-forwarding.git
```

# About the code:

For this homework I have implemented the functionalities required for a topology with two routers.
 * Receiving a package, identifying it and sending a response.
 * For received IP packets, we answer if it is ICMP echo request or if its TTL < 1 or if the checksum is wrong.
 * I implemented ARP request and reply:
   - if it is an ARP request, we send an ARP reply with the requested address
   - if it is ARP reply, we put the received address in the ARP table and send the packets in the queue
 * We save the packet in the queue in case we don't know the Mac address and send an ARP request to receive it.
 * For the sent packets it is searched in the routing table sorted by the prefix next hop according to them with the help of the binary search.
 * Initially I used the Hashtable routing table, but it wasn't a good idea.
 * For both tables within the homework we used structure arrays.

The functionalities of the router, executed in an infinite loop, are:
1. Receive a packet from any of the adjacent interfaces.
2. If it is an IP packet intended for the router, answer only if it is a
ICMP ECHO request package. Discard the original package.
3. If it is an ARP Request packet to a router's IP, respond with ARP Reply with
the appropriate MAC address.
4. If it is an ARP Reply package, update the ARP table; if there are the right packages
routed to that router, forward them now.
5. If it is a packet with TTL <= 1 send a correct ICMP message to the source (see below);
throw away the package.
6. If it is a package with the wrong checksum, discard the package.
7. Decrement TTL, update checksum.
8. Find the most specific entry in the routing table (called f) so that (iph ->
daddr & f.mask == f.prefix). Once identified, it specifies the next hop for the package.
If no route is found, an ICMP message is sent to the source; THROW
the package
9. Change the source and destination MAC addresses. If the MAC address is not known locally,
generates an ARP request and transmits on the destination interface. Save the package in the queue
for transmission. when the MAC address is known (step 4).
10. Forward the packet using the send_packet (...) function.

Protocols used:
* Ethernet (struct ether_header)
* IP (struct iphdr)
* ARP (struct ether_arp) - request and response
* ICMP (struct icmphdr) - Echo reply, Destination unreachable, Time exceeded

