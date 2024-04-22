*Copyright Fintina Stefania 324CA*


# Router - PCOM Project

`Overview`

The project implements the Dataplane component of a `router`'s software stack. The control plane (`routing tables`) is pre-populated, allowing the focus to be on forwarding packets based on Layer 2 (`Datalink`) and Layer 3 (`Network`) protocols.


* `Packet Reception`: Packets are received through the `recv_from_any_link()` API, identifying the incoming interface.
* `Packet Handling`:
    * `IP Packets` (ETHERTYPE_IP):
If destined for the router, respond to `ICMP Echo Requests`.
Verify `checksum` and `TTL`; send ICMP Time Exceeded if TTL expires.
For other packets, `decrement` TTL, `recompute` checksum, and use the routing table to `forward` the packet.
    * `ARP Packets` (ETHERTYPE_ARP):
Respond to ARP Requests with the router's MAC address.
Update ARP table on ARP Replies and forward queued packets.

`Binary Search`: Used for `efficient` querying of the `routing` table to find the `best` route.

`Queue`: Holds packets `waiting` for `MAC->IP resolution`.


`Code Structure`

The program `initializes` network interfaces and ARP tables, then continuously `receives` and `processes` packets. Routing decisions are based on the `longest prefix match` found in the binary search.

`Functions`

* `get_arp_entry()`: Returns the ARP entry for a given IP address.
compare_rtable_entr(): Compares routing table entries for sorting.
* `reply_icmp()`: Handles creation and sending of ICMP replies.
* `tle_unrch_reply_icmp()`: Sends ICMP Time Exceeded or Destination Unreachable messages.
* `get_best_route()`: Retrieves the best route for a given destination IP.
* `arp_request()`: Sends an ARP request for an unresolved IP address.
* `arp_reply()`: Responds to ARP requests with the router’s MAC address.

The `main loop` waits for packets, processes each according to its `type` (IP or ARP), and `forwards` it based on the routing and ARP `table entries`. `Unresolved` ARP entries lead to `packets being queued` until a reply is received.

*`Source and documentation`: My program basis was `Lab04`.* 

* Also I need to specify that I used `2 sleep days`.