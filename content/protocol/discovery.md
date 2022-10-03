# Discovery

After a user has generated their identity they need to find some peers to connect to. To connect to a peer you need its public key and its address using any of the protocol it supports. Typically with TCP/IP, you would need its IP address and port, but the Scuttlebutt protocol is not restricted to TCP/IP as transport. The Scuttlebutt protocol currently has three methods for peers to discover each other.

## Local network

Peers constantly broadcast UDP packets on their local network advertising their presence. The body of each packet is a string containing the peer’s IP address, port and base64-encoded public key (without `@` or `.ed25519`):

> ### ![](img/impl16.png) Implementations
>
> **JS:**
>
> * [broadcast-stream](https://github.com/dominictarr/broadcast-stream/blob/master/index.js)
> * [ssb-local](https://github.com/ssbc/ssb-local/blob/master/index.js)
>
> **Java:**
>
> * [LocalDiscoveryService](https://github.com/apache/incubator-tuweni/blob/master/scuttlebutt-discovery/src/main/java/org/apache/tuweni/scuttlebutt/discovery/ScuttlebuttLocalDiscoveryService.java)


| Source IP | Source port | Destination IP | Destination port |
|----|----|----|---- |
|  192.168.1.123 | 8008 | 255.255.255.255 | 8008 |
 
 ![net:192.168.1.123:8008:~shs:FCX/tsDLpubCPKKfIrw4gc+SQkHcaD17s7GI6i/ziWY=](img/format_udp_broadcast.png)

This message format can be any valid [multiserver address](https://github.com/ssb-js/multiserver#address-format). In local networks, this is usually a `net` address with an IPv4 or IPv6 address.

Current implementations broadcast one of these packets every second. When a peer sees another peer’s broadcast packet they can connect to exchange messages. Some clients show nearby peers in the user interface so that the user can see other people on the same network as them.

UDP source and destination ports are set to the same port number that the peer is listening on TCP for peer connections (normally 8008).

## Invite code

[Invite codes](#invites) help new users get connected to their first [pub](#pubs), which is a Scuttlebutt peer that is publicly accessible over the internet. An invite code contains a pub’s domain name, port and public key.

They also contain a secret key that the user can [redeem](#redeeming-invites) to make the pub [follow](#following) them back. This lets the new user see messages posted by other members of the pub and share their own messages. Invite codes are the most common way for new users to get started on Scuttlebutt.

Pub operators can distribute invite codes any way they see fit, for example by posting them on existing social networks. Some pubs have a web page that anybody can visit to generate an invite code.

## Pub message

Users can post a message to their own [feed](#feeds) advertising a pub:

Here the user `@FCX/ts…` is advertising that they know of pub `@VJM7w1…` along with the pub’s domain name and port.

	{
	  "author": "@FCX/tsDLpubCPKKfIrw4gc+SQkHcaD17s7GI6i/ziWY=.ed25519",
	  "content": {
		"type": "pub",
		"address": {
		  "host": "one.butt.nz",
		  "port": 8008,
		  "key": "@VJM7w1W19ZsKmG2KnfaoKIM66BRoreEkzaVm/J//wl8=.ed25519"
		}
	  },
	  …
	}

When others see this message they can make a note that this pub exists and connect to it in the future.

Pub messages are a useful way to find additional peers if you already know a few. Obviously this doesn’t work for new users who don’t know anyone else yet and therefore can’t see any pub messages.