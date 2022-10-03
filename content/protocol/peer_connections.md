# Peer connections

Once a Scuttlebutt client has discovered the IP address, port number and public key of a peer they can connect via TCP to ask for updates and exchange messages.

## Handshake

The connection begins with a 4-step handshake to authenticate each peer and set up an encrypted channel.

![Message 1: Client hello (sent by the client). Message 2: Server hello. Message 3: Client authenticate. Message 4: Server accept](img/message_flow.png)


> ### ![](img/impl16.png) Implementations
> 
> **JS:**
> 
> * [protocol.js](https://github.com/auditdrivencrypto/secret-handshake/blob/master/protocol.js)
> * [crypto.js](https://github.com/auditdrivencrypto/secret-handshake/blob/master/crypto.js)
> 
> **Python:**
> 
> * [crypto.py](https://github.com/pferreir/PySecretHandshake/blob/master/secret_handshake/crypto.py)
> 
> **Go:**
> 
> * [state.go](https://github.com/cryptoscope/secretstream/blob/ad7542b0cbda422a1ea3de7efa62a514672a2c88/secrethandshake/state.go)
> * [conn.go](https://github.com/cryptoscope/secretstream/blob/ad7542b0cbda422a1ea3de7efa62a514672a2c88/secrethandshake/conn.go)
> 
> **C:**
> 
> * [shs1.c](https://github.com/AljoschaMeyer/shs1-c/blob/master/src/shs1.c)
> * [sbotc.c](https://git.scuttlebot.io/%25133ulDgs%2FoC1DXjoK04vDFy6DgVBB%2FZok15YJmuhD5Q%3D.sha256/blob/fd953a1e72b4b16e6e5a74bcf2f893dbf1407ce4/sbotc.c)
> 
> **Java:**
> 
> * [HandshakeClient](https://github.com/apache/incubator-tuweni/blob/master/scuttlebutt-handshake/src/main/java/org/apache/tuweni/scuttlebutt/handshake/SecureScuttlebuttHandshakeClient.java)
> * [HandshakeServer](https://github.com/apache/incubator-tuweni/blob/master/scuttlebutt-handshake/src/main/java/org/apache/tuweni/scuttlebutt/handshake/SecureScuttlebuttHandshakeServer.java)

The handshake uses the [Secret Handshake key exchange](https://dominictarr.github.io/secret-handshake-paper/shs.pdf) which is designed to have these security properties:

*   After a successful handshake the peers have verified each other’s public keys.
*   The handshake produces a shared secret that can be used with a bulk encryption cypher for exchanging further messages.
*   The client must know the server’s public key before connecting. The server learns the client’s public key during the handshake.
*   Once the client has proven their identity the server can decide they don’t want to talk to this client and disconnect without confirming their own identity.
*   A man-in-the-middle cannot learn the public key of either peer.
*   Both peers need to know a key that represents the particular Scuttlebutt network they wish to connect to, however a man-in-the-middle can’t learn this key from the handshake. If the handshake succeeds then both ends have confirmed that they wish to use the same network.
*   Past handshakes cannot be replayed. Attempting to replay a handshake will not allow an attacker to discover or confirm guesses about the participants’ public keys.
*   Handshakes provide forward secrecy. Recording a user’s network traffic and then later stealing their secret key will not allow an attacker to decrypt their past handshakes.

> **Client** is the computer initiating the TCP connection and **server** is the computer receiving it. Once the handshake is complete this distinction goes away.

### Starting keys

Upon starting the handshake, the client and server know these keys:

![Both the client and servers know: their own long term key pair, their own ephemeral key pair, and the network's (private) identifier. Additionally, the client knows the server's long term public key.](img/starting_keys.png)

#### 1. Client hello

![The client sends their own ephemeral public key, hmac-authenticated using the network identifier](img/client_hello.png)

#### Client sends (64 bytes)


	concat(
	  nacl_auth(
		msg: client_ephemeral_pk,
		key: network_identifier
	  ),
	  client_ephemeral_pk
	)

#### Server verifies

	assert(length(msg1) == 64)
	
	client_hmac = first_32_bytes(msg1)
	client_ephemeral_pk = last_32_bytes(msg1)
	
	assert_nacl_auth_verify(
	  authenticator: client_hmac,
	  msg: client_ephemeral_pk,
	  key: network_identifier
	)


First the client sends their ![public](img/key_little_a_public.png) generated ephemeral key. Also included is an hmac that indicates the client wishes to use their key with this specific instance of the Scuttlebutt network.

The ![](img/key_big_n.png) network identifier is a fixed key. On the main Scuttlebutt network it is the following 32-byte sequence:

-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
d4 a1 cb 88 a6 6f 02 f8 db 63 5c e2 64 41 cc 5d 
ac 1b 08 42 0c ea ac 23 08 39 b7 55 84 5a 9f fb
-- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --

Changing the key allows separate networks to be created, for example private networks or testnets. An eavesdropper cannot extract the network identifier directly from what is sent over the wire, although they could confirm a guess that it is the main Scuttlebutt network because that identifier is publicly known.

The server stores the client’s ephemeral public key and uses the hmac to verify that the client is using the same network identifier.

> **hmac** is a function that allows verifying that a message came from someone who knows the same secret key as you. In this case the network identifier is used as the secret key.
> 
> Both the message creator and verifier have to know the same message and secret key for the verification to succeed, but the secret key is not revealed to an eavesdropper.
> 
> Throughout the protocol, all instances of hmac use HMAC-SHA-512-256 (which is the first 256 bits of HMAC-SHA-512).

#### 2. Server hello

![The server sends their own ephemeral public key, hmac-authenticated using the network identifier](img/server_hello.png)

##### Client verifies

##### Server sends (64 bytes)

	assert(length(msg2) == 64)
	
	server_hmac = first_32_bytes(msg2)
	server_ephemeral_pk = last_32_bytes(msg2)
	
	assert_nacl_auth_verify(
	  authenticator: server_hmac,
	  msg: server_ephemeral_pk,
	  key: network_identifier
	)

	concat(
	  nacl_auth(
		msg: server_ephemeral_pk,
		key: network_identifier
	  ),
	  server_ephemeral_pk
	)

The server responds with their own ![public](img/key_little_b_public.png) ephemeral public key and hmac. The client stores the key and verifies that they are also using the same network identifier.

#### Shared secret derivation

![Each derivation uses one public key (their peer's) and one secret key (their own). The resultting shared secrets are identical between server and client.](img/shared_secret_derivation_1.png)

##### Client computes

##### Server computes

	shared_secret_ab = nacl_scalarmult(
	  client_ephemeral_sk,
	  server_ephemeral_pk
	)
	
	shared_secret_aB = nacl_scalarmult(
	  client_ephemeral_sk,
	  pk_to_curve25519(server_longterm_pk)
	)

	shared_secret_ab = nacl_scalarmult(
	  server_ephemeral_sk,
	  client_ephemeral_pk
	)
	
	shared_secret_aB = nacl_scalarmult(
	  sk_to_curve25519(server_longterm_sk),
	  client_ephemeral_pk
	)

Now that ephemeral keys have been exchanged, both ends use them to derive a shared secret ![](img/key_little_a_little_b.png) using scalar multiplication.

The client and server each combine their own ephemeral secret key with the other’s ephemeral public key to produce the same shared secret on both ends. An eavesdropper doesn’t know either secret key so they can’t generate the shared secret. A man-in-the-middle could swap out the ephemeral keys in Messages 1 and 2 for their own keys, so the shared secret ![](img/key_little_a_little_b.png) alone is not enough for the client and server to know that they are talking to each other and not a man-in-the-middle.

Because the client already knows the ![](img/key_big_b_public.png) server’s long term public key, both ends derive a second secret ![using the client's ephemeral key pair (either the public or the secret key) and the server's permanent key pair (respectively either the secret or private key)](img/key_little_a_big_b.png) that will allow the client to send a message that only the real server can read and not a man-in-the-middle.

**Scalar multiplication** is a function for deriving shared secrets from a pair of secret and public Curve25519 keys.

The order of arguments matters. In the NaCl API the secret key is provided first.

Note that long term keys are Ed25519 and must first be converted to Curve25519.

#### 3\. Client authenticate

![The client computes a detached signature of the network identifier, the server's long-term public key, and a hash of the shared secret; signed with its permanent secret key. They add their permanent public key, and encrypt both so that they can only be opened by someone knowing the network identifier and both shared secrets; then send the cyphertext to the server.](img/client_authenticate.png)

##### Client computes

##### Server verifies

	detached_signature_A = nacl_sign_detached(
	  msg: concat(
		network_identifier,
		server_longterm_pk,
		sha256(shared_secret_ab)
	  ),
	  key: client_longterm_sk
	)

	msg3_plaintext = assert_nacl_secretbox_open(
	  ciphertext: msg3,
	  nonce: 24_bytes_of_zeros,
	  key: sha256(
		concat(
		  network_identifier,
		  shared_secret_ab,
		  shared_secret_aB
		)
	  )
	)
	
	assert(length(msg3_plaintext) == 96)
	
	detached_signature_A = first_64_bytes(msg3_plaintext)
	client_longterm_pk = last_32_bytes(msg3_plaintext)
	
	assert_nacl_sign_verify_detached(
	  sig: detached_signature_A,
	  msg: concat(
		network_identifier,
		server_longterm_pk,
		sha256(shared_secret_ab)
	  ),
	  key: client_longterm_pk
	)

##### Client sends (112 bytes)

	nacl_secret_box(
	  msg: concat(
		detached_signature_A,
		client_longterm_pk
	  ),
	  nonce: 24_bytes_of_zeros,
	  key: sha256(
		concat(
		  network_identifier,
		  shared_secret_ab,
		  shared_secret_aB
		)
	  )
	)

The client reveals their identity to the server by sending their ![](img/key_big_a_public.png) long term public key. The client also makes a signature using their ![](img/key_big_a_secret.png) long term secret key. By signing the keys used earlier in the handshake the client proves their identity and confirms that they do indeed wish to be part of this handshake.

The client’s message is enclosed in a secret box to ensure that only the server can read it. Upon receiving it, the server opens the box, stores the client’s long term public key and verifies the signature.

An all-zero nonce is used for the secret box. The secret box construction requires that all secret boxes using a particular key must use different nonces. It’s important to get this detail right because reusing a nonce will allow an attacker to recover the key and encrypt or decrypt any secret boxes using that key. Using a zero nonce is allowed here because this is the only secret box that ever uses the key sha256(concat( ![](img/key_big_n.png), ![](img/key_little_a_little_b.png), ![](img/key_little_a_big_b.png))).

**Detached signatures** do not contain a copy of the message that was signed, only a tag that allows verifying the signature if you already know the message.

Here it is okay because the server knows all the information needed to reconstruct the message that the client signed.

#### Shared secret derivation

![The client computes a new shared secret from their permanent secret key and the server's ephemeral public key. The server computes the same shared secret from the client's permanent public key and their own ephemeral secret key.](img/shared_secret_derivation_2.png)

##### Client computes

##### Server computes

	shared_secret_Ab = nacl_scalarmult(
	  sk_to_curve25519(client_longterm_sk),
	  server_ephemeral_pk
	)

	shared_secret_Ab = nacl_scalarmult(
	  server_ephemeral_sk,
	  pk_to_curve25519(client_longterm_pk)
	)

Now that the server knows the ![](img/key_big_a_public.png) client’s long term public key, another shared secret ![](img/key_big_a_little_b.png) is derived by both ends. The server uses this shared secret to send a message that only the real client can read and not a man-in-the-middle.

#### 4\. Server accept

![The server signs the network identifier, the previous detached signature, the client's permanent secret key, and the hash of the first shared secret, with their permanent secret key, as a new detached signature. They encrypt it so that they can only be opened by someone knowing the network identifier and all three shared secrets; then send the cyphertext to the client.](img/server_accept.png)

##### Client verifies

##### Server computes

	detached_signature_B = assert_nacl_secretbox_open(
	  ciphertext: msg4,
	  nonce: 24_bytes_of_zeros,
	  key: sha256(
		concat(
		  network_identifier,
		  shared_secret_ab,
		  shared_secret_aB,
		  shared_secret_Ab
		)
	  )
	)
	
	assert_nacl_sign_verify_detached(
	  sig: detached_signature_B,
	  msg: concat(
		network_identifier,
		detached_signature_A,
		client_longterm_pk,
		sha256(shared_secret_ab)
	  ),
	  key: server_longterm_pk
	)

	detached_signature_B = nacl_sign_detached(
	  msg: concat(
		network_identifier,
		detached_signature_A,
		client_longterm_pk,
		sha256(shared_secret_ab)
	  ),
	  key: server_longterm_sk
	)

##### Server sends (80 bytes)

	nacl_secret_box(
	  msg: detached_signature_B,
	  nonce: 24_bytes_of_zeros,
	  key: sha256(
		concat(
		  network_identifier,
		  shared_secret_ab,
		  shared_secret_aB,
		  shared_secret_Ab
		)
	  )
	)

The server accepts the handshake by signing a message using their ![](img/key_big_b_secret.png) long term secret key. It includes a copy of the client’s previous signature. The server’s signature is enclosed in a secret box using all of the shared secrets.

Upon receiving it, the client opens the box and verifies the server’s signature.

Similarly to the previous message, this secret box also uses an all-zero nonce because it is the only secret box that ever uses the key sha256(concat( ![](img/key_big_n.png), ![](img/key_little_a_little_b.png), ![](img/key_little_a_big_b.png), ![](img/key_big_a_little_b.png))).

#### Handshake complete

![](img/final_shared_secret.png)

At this point the handshake has succeeded. The client and server have proven their identities to each other.

The shared secrets established during the handshake are used to set up a pair of box streams for securely exchanging further messages.

### Box stream

Box stream is the bulk encryption protocol used to exchange messages following the handshake until the connection ends. It is designed to protect messages from being read or modified by a man-in-the-middle.

Each message in a box stream has a header and body. The header is always 34 bytes long and says how long the body will be.

![A stream is made of alternating headers (34 bytes) and bodies (1 to 4096 bytes); ending with a body followed by a 34-bytes 'goodbye' header](img/box_stream_overview.png)

#### Sending

Sending a message involves encrypting the body of the message and preparing a header for it. Two secret boxes are used; one to protect the header and another to protect the body.

![](img/impl.png)

##### Implementations

JS

[pull-box-stream](https://github.com/dominictarr/pull-box-stream/blob/master/index.js)

Py

[boxstream.py](https://github.com/pferreir/PySecretHandshake/blob/master/secret_handshake/boxstream.py)

Go

[box.go](https://github.com/cryptoscope/secretstream/blob/ad7542b0cbda422a1ea3de7efa62a514672a2c88/boxstream/box.go)

[unbox.go](https://github.com/cryptoscope/secretstream/blob/ad7542b0cbda422a1ea3de7efa62a514672a2c88/boxstream/unbox.go)

C

[box-stream.c](https://github.com/AljoschaMeyer/box-stream-c/blob/master/src/box-stream.c)

[sbotc.c](https://git.scuttlebot.io/%25133ulDgs%2FoC1DXjoK04vDFy6DgVBB%2FZok15YJmuhD5Q%3D.sha256/blob/fd953a1e72b4b16e6e5a74bcf2f893dbf1407ce4/sbotc.c)

Java

[Stream](https://github.com/apache/incubator-tuweni/blob/master/scuttlebutt-handshake/src/main/java/org/apache/tuweni/scuttlebutt/handshake/SecureScuttlebuttStream.java)

![The plaintext message body is enclosed in a secret box using the key and nonce shown below. Secret boxes put a 16-byte tag onto the front of messages so that tampering can be detected when the box is opened. This tag is sliced off the body and put inside the header. A temporary header is made of the body length (a two-bytes big-endian integer) and th previous tag. This temporary header is then encrypted too, including its own (16-bytes) authentication tag, producing a 16+2+16 bytes header.](img/box_stream_send.png)

#### Receiving

Receiving a message involves reading the header to find out how long the body is then reassembling and opening the body secret box.

![Read the first 34 bytes. This is the secret box containing the header. Open this box, extract the body length and body authentication tag. Read the number of bytes specified in the header. Join the body authentication tag and encrypted body back together, open it, and read the secret text.](img/box_stream_receive.png)

#### Goodbye

The stream ends with a special “goodbye” header. Because the goodbye header is authenticated it allows a receiver to tell the difference between the connection genuinely being finished and a man-in-the-middle forcibly resetting the underlying TCP connection.

![The 'goodbye' header is made of 18 bytes of zero, encrypted in a secret box (with a header authenticated tag like other headers).](img/box_stream_goodbye.png)

When a receiver opens a header and finds that it contains all zeros then they will know that the connection is finished.

#### Keys and nonces

Two box streams are used at the same time when Scuttlebutt peers communicate. One is for client-to-server messages and the other is for server-to-client messages. The two streams use different keys and starting nonces for their secret boxes.

![The secret box key is made of a double-sha256 hash of the network identifier and three shared secrets, followed by either the server's permanent public key (for Client to Server) or the client's permanent public key (for Server to Client), both hashed again with sha256. The starting nonces are respectively the first 24 bytes of server's or the client's ephemeral public key, hmac-authenticated with the network identifier.](img/box_stream_params.png)

The starting nonce is used for the first header in the stream (“secret box 1” in the above figures), then incremented for the first body (“secret box 2”), then incremented for the next header and so on.

### RPC protocol

![](img/impl.png)

##### Implementations

JS

[packet-stream-codec](https://github.com/ssbc/packet-stream-codec/blob/master/index.js)

Py

[packet\_stream.py](https://github.com/pferreir/pyssb/blob/master/ssb/packet_stream.py)

[muxrpc.py](https://github.com/pferreir/pyssb/blob/master/ssb/muxrpc.py)

Go

[codec](https://github.com/cryptoscope/go-muxrpc/tree/601b7be81ee6b2bd6f32b1247e4688537f696794/codec)

[rpc.go](https://github.com/cryptoscope/go-muxrpc/blob/601b7be81ee6b2bd6f32b1247e4688537f696794/rpc.go)

C

[sbotc.c](https://git.scuttlebot.io/%25133ulDgs%2FoC1DXjoK04vDFy6DgVBB%2FZok15YJmuhD5Q%3D.sha256/blob/fd953a1e72b4b16e6e5a74bcf2f893dbf1407ce4/sbotc.c)

Java

[RPCCodec](https://github.com/apache/incubator-tuweni/blob/master/scuttlebutt-rpc/src/main/java/org/apache/tuweni/scuttlebutt/rpc/RPCCodec.java)

Scuttlebutt peers make requests to each other using an RPC protocol. Typical requests include asking for the latest messages in a particular feed or requesting a blob.

The RPC protocol can interleave multiple requests so that a slow request doesn’t block following ones. It also handles long-running asynchronous requests for notifying when an event occurs and streams that deliver multiple responses over time.

Similar to the box stream protocol, the RPC protocol consists of 9-bytes headers followed by variable-length bodies. There is also a 9-bytes goodbye message which is just a zeroed out header.

![](img/rpc_overview.png)

**Remote procedure calls** are where a computer exposes a set of procedures that another computer can call over the network.

The requester tells the responder the name of the procedure they wish to call along with any arguments. The responder performs the action and returns a value back to the requester.

Both peers make requests to each other at the same time using the pair of box streams that have been established. The box streams protect the RPC protocol from eavesdropping and tampering.

![](img/rpc_alignment.png)

RPC messages are not necessarily aligned to box stream boxes.

Multiple RPC messages may be put inside one box or a single RPC message may be split over several boxes.

#### Header structure

RPC headers contain a set of flags to say what type of message it is, a field specifying its length and a request number which allows matching requests with their responses when there are several active at the same time.

![Headers are made of (in network order): 4 zero bits, a stream bit (1 = 'message is part of a stream'), a end/error bit (1 = 'message is the last in its stream or an error), and a 2-bits body type (00 = binary, 01 = UTF-8 string, 10 = JSON), the body length (4 bytes unsigned big-endian), and the request number (4 bytes signed big-endial).](img/rpc_header.png)

#### Request format

To make an RPC request, send a JSON message containing the name of the procedure you wish to call, the type of procedure and any arguments.

The name is a list of strings. For a top-level procedure like _createHistoryStream_ the list only has one element: `["createHistoryStream"]`. Procedures relating to blobs are grouped in the blobs namespace, for example to use _blobs.get_ send the list: `["blobs", "get"]`.

There are three types of procedure used when Scuttlebutt peers talk to each other:

*   _Source_ procedures return multiple responses over time and are used for streaming data or continually notifying when new events occur. When making one of these requests, the stream flag in the RPC header must be set.
*   _Duplex_ procedures are similar to _source_ procedures but allow _multiple requests_ as well as multiple responses over time. The many request events in a duplex utilize the same request number, and the stream flag must be set.
*   _Async_ procedures return a single response. Async responses can arrive quickly or arrive much later in response to a one-off event.

For each procedure in the RPC protocol you must already know whether it is source or async and correctly specify this in the request body.

The reference Scuttlebot implementation also has other internal procedures and procedure types which are used by graphical user interfaces like Patchwork.

This guide only covers the procedures that are publicly available to other Scuttlebutt peers.

#### Source example

This RPC message shows an example of a _createHistoryStream_ request:

JSON messages don’t have indentation or whitespace when sent over the wire.

Request number1 Body typeJSON StreamYes End/errNo

	{
	  "name": ["createHistoryStream"],
	  "type": "source",
	  "args": [{"id": "@FCX/tsDLpubCPKKfIrw4gc+SQkHcaD17s7GI6i/ziWY=.ed25519"}]
	}

![](img/arrow.png)

_createHistoryStream_ is how Scuttlebutt peers ask each other for a list of messages posted by a particular feed. It has one argument that is a JSON dictionary specifying more options about the request. _id_ is the only required option and says which feed you are interested in.

Because this is the first RPC request, the request number is 1. The next request made by this peer will be numbered 2. The other peer will also use request number 1 for their first request, but the peers can tell these apart because they know whether they sent or received each request.

Now the responder begins streaming back responses:

![](img/arrow.png)

Request number\-1 Body typeJSON StreamYes End/errNo

	{
	  "key": "%XphMUkWQtomKjXQvFGfsGYpt69sgEY7Y4Vou9cEuJho=.sha256",
	  "value": {
		"previous": null,
		"author": "@FCX/tsDLpubCPKKfIrw4gc+SQkHcaD17s7GI6i/ziWY=.ed25519",
		"sequence": 1,
		"timestamp": 1514517067954,
		"hash": "sha256",
		"content": {
		  "type": "post",
		  "text": "This is the first post!"
		},
		"signature": "QYOR/zU9dxE1aKBaxc3C0DJ4gRyZtlMfPLt+CGJcY73sv5abKK
					  Kxr1SqhOvnm8TY784VHE8kZHCD8RdzFl1tBA==.sig.ed25519"
	  },
	  "timestamp": 1514517067956
	}

![](img/arrow.png)

Request number\-1 Body typeJSON StreamYes End/errNo

	{
	  "key": "%R7lJEkz27lNijPhYNDzYoPjM0Fp+bFWzwX0SmNJB/ZE=.sha256",
	  "value": {
		"previous": "%XphMUkWQtomKjXQvFGfsGYpt69sgEY7Y4Vou9cEuJho=.sha256",
		"author": "@FCX/tsDLpubCPKKfIrw4gc+SQkHcaD17s7GI6i/ziWY=.ed25519",
		"sequence": 2,
		"timestamp": 1514517078157,
		"hash": "sha256",
		"content": {
		  "type": "post",
		  "text": "Second post!"
		},
		"signature": "z7W1ERg9UYZjNfE72ZwEuJF79khG+eOHWFp6iF+KLuSrw8Lqa6
					  IousK4cCn9T5qFa8E14GVek4cAMmMbjqDnAg==.sig.ed25519"
	  },
	  "timestamp": 1514517078160
	}

Because the responses are part of a stream, their RPC headers have the stream flag set.

All responses use the same request number as the original request but negative.

Each message posted by the feed is sent back in its own response. This feed only contains two messages.

To close the stream the responder sends an RPC message with both the stream and end/err flags set and a JSON body of `true`. When the requester sees that the stream is being closed they send a final message to close their own end of it (source type requests must always be closed by both ends).

![](img/arrow.png)

Request number\-1 Body typeJSON StreamYes End/errYes

	true

Request number1 Body typeJSON StreamYes End/errYes

	true

![](img/arrow.png)

Alternatively, to abort a stream before it is finished the requester can send their closing message early, at which point the responder closes their own end.

Request number1 Body typeJSON StreamYes End/errYes

	true

![](img/arrow.png) ![](img/arrow.png)

Request number\-1 Body typeJSON StreamYes End/errYes

	true

#### Async example

One of the few public async procedures is _blobs.has_, which peers use to ask each other whether they have a particular blob.

In this example the requester is asking the responder if they have blob `&WWw4tQJ6…`:

Request number2 Body typeJSON StreamNo End/errNo

	{
	  "name": ["blobs", "has"],
	  "type": "async",
	  "args": ["&WWw4tQJ6ZrM7o3gA8lOEAcO4zmyqXqb/3bmIKTLQepo=.sha256"]
	}

![](img/arrow.png)

The responder does in fact have this blob so they respond with `true`. Because this is an async procedure and not a stream, there is only one response and no need to close the stream afterwards:

![](img/arrow.png)

Request number\-2 Body typeJSON StreamNo End/errNo

	true

#### Error example

Let’s take the previous example and introduce a programming mistake to see how the RPC protocol handles errors:

Request number3 Body typeJSON StreamNo End/errNo

	{
	  "name": ["blobs", "has"],
	  "type": "async",
	  "args": ["this was a mistake"]
	}

![](img/arrow.png) ![](img/arrow.png)

Request number\-3 Body typeJSON StreamNo End/errYes

	{
	  "name": "Error",
	  "message": "invalid hash:this was a mistake",
	  "stack": "…"
	}

Most importantly, the response has the end/err flag set to indicate that an error occurred. The reference Scuttlebot implementation also includes an error message and a JavaScript stack trace.

For source type procedures an error will also end the stream because the end/err flag has the dual purpose of ending streams and indicating that an error occurred.