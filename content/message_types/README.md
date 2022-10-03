---
title: Message Types
...


# Message Types

A [Scuttlebutt feed](https://ssbc.github.io/scuttlebutt-protocol-guide/#feeds) is a list of all the messages posted by a particular identity. When a user writes a message in a Scuttlebutt client and posts it, that message is put onto the end of their feed.

Each [message](https://ssbc.github.io/scuttlebutt-protocol-guide/#message-format) has its own _type_ which identifies what kind of message it is. There are messages related to your social graph, private messages, chess playing messages, etc. People can define their own message types provided they follow [the message format mentioned above](https://ssbc.github.io/scuttlebutt-protocol-guide/#message-format).

## Custom Types

Message schemas are interpretted according to the `type` property, as demonstrated in the other pages of this section.

There is no restriction on which types applications use. A type simply must be a string between 3 and 52 characters long. You are free to create new types, with their own schemas, as you need them.

Likewise, there is no restriction on message schemas, so long as the content is an object, and the total message size (including headers) is less than 8kb.

## Interoperation

Applications should interpret messages "defensively." There's nothing enforcing a schema, so (as with any input) applications must be prepared for malformed content objects in messages.

Applications should endeavor to interpret messages the same way. Otherwise, they won't be able to interoperate, and may introduce unexpected behaviors.

There is no official mechanism for making sure message-types interoperate, except for the documentation which you're reading here. As it becomes clear that new types are coming into common use, we'll add them to this site.


* [about](/message_types/about)
* [blog](/message_types/blog)
* [bookclub](/message_types/bookclub)
* [bookclubUpdate](/message_types/bookclubUpdate)
* [channel](/message_types/channel)
* [contact](/message_types/contact)
* [gathering](/message_types/gathering)
* [more-info](/message_types/more-info)
* [post](/message_types/post)
* [private](/message_types/private)
* [pub](/message_types/pub)
* [vote](/message_types/vote)
