---
title: Contact messages
...

# `contact` message

Contact messages are used to follow or unfollow another user. This affects your [social graph](/concepts/social_graph) and [gossiping](/concepts/gossip). Once you follow a given user, you'll start replicating all of that user's feed and, depending on how your client is configured, your followers' friends. Most clients will do two levels of replication, so you end up with all your friends' data and friends-of-friends' data, much like the physical world in which you'll often hear gossip regarding your friends' friends.

## What does it look like?

```{.json}
{
  "key": "%JJW6l3PphHHNxkbe6q+gzsgsgOIgIEjqtnKVq5fo=.sha256",
  "value": {
    "previous": "%4UrrxMHmjgkw/tDZ40ztxwwrg2TQSzPVMw9efqj9E=.sha256",
    "sequence": 1182,
    "author": "@GLH9VPzvvU2KcnnUwgwgTUtzw+Rk6fd/Kb9Si0=.ed25519",
    "timestamp": 1560279915710,
    "hash": "sha256",
    "content": {
      "type": "contact",
      "contact": "@S954DSMnCh8aBqwegwegVZSBtK9N49Wq5AHh3OwOjo=.ed25519",
      "following": true
    },
    "signature": "laHTnqQkbem2rFxvfwegwegwI4B7l2BE8n60sWsW8UZ/H6B1xz1yhlFGJ/2NkIBGsxpIW7GJM4i8uTCDg==.sig.ed25519"
  },
  "timestamp": 1560279930388,
  "rts": 1560279915710
}
```

In the message above, the author is _following_ (specified by the `following` field) a user specified by the `contact` field. If the value of the `following` field was false, that would be an unfollow message.