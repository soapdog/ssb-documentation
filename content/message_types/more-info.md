---
title: More Info messages
...

# `more-info` message

Messages of type `more-info` are **PRIVATE** messages sent from one feed to itself. They attach additional metadata to a user. They are used to provide _address book_ features to SSB. Only the issuer of a `more-info` message can read them, so the data attached to a profile is private.

## What they look like

```{.json}
{
  "key": "%buRChnotexistk/WjZQsfsgsg17XHmSDnMMKfFEXv/bjL43lQ=.sha256",
  "value": {
    "previous": null,
    "sequence": 1,
    "author": "@G/zUdqlPsdgsgd8yXIfMjx1676ApAOghwgc=.ed25519",
    "timestamp": 1560287825423,
    "hash": "sha256",
    "content": {
      "type": "more-info",
      "about": "@G/zUdqlPMsdgsdg8yXIfMjx1676ApAOghwgc=.ed25519",
      "luckyNumbers": ["1","2","3"],
      "fields": [
      	{"name": "primary email", "type": "email", "value": "example@example.com"},
      	{"name": "blog", "type": "URL", "value": "https://example.com"}
      ]
    },
    "signature": "UMjf4aFsdgsgUY9zeDAqWdTZeymoQznicvfgATu0/aaaa==.sig.ed25519"
  },
  "timestamp": 1560288248693,
  "rts": 1560287825423
}

```

* `about`: This field should contain a _feed id_.
* `luckyNumbers`: An array of numbers that is used to beef-up the cryptographic safety of the message. They provide some randomness to the data so that bad actors who know part of the other fields can't brute force and discover the keys more easily.
* `fields`: An array of objects containing extra data about the user specified in the `about` field. 
  * Each object in this array has a `label` that is displayed in the application UI, a `type` which dictates what kind of data it is holding, and a `value` which holds the data.

The `more-info` message contains all the _more information_ about a given user. Applications when editing or updating that information send a complete final snapshot of all `fields`. An application should only read the last `more-info` message about a user and ignore any previous one (they should be treated as older versions). There is no reducing or tangles requiring a merge to make sense of the information.