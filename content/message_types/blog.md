---
title: Blog messages
...

# `blog` messages

Sometimes messages of type `post` are not enough for you to express what you need. Posts in Secure Scuttlebutt have a maximum size of 8k which is counting the metadata associated with the message and not just the content itself. For occasions when you need to write longer messages, you can use `blog`.

These messages are actually a small set of metadata, just enough so that clients can display a summary and an associated [blob (this link explains them in depth)](/protocol/blobs) which holds the content. 

> **About blobs:** You can think of blobs like attachments to an email. Blobs are not downloaded automatically, they need to be requested. Most clients will request images on their own so that you can see posts and images together, but they will not request other blobs unless the user initiates some action that needs them. In cases such as `blog` messages, the blobs are requested when the user initiates the action to read the post.

## What do blog posts look like?

```{.json}
{
  "key": "%x4+H95OSsvVgsPl6sggsfgsD0KPM8Y3eHQ9lj2oKNb4=.sha256",
  "value": {
    "previous": "%CwJcRGnZsdgsdg59NyL9gBokQzOzAoJJFjBE=.sha256",
    "sequence": 176,
    "author": "@aSo64imXSBLArsdgsdgidEUsvp2Lziiu3youY=.ed25519",
    "timestamp": 1560521419974,
    "hash": "sha256",
    "content": {
      "type": "blog",
      "title": "Fridays for Future treffen Science Fiction: Was ist eigentlich Solarpunk?",
      "summary": "Die Welt der Science Fiction ist bunt und vielfältig. Das zeigen Untergenres wie Cyberpunk und Steampunk – die mittlerweile weithin bekannt sind. Solarpunk ist hingegen nur wenigen ein Begriff. Dabei passt dieses Genre so gut in unsere Zeit wie kein anderes. Denn Solarpunk zeichnet eine Welt, in der wir unseren Planeten noch retten können.",
      "thumbnail": "&EmYpby5uFsdgsdg81wwggzPT52zZLNpQSoZu8=.sha256",
      "blog": "&DcG4eJNU65yuVMjwNIsdgsdgsdZfmTIfXQrTxOQ=.sha256",
      "mentions": [
        {
          "link": "&pU8sdgsdgsSIs3z5kw25OPoqmDbwLoNPIJE6XI=.sha256",
          "type": "image/jpeg",
          "size": 195993
        }
      ],
      "channel": "solarpunk"
    },
    "signature": "51SNzLdPRDMWNVTdBjU0TplV9gbmyehpcWKsCz9DsWlz0gFynzybXMJozMUC5GieNPUAaMnob9YFe4sH6nMjAA==.sig.ed25519"
  }
}
```

On the message above you can see some metadata to helps the application display a summary of the blog post to the user using the fields `summary`, `title`, `thumbnail`. The content for the blogpost is a blob in field `blog`. Blobs start with an `%`. Clients will fetch that blob and display it if once the user ask to read the post. The content of the blob should be a markdown text file.
