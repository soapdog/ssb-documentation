---
title: Book Club messages
...

# `bookclub` message

Book club messages are used to create new books.

A book club message looks like:

```{.json}
{
  "type": "bookclub",
  "title": "A Prehistory of the Cloud",
  "authors": "Tung Hui-Hu",
  "description": "A radical collage of internet history.  Traces the origins of \"the cloud\" as an idea and as a force in the world today.  Tung Hui-Hu is a network engineer and English professor, and so the history draws equally from computing and railroads and victorian sewers and 1970's countercultural performance artists.  A powerful, pleasantly short read!",
  "image": {
    "link": "&Qf54gh2QQGhYjC+L1/asC9qEpYeBN76LCwauZmjgioM=.sha256",
    "name": "prehistory-of-the-cloud.jpg",
    "size": 26228,
    "type": "image/jpeg"
  }
}

```

Book club features were built to provide SSB users a convenient way to organise and review books. In this way, it provides the groundwork for experiences similar to book review services such as _Goodreads_ and _BookWyrm_.

You can read more about book club schemas in the [scuttle-book documentation](https://github.com/ssbc/ssb-book-schema/).
