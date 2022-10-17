---
title: SSB Specifications

dynamic: true
...

# Relationship between specs {#index}

```{.mermaid format=svg loc=content/specifications/img}
flowchart BT

subgraph feedFormat [feed format]
  classic
  bendybutt
  buttwoo
end
click bendybutt "/specifications/bendy-butt-spec" " "
click classic "https://ssbc.github.io/scuttlebutt-protocol-guide/#message-format" " "
click buttwoo "/specifications/ssb-buttwoo-spec" " "

subgraph connection
  direction BT
  shs[secret handshake] --> box-stream --> muxrpc
end
click shs "https://ssbc.github.io/scuttlebutt-protocol-guide/#handshake" " "
click box-stream "https://ssbc.github.io/scuttlebutt-protocol-guide/#box-stream" " "
click muxrpc "https://ssbc.github.io/scuttlebutt-protocol-guide/#rpc-protocol" " "


subgraph replication
  direction BT
  createHistoryStream:::sunset
  EBT[epidemic broadcast trees]:::noSpec
end
click createHistoryStream "https://ssbc.github.io/scuttlebutt-protocol-guide/#createHistoryStream" " "


muxrpc --> createHistoryStream & EBT


bendybutt --> meta-feeds
envelope --> private-group

meta-feeds & private-group --> meta-feed-groups

bfe -.-> envelope
uri -.-> bendybutt & buttwoo



click uri "/specifications/ssb-uri-spec" " "


click bfe "/specifications/ssb-bfe-spec" " "
click envelope "/specifications/envelope-spec" " "
click private-group "/specifications/private-group-spec" " "


click meta-feeds "/specifications/ssb-meta-feeds-spec" " "
click meta-feed-groups "/specifications/ssb-meta-feed-group-spec"

classDef node color:#fff, stroke:none, fill:#2F2440;
classDef cluster color:#555, stroke:#BFD7ED, fill:#ffffff00;
classDef noSpec color:#fff, fill:#BA0F30;
classDef sunset color:#555, fill:#C6B79B;
```

