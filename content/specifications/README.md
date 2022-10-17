---
title: SSB Specifications
...

# Relationship between specs {#index}

```{.mermaid format=svg loc=content/specifications/img}
flowchart BT

subgraph feedFormat [feed format]
  classic
  bendybutt
  buttwoo
end
click bendybutt "https://github.com/ssbc/bendy-butt-spec" " "
click classic "https://ssbc.github.io/scuttlebutt-protocol-guide/#message-format" " "
click buttwoo "https://github.com/ssbc/ssb-buttwoo-spec" " "

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



click uri "https://github.com/ssbc/ssb-uri-spec" " "


click bfe "https://github.com/ssbc/ssb-bfe-spec" " "
click envelope "https://github.com/ssbc/envelope-spec" " "
click private-group "https://github.com/ssbc/private-group-spec" " "


click meta-feeds "https://github.com/ssbc/ssb-meta-feeds-spec" " "
click meta-feed-groups "https://github.com/ssbc/ssb-meta-feed-group-spec"

classDef node color:#fff, stroke:none, fill:#2F2440;
classDef cluster color:#555, stroke:#BFD7ED, fill:#ffffff00;
classDef noSpec color:#fff, fill:#BA0F30;
classDef sunset color:#555, fill:#C6B79B;
```
