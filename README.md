# vmesh

### Introduction

VMesh is a decentralized Layer 3 mesh router and protocol designed for open network interconnection.

It securely handles everything you'll need to interconnect your globally distributed 
nodes or peer with other networks: packet routing, route announcement, authentication,
distributed configuration management, prefix filtering, and more.

VMesh supports only IPv6 in the routed network.

### Getting started

Knowledge of routing protocols such as [BGP](https://en.wikipedia.org/wiki/Border_Gateway_Protocol)
would help a lot in understanding how VMesh works.

Take a look at `config.example.json` and `scripts/` to get an idea about the detailed usage.

Usually you need a globally routable IPv6 block to make full use of VMesh, but you can also
request IPv6 prefix allocation and transit from an existing VMesh network through peering.
(See [Peering](#peering), [Interconnect with AS209291](#as209291))

Detailed documentation is still TBD.

### Peering

Specify `"external_peer_certs": ["/path/to/your/peers/cert.crt"]` in your `config.json` to
allow interconnection with a node with a certificate outside your PKI tree. It's advised to
prefix-filter announcements from external peers - see the "Distributed config" section for
how to do that.

### Distributed config

Use the `vnconfigsign` tool to sign your distributed configuration in JSON format and produce a
`.bin`. Then start any one node with the `-initial-dc your_signed_config.bin` option to sync
the configuration with the rest of your network. As long as any single node on your network
is alive with a latest version of the distributed configuration, all directly/indirectly
connected nodes will eventually be in sync.

The JSON format distributed config should look like:

```json
{
	"prefix_whitelist": {
		"a.vnet.example.com": [
			"2001:db8:1000::/48,max_prefix_len=64",
			"64:ff9b::/96,max_prefix_len=96"
		],
		"b.vnet.example.com": [
			"2001:db8:2000::/48"
		]
	}
}
```

### Interconnect with AS209291

VMesh is deployed on my network (AS209291) and is handling most internal traffic among nodes in
the globally distributed network.

Email me at `me@connected.direct` if you want to peer.