# lockkit

lockkit is the shared foundation of [locksql](https://github.com/DavidGodefroid/locksql)
and its sibling products: the console that holds the credentials and asks
the human, its isolated account and socket, the policy files that the AI
may tighten and only the human loosens, the approval screen, the audit log,
credential sources (ask, OS keychain, Vault), personal-data detectors and
masks, and the MCP and agent wiring. A product plugs its own operations into
the console through a `Backend`. There is no stability promise before v1:
products pin an exact version.

Start with [GUIDE.md](GUIDE.md).
