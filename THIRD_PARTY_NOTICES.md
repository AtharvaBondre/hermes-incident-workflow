# Third-party notices

This repository contains original workflow, fixture, and controller code. It does not vendor Hermes Agent or any of its bundled skills, plugins, assets, Node modules, or Python environment.

The optional local integration example pulls these separately distributed components:

| Component | Use | License |
|---|---|---|
| [Hermes Agent](https://github.com/NousResearch/hermes-agent) v0.19.1 | External CLI and profile runtime | MIT, copyright Nous Research |
| [Python](https://www.python.org/) 3.12 container images | Sandbox and verifier runtime | Python Software Foundation License |
| [PostgreSQL](https://www.postgresql.org/) 14.24 | Disposable relational state | PostgreSQL License |
| [Apache Kafka](https://kafka.apache.org/) 4.3.1 | Disposable event transport | Apache-2.0 |
| [OpenSearch](https://opensearch.org/) 3.8.0 | Disposable search state | Apache-2.0 |
| [Psycopg](https://www.psycopg.org/) 3.2.9 | PostgreSQL client in the verifier image | LGPL-3.0-only |
| [kafka-python](https://github.com/dpkp/kafka-python) 2.3.2 | Kafka client in the verifier image | Apache-2.0 |
| [typing-extensions](https://github.com/python/typing_extensions) 4.16.0 | Psycopg compatibility dependency in the verifier image | PSF-2.0 |

The repository references versioned container images; it does not distribute those images. Anyone redistributing a prebuilt verifier image must preserve applicable notices, satisfy the Psycopg LGPL requirements, and produce an appropriate software bill of materials.
