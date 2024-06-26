# ssl-cert-tree

An SSL certificate chain visualizer written in Python.

This uses the [cryptography] package to load and verify certificates,
then organizes them into a tree to be presented with tkinter.

[cryptography]: https://cryptography.io/en/latest/

## Usage

With Python 3.11+ and Git installed, you can clone and install this repository:

```sh
$ git clone https://github.com/thegamecracks/ssl-cert-tree
$ cd ssl-cert-tree
$ pip install .
```

Once installed, the `sslct` command can be used to load certificate files
from the current working directory or a given directory:

```sh
$ sslct examples/certifi
```

![A list of trusted root certificates](/docs/images/certifi.png)

Certificates highlighted in red mean they were unable to be verified.
This may be a result of an unsupported signature algorithm (like shown above),
a missing issuer certificate, or an invalid signature.

When there are CA-issued certificates, i.e. certificates that aren't self-signed,
they will be shown under the certificate authority that issued them, forming a hierarchy.
If you have OpenSSL installed, you can see this effect by running the
[example script](/examples/nested/generate_certificates.py)
to generate a set of certificates:

```sh
$ python examples/nested/generate_certificates.py
$ sslct examples/nested
```

![A tree of certificates](/docs/images/nested.png)
