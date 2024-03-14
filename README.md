# ACA-Py External JSON-LD Signer

A quick demonstration of using an external service for signing JSON-LD creds.

The External Provider component is added to ACA-Py in [PR #2835](https://github.com/hyperledger/aries-cloudagent-python/pull/2835).

The KMS Service used by this demo can be found here: [dbluhm/mini-kms](https://github.com/dbluhm/mini-kms).


## Run the Demo

```sh
docker-compose build
docker-compose run demo
docker-compose down -v # Stop and clean up when you're done
```

You should be able to observe two requests to the `kms` service by running:

```sh
docker-compose logs kms
```

There should be one request to the key generation endpoint and one to the signing endpoint.

Logs from the ACA-Py instance may also be of interest:

```sh
docker-compose logs issuer
```


## Points of Interest

See the [package init](/acapy_ld_signer/__init__.py) for an example of instantiating and loading the External Provider in ACA-Py.

See [provider.py](/acapy_ld_signer/provider.py) to see the implementation of the External Provider itself.
