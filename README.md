# network-transport-tcp-tls

[![CircleCI](https://circleci.com/gh/adjoint-io/network-transport-tcp-tls.svg?style=svg&circle-token=5f583c222bdd72844749fdf3a82a2900a5f93d86)](https://circleci.com/gh/adjoint-io/network-transport-tcp-tls)

TCP instantiation of Network.Transport with TLS  

See http://haskell-distributed.github.com for documentation, user guides,
tutorials and assistance.

## Description

This library was written to provide TLS on top of the `network-transport-tcp`
Transport implementation. It provides a minimal TLS interface, and makes certain
TLS configuration decisions based on the manner in which processes initialized
by `distributed-process` will interact: an TCP transport layer with TLS such that 
all non-tcp-control messages, messages `network-transport-tcp` uses to establish
reliable connections between endpoints, sent between Transport Endpoints are
encrypted with Ephemeral Diffie Hellman RSA keys such that forward secrecy is
preserved. Assumption, notes to users of this package, and description of future
work are outlined below.

## Assumptions

* Users care about security more than speed; TLS introduces a significant
  overhead over TCP.
* The Common Name on TLS certificates possessed by endpoints do not match their
  hostname; This check is turned when validating TLS certificates.
* Users care about [forward
  secrecy](https://en.wikipedia.org/wiki/Forward_secrecy), thus ephemeral Diffie
  Helman keys are used during the exchange of messages between a client and
  server.
* Users desire strongly encrypted network communication, thus 4096bit RSA keys
  are expected to be used by both client and server. Server with certificates
  made with less than 4096bit RSA keys will be rejected by clients.
* All connections made with remote endpoints are by other endpoints created 
  using the same version of `network-transport-tcp-tls`.

## Notes 

* In local benchmarks, the `network-transport-tcp-tls` implementation has
  proven to be 2000x - 5000x slower than the original `network-transport-tcp`
  library. This is seemingly due the large overhead introduced for de/serializing 
  TLS messages within the `tls` package, along with encrypting and decrypting 
  messages using modular exponentiation.

* The `TLSConfig` type serves as the configuration for the TLS communication
  between endpoints. It is currently quite limited, obligating users to supply
  only the server credentials and supported algorithms, versions, and ciphers
  via the `Network.TLS.Supported` type, and optionally a certificate store and
  client credentials. 

* A TLS handshake is performed after establishing a reliable TCP connection
  after performing the proper handshake `network-transport-tcp`'s Transport
  instantiation performs during valid remote endpoint connection setup.

* EndPoints create a TLS server with when responding to connection requests from
  remote EndPoints, and create a TLS client when initiating connections with
  remote EndPoints. In both cases, a `Network.TLS.Context` is established and
  stored in the `ValidRemoteEndPointState` such that sending/receiving messages 
  to/from remote endpoint can be encrypted/decrypted accordingly. 

* EndPoint connections with TLS do not verify that the name on the certificate
  of the remote endpoint being verified matches the network hostname of the
  remote endpoint. 

* TLS is not used when sending and receiving messages on the same endpoint. E.g.
  processes on the same local node (in `distributed-process`) do not communicate
  with TLS as messages are not sent over the network. 

## Roadmap / Future Work 

* In future releases more configuration options should be exposed. For now, the 
  limited config is because there are a number of secure, sensible parameters 
  hard coded such that end users of this library need not concern themselves 
  with certain aspects of TLS. However, we should not force these TLS
  configuration parameters upon users with deeper knowledge of TLS.

* TLS Sessions are currently not supported. This would require
  `ValidLocalEndPointState` values to never remove or temporarily cache previous
  connections to `RemoteEndPoint`s, remembering the `SessionID` (if they were
  the "client" in the connection) or remembering the `SessionData` (if they were
  the "server" in the previous connection), and sometimes both. This would
  require use of `Network.TLS.bye` before a connection to a `RemoteEndPoint` is
  closed, so a session could be resumable. 

* A "network-access-token" could be implemented on the transport layer by
  signing an endpoint's certificate with a shared private key. First, the
  instantiator of the network would generate a new private key and a 
  subsequent self-signed certificate; This would be known as the Network Access
  Certificate Authority (NACA). Members of the network would generate a
  Certificate Signing Request (CSR) and either send it off to an authority in
  posession of the NACA to be signed, or sign their CSR themselves using the 
  potentially shared private key of the NACA. When using a NACA, processes using 
  `network-transport-tcp-tls` will only be able to establish connections with 
  endpoints using a NACA if they possess the same NACA and their certificate is 
  signed by the NACA's private key. Both clients and servers will be required to 
  exchange certificates proving they possess a valid certificate signed by the NACA.

## Getting Help / Raising Issues

Please visit the [bug tracker](https://github.com/haskell-distributed/network-transport-tcp/issues) to submit issues. You can contact the distributed-haskell@googlegroups.com mailing list for help and comments.

## License

This package is made available under a 3-clause BSD-style license.
