---
title: End-to-End Secure Objects for Media over QUIC Transport
abbrev: MoQT Secure Objects
docname: draft-ietf-moq-secure-objects-latest
category: std

ipr: trust200902
stream: IETF
area: "Applications and Real-Time"
keyword: Internet-Draft
v: 3
venue:
  group: "Media over QUIC"
  type: "Working Group"
  mail: "moq@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/moq/"
  github: "moq-wg/secure-objects"
  latest: "https://moq-wg.github.io/secure-objects/draft-ietf-moq-secure-objects.html"

author:
 -
    name: Cullen Jennings
    organization: Cisco
    email: fluffy@cisco.com
 -
    name: Suhas Nandakumar
    organization: Cisco
    email: snandaku@cisco.com
 -
    name: Richard Barnes
    organization: Cisco
    email: rlb@ipv.sx


normative:
  MoQ-TRANSPORT: I-D.draft-ietf-moq-transport
  SFRAME: RFC9605
  AEAD-LIMITS: I-D.draft-irtf-cfrg-aead-limits

informative:
  CIPHERS:
    title: SFrame Cipher Suites
    author:
    - org: IANA
    date: false
    target: https://www.iana.org/assignments/sframe/sframe.xhtml#sframe-cipher-suites

--- abstract

This document specifies an end-to-end authenticated encryption scheme
for application objects transmitted via Media over QUIC (MoQ)
Transport. The scheme enables original publishers that share a symmetric
key with end subscribers, to ensuring that MoQ relays are unable to
decrypt object contents.  Additionally, subscribers can verify the
integrity and authenticity of received objects, confirming that the
content has not been modified in transit.  Additionally it allows MoQ
parameters to be protected so the publisher can select if they are
readable and/or modifiable by relays.


--- middle

# Introduction

Media Over QUIC Transport (MoQT) is a protocol that is optimized for the
QUIC protocol, either directly or via WebTransport, for the
dissemination of delivery of low latency media {{MoQ-TRANSPORT}}. MoQT
defines a publish/subscribe media delivery layer across set of
participating relays for supporting wide range of use-cases with
different resiliency and latency (live, interactive) needs without
compromising the scalability and cost effectiveness associated with
content delivery networks. It supports sending media objects through
sets of relays nodes.

Typically a MOQ Relay doesn't need to access the media content, thus
allowing the media to be "end-to-end" encrypted so that it cannot be
decrypted by the relays. However for a relay to participate effectively
in the media delivery, it needs to access naming information of a MoQT
object to carryout the required store and forward functions.

As such, two layers of security are required:

1. Hop-by-hop (HBH) security between two MoQT endpoints.

2. End-to-end (E2E) security from the Original Publisher of an MoQT
   object to End Subscribers

The HBH security is provided by TLS in the QUIC connection that MoQT
runs over. MoQT support different E2EE protection as well as allowing
for E2EE security.

This document defines a scheme for E2E authenticated encryption of MoQT
objects.  This scheme is based on the SFrame mechanism for authenticated
encryption of media objects {{SFRAME}}.

However, a secondary goal of this design is to minimize the amount of
additional data the encryptions requires for each object. This is
particularly important for very low bit rate audio applications where
the encryption overhead can increase overall bandwidth usage by a
significant percentage.  To minimize the overhead added by end-to-end
encryption, certain fields that would be redundant between MoQT and
SFrame are not transmitted.

The encryption mechanism defined in this specification can only be used
in application context where object ID values are never more than 32
bits long. This limitation is described in {{nonce}}.

## Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{!RFC2119}} {{!RFC8174}} when, and only when, they appear in all
capitals, as shown here.

E2EE:
: End-to-End Encryption

HBH:
: Hop-by-Hop

varint:
: {{MoQ-TRANSPORT}} variable length integer (Section 1.4.1).


# MoQT Object Model Recap {#MoQT}

MoQT defines a publish/subscribe based media delivery protocol, where in
endpoints, called original publishers, publish objects which are
delivered via participating relays to receiving endpoints, called end
subscribers.

Section 2 of {{MoQ-TRANSPORT}} defines hierarchical object model for
application data, comprised of objects, groups and tracks.

Objects defines the basic data element, an addressable unit whose
payload is sequence of bytes. All objects belong to a group, indicating
ordering and potential dependencies. A track contains has collection of
groups and serves as the entity against which a subscribers issue
subscription requests.

~~~ aasvg
Media Over QUIC Application
|
|                                                           time
+-- TrackA --+---------+-----+---------+-------+---------+------>
|            | Group1  |     | Group2  |  ...  | GroupN  |
|            +----+----+     +----+----+       +---------+
|                 |               |
|                 |               |
|            +----+----+     +----+----+
|            | Object0 |     | Object0 |
|            +---------+     +---------+
|            | Object1 |     | Object1 |
|            +---------+     +---------+
|            | Object2 |     | Object2 |
|            +---------+     +---------+
|                ...
|            +---------+
|            | ObjectN |
|            +---------+
|
|                                                          time
+-- TrackB --+---------+-----+---------+-------+---------+------>
             | Group1  |     | Group2  |  ...  | GroupN  |
             +----+----+     +----+----+       +----+----+
                  |               |                 |
                  |               |                 |
             +----+----+     +----+----+       +----+----+
             | Object0 |     | Object0 |       | Object0 |
             +---------+     +---------+       +---------+
~~~
{: #fig-moqt-session title="Structure of an MoQT session" }

Objects are comprised of three parts: parts that Relays can read and
modify, parts that Relay can read but is not allowed to modify, and
parts the Relays cannot read or modify. The payload portion MAY be end
to end encrypted, in which case it is only visible to the original
publisher and the end subscribers. The application is solely responsible
for the content of the object payload.

Tracks are identified by a combination of its Track Namespace and Track
Name.  Tuples of the Track Namespace and Track Name are treated as a
sequence of binary bytes.  Groups and Objects are represented as
variable length integers called GroupID and ObjectID respectively.

Two important properties of objects are:

1. The combination of Track Namespace, Track Name, Group ID and Object
   ID are globally unique in a given relay network, referred to as Full
   Object ID in this specification.

2. The data inside an MoQT Object (and its size) can never change after
   the Object is first published. There can never be two Objects with
   the same Full Object ID but different data.

One of the ways system keep the Full Object IDs unique is by using a fully
qualified domain names or UUIDs as part of the Track Namespace.

# Secure Objects

Section 10.2.1 {{MoQ-TRANSPORT}} defines fields of a canonical MoQT
Object. The protection scheme defined in this draft encrypts the `Object
Payload` and Encrypted Properties List {{pvt-ext}}.  The scheme
authenticates the `Group ID`, `Object ID`, `Immutable Properties`
(Section 11.6 of {{MoQ-TRANSPORT}}) and `Object Payload` fields,
regardless of the on-the-wire encoding of the objects over QUIC
Datagrams or QUIC streams.

| Protection Level | Fields |
|:-----------------|:-------|
| Unprotected and Unauthenticated (HBH only) | Track Alias, Mutable Properties |
| End-to-End Authenticated | Group ID, Object ID, Publisher Priority, Immutable Properties, Track Namespace, Track Name (including Key ID) |
| End-to-End Encrypted and Authenticated | Original Payload, Encrypted Properties List |
{: #tbl-protection-levels title="MoQ Object Security Protection Levels" }

## Properties

MoQT defines mutable and immutable properties for objects. This
specification uses MoQT immutable properties to convey end-to-end
authenticated metadata and adds encrypted object properties (see
{{pvt-ext}}). The Encrypted Properties List is serialized and encrypted
along with the Object payload, decrypted and deserialized by the
receiver.  This specification further defines the `Secure Object Key ID`
property (see {{keyid-ext}}), which is transmitted within the immutable
properties.

## Setup Assumptions

The application assigns each track a set of (Key ID, `track_base_key`)
tuples, where each `track_base_key` is known only to authorized original
publishers and end subscribers for a given track. How these per-track
secrets and their lifetimes are established is outside the scope of this
specification.  The application also defines which Key ID should be used
for a given encryption operation. For decryption, the Key ID is obtained
from the `Secure Object Key ID` property (that is contained within the
immutable properties of the Object).
The scope of a Key ID is the namespace so if two tracks inside the same
namespace have different tracks_base_keys, then they need to have
different Key ID values. This design is to support a single key across many
tracks where a client uses subscribe namespace to get new tracks as they
are created in the namespace.

Applications determine the ciphersuite to be used for each track's
encryption context.  See {{ciphersuite}} for the list of ciphersuites
that can be used.

## Application Procedure {#app}

This section provides steps for applications over MoQT to use mechanisms
defined in this specification.

### Serialized Full Track Name {#ftn}

Serialized Full Track Name is composed of MoQT Track Namespace and Track
Name as shown below:

~~~
Serialized Full Track Name = Serialize(Track Namespace)
                             + Serialize(Track Name)
~~~

The `Serialize` operation follows the same on-the-wire encoding for
Track Name Space and Track Name as defined in Section 2.4.1 of
{{MoQ-TRANSPORT}}.

This mandates that the serialization of Track Namespace tuples starts
with varint encoded count of tuples. This is followed by encoding
corresponding to each tuple. Each tuple's encoding starts with varint
encoded length for the count of bytes and bytes representing the content
of the tuple.

The Track Name is varint encoded length followed by sequence of bytes
that identifies an individual track within the namespace.


The `+` represents concatenation of byte sequences.

### Object Encryption

To encrypt a MoQT Object, the application constructs a plaintext from
the application data and any encrypted properties:

~~~
pt = Serialize(original_payload)
     + Serialize(Encrypted Properties List)
~~~

Where `original_payload` is the application's object data. The
serialization of `original_payload` consists of a varint-encoded byte
count followed by the payload bytes. The serialization for the Encrypted
Properties List follows the rules for immutable properties (as defined
in Section 11 of {{MoQ-TRANSPORT}}).

The plaintext is then encrypted:

~~~
ciphertext = encrypt(pt)
~~~

The resulting ciphertext replaces the `original_payload` as the MoQT
Object Payload. The ciphertext length reflects the encrypted
`original_payload` plus any Encrypted Properties List plus the AEAD
authentication tag.

The detailed encryption process is shown below:

~~~ aasvg
+-------------------+     +-----------------+
| original_payload  |     | Private Header  |
| (application data)|     | Extensions      |
+---------+---------+     +--------+--------+
          |                        |
          v                        v
          +-----------------------------------------------------------+
                                                                      |
+----------------+           +-------------------------------+        |
| track_base_key |           | Group ID, Object ID,          |        |
| (per Key ID)   |           | Publisher Priority,           |        |
+-------+--------+           | Serialized Immutable Ext[ Key ID ]     |
        |                    +-------+-----------------------+        |
        v                            |                                |
+-------+--------+                   +------------+-----------+       |
| Key Derivation |                   |                        |       |
| (HKDF)         |                   v                        v       |
+---+---------+--+              +------------------------+  +-----+   |
    |         |                 | CTR = GID(64)||OID(32) |  | AAD |   |
    |         |                 +----+-------------------+  +-----+   |
    |         |                      |                        |       |
    |        salt                    |                        |       |
    |         |                      v                        |       |
    |         |            +----+-----------+                 |       |
    |         +----------> | Nonce Formation|                 |       |
    |                      +----+-----------+                 |       |
    |                                |                        |       |
   key                             nonce                     aad     pt
    |                                |                        |       |
    |                                v                        |       |
    |    +-------------+--------------+                       |       |
    |    |                            |                       |       |
    +--->+        AEAD.Encrypt        +<----------------------+       |
         |                            |<------------------------------+
         +-------------+--------------+
                       |
                       v
                 +-----+-----+
                 |Ciphertext |
                 |(MoQT Obj  |
                 | Payload)  |
                 +-----------+
~~~
{: #fig-encryption-process title="Object Encryption Process" }

### Object Decryption

To decrypt a MoQT Object, the application provides the MoQT Object
Payload as ciphertext input to obtain the plaintext:

~~~
pt = decrypt(ciphertext)
~~~

The plaintext is then deserialized to extract the application's
`original_payload` and the Encrypted Properties List:

1. Read a varint to obtain the `original_payload` length.

2. Read that many bytes as `original_payload`.

3. If no bytes remain, there is no Encrypted Properties List.

4. Otherwise, read the property type (16 bits). If the value is not 0xA,
   drop the object. Parse the remaining bytes as the Encrypted
   Properties List structure.

If parsing fails at any stage, the receiver MUST drop the MoQT Object.


The detailed decryption process is shown below:

~~~ aasvg
                 +-----------+
                 |Ciphertext |
                 |(MoQT Obj  |
                 | Payload)  |
                 +-----+-----+
                       |
                       +----------------------------------------------+
                                                                      |
+----------------+           +-------------------------------+        |
| track_base_key |           | Group ID, Object ID,          |        |
| (per Key ID)   |           | Publisher Priority,           |        |
+-------+--------+           | Serialized Immutable Ext[ Key ID ]     |
        |                    +-------+-----------------------+        |
        v                            |                                |
+-------+--------+                   +------------------------+       |
| Key Derivation |                   |                        |       |
| (HKDF)         |                   v                        v       |
+---+------------+              +------------------------+  +-----+   |
    |         |                 | CTR = GID(64)||OID(32) |  | AAD |   |
    |         |                 +----+-------------------+  +-----+   |
    |         |                      |                        |       |
    |       salt                     |                        |       |
    |         |                      v                        |       |
    |         |            +----------------+                 |       |
    |         +----------> | Nonce Formation|                 |       |
    |                      +----------------+                 |       |
    |                                |                        |       |
   key                             nonce                     aad     ct
    |                                |                        |       |
    |                                v                        |       |
    |    +----------------------------+                       |       |
    |    |                            |                       |       |
    +--->|        AEAD.Decrypt        |<----------------------+       |
         |                            |<------------------------------+
         +-------------+--------------+
                       |
                      pt
                       |
                       v
            +----------+----------------+
            |                           |
            v                           v
      +-------------------+     +-----------------+
      | original_payload  |     | Private Header  |
      | (application data)|     | Extensions      |
      +-------------------+     +-----------------+
~~~
{: #fig-decryption-process title="Object Decryption Process" }

## Encryption Schema

MoQT secure object protection relies on an ciphersute to define the AEAD
encryption algorithm and hash algorithm in use ({{ciphersuite}}).  We
will refer to the following aspects of the AEAD and the hash algorithm
below:

* `AEAD.Encrypt` and `AEAD.Decrypt` - The encryption and decryption
  functions for the AEAD.  We follow the convention of RFC 5116
  {{!RFC5116}} and consider the authentication tag part of the
  ciphertext produced by `AEAD.Encrypt` (as opposed to a separate field
  as in SRTP {{?RFC3711}}).

* `AEAD.Nk` - The size in bytes of a key for the encryption algorithm

* `AEAD.Nn` - The size in bytes of a nonce for the encryption algorithm

* `AEAD.Nt` - The overhead in bytes of the encryption algorithm
  (typically the size of a "tag" that is added to the plaintext)

* `AEAD.Nka` - For cipher suites using the compound AEAD described in
  (Section 4.5.1 of {{SFRAME}}), the size in bytes of a key for the
  underlying encryption algorithm

* `Hash.Nh` - The size in bytes of the output of the hash function


## Metadata Authentication {#aad}

The Key ID, Full Track Name, Immutable Properties, Group ID, Object
ID, and Publisher Priority for a given MoQT Object are authenticated as
part of secure object encryption.  This ensures, for example, that
encrypted objects cannot be replayed across tracks and that the
publisher's intended priority cannot be modified without detection.

When protecting or unprotecting a secure object, the following data
structure captures the input to the AEAD function's AAD argument:

~~~  pseudocode
SECURE_OBJECT_AAD {
    Group ID (64),
    Object ID (32),
    Publisher Priority (8),
    Serialized Immutable Properties (..)
}
~~~

The Group ID and Object ID fields are encoded as 64-bit and 32-bit unsigned
integers respectively in big-endian (network) byte order. This fixed-width
encoding ensures that both sender and receiver construct identical AAD values
without ambiguity, as variable-length integer encodings permit multiple
valid representations of the same value.

Serialized Immutable Properties MUST include the `Secure Object Key ID`
property containing the Key ID. This serves as the semantic equivalent
of the KID field in SFrame.

## Nonce Formation {#nonce}

The Group ID and Object ID for an object are used to form a 96-bit
counter (CTR) value, which is XORed with a salt to form the nonce used in
AEAD encryption. The counter value is formed by encoding the Group ID as
a 64-bit big-endian unsigned integer, followed by the Object ID encoded
as a 32-bit big-endian unsigned integer. This encryption/decryption will
fail if applied to an object where group ID is larger than 2^64-1 or the
object ID is larger than 2^32-1 and the MoQT Object MUST NOT be processed
further.

MOQT supports Object IDs larger than 32 bits. However, for common AEAD ciphers such as AES-GCM, performance is better when the nonce is 96 bits. For MOQT’s primary use cases, applications can typically design their track, group, and object structure so that Object IDs do not need to exceed 32 bits, making this a reasonable performance tradeoff.

The Group ID and Object ID could both have been limited to, for example, 48 bits each. However, because 32 bit Object IDs were large enough for the identified use cases, the Object ID field was left at 32 bits.


## Key and Salt Derivation {#keys}

Encryption and decryption use a key and salt derived from the
`track_base_key` associated with a Key ID. Given a `track_base_key`
value, the key and salt are derived using HMAC-based Key Derivation
Function (HKDF) {{!RFC5869}} as follows:

~~~ pseudocode
def derive_key_salt(key_id,track_base_key,
                    serialized_full_track_name):
  moq_secret = HKDF-Extract("", track_base_key)
  moq_key_label = "MOQ 1.0 Secure Objects Secret key "
                + serialized_full_track_name
                + cipher_suite + key_id
  moq_key =
    HKDF-Expand(moq_secret, moq_key_label, AEAD.Nk)
  moq_salt_label = "MOQ 1.0 Secret salt "
                 + serialized_full_track_name
                 + cipher_suite + key_id
  moq_salt =
    HKDF-Expand(moq_secret, moq_salt_label, AEAD.Nn)

  return moq_key, moq_salt
~~~

In the derivation of `moq_secret`:

* The `+` operator represents concatenation of byte sequences.

* The Key ID value is encoded as an 8-byte big-endian integer.

* The `cipher_suite` value is a 2-byte big-endian integer representing
  the cipher suite in use (see {{SFRAME}}).

The hash function used for HKDF is determined by the cipher suite in
use.

## Encryption {#encrypt}

MoQT secure object encryption uses the AEAD encryption algorithm for the
cipher suite in use.  The key for the encryption is the `moq_key`
derived from the `track_base_key` {{keys}}.  The nonce is formed by
first XORing the `moq_salt` with the current CTR value {{nonce}}, and
then encoding the result as a big-endian integer of length `AEAD.Nn`.

The Encrypted Properties List and Object payload field from the MoQT
object are used by the AEAD algorithm for the plaintext.

The encryptor forms an SecObj header using the Key ID value provided.

The encryption procedure is as follows:

1. Obtain the plaintext payload to encrypt from the MoQT object. Extract
   the Group ID, Object ID, and the Serialized Immutable Properties from
   the MoQT object headers. Ensure the Secure Object Key ID property is
   included, with the Key ID set as its value.

2. Retrieve the `moq_key` and `moq_salt` matching the Key ID.

3. Form the aad input as described in {{aad}}.

4. Form the nonce by as described in {{nonce}}.

5. Apply the AEAD encryption function with moq_key, nonce, aad, MoQT
   Object payload and serialized Encrypted Properties List as inputs
   (see {{app}}).

The final SecureObject is formed from the MoQT transport headers,
followed by the output of the encryption.

## Decryption

For decrypting, the Key ID from the `Secure Object Key ID` property
contained within the immutable properties is used to find the right key
and salt for the encrypted object. The MoQT track information matching
the Key ID along with `Group ID` and `Object ID` fields of the MoQT
object header are used to form the nonce.

The decryption procedure is as follows:

1. Parse the SecureObject to obtain Key ID, the ciphertext corresponding
   to MoQT object payload and the Group ID and Object ID from the MoQT
   object headers.

2. Retrieve the `moq_key`, `moq_salt` and MoQT track information
   matching the Key ID.

3. Form the aad input as described in {{aad}}.

4. Form the nonce by as described in {{nonce}}.

5. Apply the AEAD decryption function with moq_key, nonce, aad and
   ciphertext as inputs.

6. Decode the Encrypted Properties List, returning both the properties
   and the object payload.

If extracting Key ID fails either due to missing `Secure Object Key ID`
property within immutable properties or error from parsing, the client
MUST discard the received MoQT Object.

If a ciphertext fails to decrypt because there is no key available for
the Key ID value presented, the client MAY buffer the ciphertext and
retry decryption once a key with that Key ID is received.  If a
ciphertext fails to decrypt for any other reason, the client MUST
discard the ciphertext. Invalid ciphertexts SHOULD be discarded in a way
that is indistinguishable (to an external observer) from having
processed a valid ciphertext.  In other words, the decryption operation
should take the same amount of time regardless of whether decryption
succeeds or fails.


# Object Properties

## Key ID Property {#keyid-ext}

Key ID (Property Type 0x2) is a variable length integer and identifies
the keying material (keys, nonces and associated context for the MoQT
Track) to be used for a given MoQT track.

The Key ID property is included within the Immutable Properties.  All
objects encoded MUST include the Key ID property when using this
specification for object encryption.

## Encrypted Properties List {#pvt-ext}

The Encrypted Properties List (Property Type 0xA) is a container that
holds a sequence of Key-Value-Pairs (see Section 1.4.3 of
{{MoQ-TRANSPORT}}) representing one or more Object Properties. These
properties can be added by the Original Publisher and are encrypted
along with the Object Payload, making them accessible only to End
Subscribers.

~~~
Encrypted Properties List {
  Type (0xA),
  Length (i),
  Key-Value-Pair (..) ...
}
~~~

## Padding Property {#padding-ext}

The Padding Property (Property Type 0x32) allows the Original Publisher
to pad the encrypted payload to obscure the actual size of the object
payload, helping mitigate traffic analysis attacks.

~~~
Padding Property {
  Type (0x32),
  Length (16),
  Padding (...)
}
~~~

Unlike other properties where the Length field uses the MOQ variable-
length integer encoding, the Padding Property always encodes its Length
as a 2-byte (16-bit) unsigned integer in network byte order. This fixed-
size encoding simplifies computing the amount of padding to add.

The Padding field contains `Length` bytes, all of which SHOULD be set to
zero (0x00). Receivers MUST ignore the contents of the Padding field.

This property is included within the Encrypted Properties List, ensuring
that the padding bytes are encrypted along with the object payload and
other encrypted properties. The Padding Property MUST be the last
property in the Encrypted Properties List if present.

### Processing

To add padding, the publisher:

1. Determines the desired padding size based on its traffic analysis
   threat model.

2. Encodes the padding length as a 4-byte unsigned integer in network
   byte order.

3. Appends that many zero bytes as the Padding field.

To skip padding, the receiver:

1. Reads the 1-byte type field (0x32).

2. Reads the next 4 bytes as the padding length.

3. Skips the indicated number of bytes to reach the payload or next
   property.

# Usage Considerations

To implement the protection mechanisms specified herein, a secure object
requires the complete object before any validity checks can be
performed. This introduces latency proportional to the object size; if
the application aggregates excessive data into a single object (e.g.,
encapsulating 6 seconds of video), the entire segment must be received
before processing or validation can commence, delaying access to all
contained data until transfer completion.

This specification does not provide security for Track Properties.
If an application needs end-to-end authentication for track associated data,
the application SHOULD send that data in the Immutable Properties
of the first object in each group.


# Security Considerations {#security}

## Threat Model

MoQT Objects are published by Original Publishers and delivered to End
Subscribers, potentially through one or more Relays. Each MoQT connection
is protected hop-by-hop using TLS. Security on cross Relay links is
outside the scope of MoQT, but this specification assumes protection
equivalent to TLS on those links.

Because security is hop-by-hop, each Relay terminates a security
association and can observe, modify, drop, delay, reorder, or replay MoQT
data. Some message fields are expected to be modified by Relays during
normal operation, while other fields are expected to be visible but
immutable. See {{MoQ-TRANSPORT}} for details.

This specification assumes that the Original Publisher and End Subscriber
share one or more symmetric keys per Track, each identified by a `Key ID`.
Key distribution and key negotiation are out of scope for this document
(e.g., MLS could be used).

In MoQT, sending multiple Objects with the same Track, Group ID, and Object
ID but different values is a Malformed Track Error. This specification
therefore assumes the Original Publisher does not publish modified
versions of the same Object.

This specification enables an End Subscriber to:

1. detect Relay modification of an Object's Original Payload, Encrypted
   Properties, Immutable Properties, Publisher Priority, Group ID, or
   Object ID;

2. detect delivery of an Object under the wrong Track Name or with a
   modified `Key ID`;

3. verify that the Original Payload and Encrypted Properties remained
   confidential from Relays; and

4. detect some (but not all) Object drops or replays in limited cases (see
   {{deletion-detection}}).

This specification does **not** enable an End Subscriber to reliably detect:

* complete suppression of all Objects by a Relay;

* Relay-induced delay or reordering of Objects.


### Fan Out Attacks

Further complexity in the threat model arises from Relay fan out.  A
Relay network can forward Objects on a given Track to many downstream
End Subscribers.  In high rate applications such as video, the number of
Objects delivered per second can be large, and the number of downscale
subscribers can be large.  A malicious Relay can exploit this scale by
attempting different forgeries for different downstream End Subscribers
on a subset of Objects.

In some applications, a Relay could send a forged packet using a trial
key.  If the forgery was accepted, the forged packet would cause the End
Subscriber to take an action observable by the Relay, such as closing
the connection.  This would allow the Relay to determine that the
forgery succeeded, and therefore learn that the trial key was valid for
the Track.

This type of attack should be considered when selecting an appropriate
cryptographic key length for an application. If an applications can fan
out to 2^x clients and send 2^y message over a reasonable time period, a
key roughly (x+y) bits longer SHOULD be used.

One possible mitigation is for the application to track a metric of the
rate of authentication failures across all End Subscribers for each
Track.


## Cryptographic Design

The cryptographic computations described in this document are exactly
those performed in the SFrame encryption scheme defined in {{SFRAME}},
The scheme in this document is effectively a "virtualized" version of
SFrame:

* The CTR value used in nonce formation is not carried in the object
  payload, but instead synthesized from the GroupID and ObjectID.

* The AAD for the AEAD operation is not sent on the wire (as with the
  SFrame Header), but constructed locally by the encrypting and
  decrypting endpoints.

* The format of the AAD is different but contains the same semantic
  information:

    * The Group ID and Object ID are combined to form what is the CTR
      in SFrame.

    * The Key ID (KID) is contained in the Serialized Immutable
      Properties rather than a separate header field.

    * The SFrame Header is constructed using MoQT-style varints, instead
      of the variable-length integer scheme defined in SFrame.

* The `metadata` input in to SFrame operations is defined to be the
  FullTrackName value for the object.

* The labels used in key derivation reflect MOQ usage, not generic
  SFrame.

The security considerations discussed in the SFrame specification thus
also apply here.

The SFrame specification lists several things that an application needs
to account for in order to use SFrame securely, which are all accounted
for here:

1. **Header value uniqueness:** Uniqueness of CTR values follows from
   the uniqueness of MoQT (GroupID, ObjectID) pairs. We only use one Key
   ID value, but instead use distinct SFrame contexts with distinct keys
   per track. This assures that the same (`track_base_key`, Key ID, CTR)
   tuple is never used twice.

2. **Key management:** We delegate this to the MoQT application, with
   subject to the assumptions described in {{setup-assumptions}}.

3. **Anti-replay:** Replay is not possible within the MoQT framework
   because of the uniqueness constraints on ObjectIDs and objects, and
   because the group ID and object ID are cryptographically bound to the
   secure object payload.

4. **Metadata:** The analogue of the SFrame metadata input is defined in
   {{aad}}.

Any of the ciphersuites defined in {{ciphersuite}} registry can be used
to protect MoQT objects.  The caution against short tags in {{Section
7.5 of SFRAME}} still applies here, but the MoQT environment provides
some safeguards that make it safer to use short tags, namely:

* MoQT has hop-by-hop protections provided by the underlying QUIC layer,
  so a brute-force attack could only be mounted by a relay.

* In some usecases MoQT tracks have predictable object arrival rates, so
  a receiver can interpret a large deviation from this rate as a sign of
  an attack.

* The binding of the secure object payload to other MoQT parameters
  (as metadata), together with MoQT's uniqueness properties ensure that
  a valid secure object payload cannot be replayed in a different
  context.

## AEAD Invocation Limits

AEAD algorithms have limits on how many times a single key can be used
before the cryptographic guarantees begin to degrade. Exceeding these
limits can compromise confidentiality (allowing an attacker to
distinguish encrypted content from random data) or integrity (allowing
an attacker to forge valid ciphertexts). The severity of these risks
depends on the specific algorithm in use.

Implementations MUST track the number of encryption and decryption
operations performed with each `moq_key` and ensure that these counts
remain within the limits specified in {{AEAD-LIMITS}} for the cipher
suite in use. When approaching these limits, implementations MUST
arrange for new keying material to be established (e.g., by rotating to
a new Key ID with a fresh `track_base_key`) before the limits are
exceeded.

For the AES-GCM cipher suites defined in this document, the primary
concern is the confidentiality limit, which restricts the number of
encryptions performed with a single key. For AES-CTR-HMAC cipher suites,
both encryption and decryption operations count toward the applicable
limits.

## Detecting Deletion by Malicious Relays {#deletion-detection}

A malicious relay could selectively delete objects or groups before
forwarding them to subscribers. While this specification does not
mandate detection of such deletions, it does provide mechanisms that
applications can use to detect when content has been removed.

Some applications may not require deletion detection, or may be able to
detect missing data based on the internal structure of the object
payload (e.g., sequence numbers embedded in the media format). For
applications that do require deletion detection at the MoQT layer, the
following approaches are available:

### Monotonically Incrementing Identifiers

Applications that assign Group IDs and Object IDs in a strictly
monotonic sequence (incrementing by 1 for each successive group or
object) can straightforwardly detect gaps. A subscriber receiving Group
ID N followed by Group ID N+2, or Object ID M followed by Object ID M+3,
can conclude that intervening content was not delivered.

### Non-Sequential Identifiers with Gap Properties

Applications that use Group IDs or Object IDs with intentional gaps
(e.g., for sparse data or timestamp-based identifiers) MUST include the
Prior Group ID Gap and/or Prior Object ID Gap properties as immutable
properties. These properties indicate the expected distance to the next
identifier. If the Prior Object ID Gap property is absent from a secure
object, receivers MUST assume a gap value of 1. Similarly, if the Prior
Group ID Gap property is absent, receivers MUST assume a gap value of 1.

## Signaling End of Content

For applications that need to reliably detect lost objects at the end of
a subgroup, group, or track, it is RECOMMENDED to signal completion
using object status values defined in {{MoQ-TRANSPORT}}. By explicitly
marking the final object in a sequence, subscribers can distinguish
between "more objects may arrive" and "all objects have been sent,"
enabling detection of trailing deletions that would otherwise be
undetectable.

Publishers SHOULD send an End of Group status (0x3) as the final object
in each group. This allows subscribers to determine whether all objects
up to that Object ID have been received, enabling detection of any
missing objects at the end of the group.

Publishers SHOULD send an End of Track status (0x4) when the track is
complete (e.g., end of a recorded stream or live session). This allows
subscribers to determine whether all objects up to that location have
been received, enabling detection of any missing objects at the end of
the track.

For subgroup boundaries, the transport stream closure (FIN) signals that
all objects in the subgroup have been delivered.

# IANA Considerations {#iana}

## MOQ Object Properties Registry

This document defines new MoQT Object properties under the
`MOQ Object Properties` registry.

| Type |                         Value                        |
| ---- | ---------------------------------------------------- |
| 0x2  | Secure Object Key ID - see {{keyid-ext}}             |
| 0xA  | Encrypted Properties List - see {{pvt-ext}}          |
| 0x32 | Padding - see {{padding-ext}}                        |

Note: The Encrypted Properties List type (0xA) appears only within the
encrypted payload structure defined in {{app}}, not as a regular MoQT
Object Property. It is registered here to reserve the type value and
prevent conflicts with the property type field used in the encrypted
payload format.

## Cipher Suites {#ciphersuite}

This document establishes a "MoQ Secure Objects Cipher Suites" registry.
Each cipher suite specifies an AEAD encryption algorithm and a hash
algorithm used for key derivation.

The following values are defined for each cipher suite:

* `Nh`: The size in bytes of the hash function output

* `Nka`: The size in bytes of the encryption key for the underlying
  cipher (CTR suites only)

* `Nk`: The size in bytes of the AEAD key

* `Nn`: The size in bytes of the AEAD nonce

* `Nt`: The size in bytes of the AEAD authentication tag

| Value  | Name                       | R | Nh | Nka | Nk | Nn | Nt |
| ------ | -------------------------- | - | -- | --- | -- | -- | -- |
| 0x0000 | Reserved                   | - |    |     |    |    |    |
| 0x0001 | AES_128_CTR_HMAC_SHA256_80 | Y | 32 | 16  | 48 | 12 | 10 |
| 0x0002 | AES_128_CTR_HMAC_SHA256_64 | Y | 32 | 16  | 48 | 12 | 8  |
| 0x0003 | AES_128_CTR_HMAC_SHA256_32 | N | 32 | 16  | 48 | 12 | 4  |
| 0x0004 | AES_128_GCM_SHA256_128     | Y | 32 | n/a | 16 | 12 | 16 |
| 0x0005 | AES_256_GCM_SHA512_128     | Y | 64 | n/a | 32 | 12 | 16 |
| 0xF000-0xFFFF | Reserved for private use | - |  |     |    |    |    |

The "R" column indicates whether the cipher suite is Recommended:

* Y: Indicates that the IETF has consensus that the item is
     RECOMMENDED. Requires Standard Action as defined {{!RFC8126}}.

* N: Indicates the IETF has made no statement about the suitability of
     the associated mechanism. Requires First Come First Serve as
     defined in {{!RFC8126}}.

* D: Indicates that the item is discouraged and SHOULD NOT be
     used. Requires Standard Action or IESG Approval as defined in
     {{!RFC8126}}.

Cipher suite values are 2-byte big-endian integers.  The algorithms are
the same as defined in SFrame ciphersuites defined in the IANA SFrame
Cipher Suites -registry {{CIPHERS}}.

**AES-GCM cipher suites** (0x0004, 0x0005) use AES-GCM for authenticated
encryption with a full 128-bit authentication tag.

**AES-CTR-HMAC cipher suites** (0x0001, 0x0002, 0x0003) use AES in
counter mode combined with HMAC for authentication in an
encrypt-then-MAC construction. These suites support truncated
authentication tags, providing lower overhead at the cost of reduced
forgery resistance.

Implementations MUST support `AES_128_GCM_SHA256_128` (0x0004).
Implementations SHOULD support `AES_128_CTR_HMAC_SHA256_80` (0x0001).



--- back

# Acknowledgements

Thanks to Alan Frindell for providing text on adding encrypted
properties. Thank you to Magnus Westerlund for doing a thorough
security review.

# Test Vectors {#test-vectors}

This appendix provides test vectors for verifying implementations of the
MOQ Secure Objects encryption scheme. The vectors are presented in JSON
format with hex-encoded byte strings and integer numeric values.
Whitespace in the JSON is not significant.

These vectors are deterministic and can be reproduced from the reference
implementation by running `cargo run --bin generate-test-vectors`.

The JSON structure has four top-level keys corresponding to four test
categories:

~~~json
\{
  "full_track_name": [...],
  "key_derivation": [...],
  "nonce_aad": [...],
  "encryption": [...]
\}
~~~

## Full Track Name Serialization

Each entry tests serialization of Track Namespace tuples and Track Name
into the Serialized Full Track Name byte string.

~~~json
[
  {
    "namespace_tuples": ["example.com"],
    "track_name": "audio",
    "serialized_full_track_name":
      "010b6578616d706c652e636f6d05617564696f"
  },
  {
    "namespace_tuples": ["example.com", "meeting-123"],
    "track_name": "video",
    "serialized_full_track_name":
      "020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f"
  },
  {
    "namespace_tuples": ["example.com", "meeting-123", "floor-1"],
    "track_name": "slides",
    "serialized_full_track_name":
      "030b6578616d706c652e636f6d0b6d656574696e672d31323307666c6f6f722d3106736c69646573"
  }
]
~~~

## Key Derivation

Each entry tests HKDF-Extract and HKDF-Expand for deriving `moq_key`
and `moq_salt` from the `track_base_key`. The `track_base_key` values
are ASCII strings: "sixteen byte key" (16 bytes) for SHA-256 suites and
"a]256-bit-base-key-for-test!!!!!" (32 bytes) for SHA-512 suites.
Intermediate values (`moq_secret`, `moq_key_label`, `moq_salt_label`)
are included to aid debugging.

~~~json
[
  {
    "cipher_suite": 1,
    "key_id": 7,
    "track_base_key": "7369787465656e2062797465206b6579",
    "serialized_full_track_name":
      "020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f",
    "moq_secret":
      "e5e76a372058231c56eedca06436c94e6f6bab38d759687367c92048faf93f18",
    "moq_key_label":
      "4d4f5120312e3020536563757265204f626a6563747320536563726574206b657920020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00010000000000000007",
    "moq_salt_label":
      "4d4f5120312e30205365637265742073616c7420020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00010000000000000007",
    "moq_key":
      "36543f1f0d00ea1c6ecacaab3ec878772ef6e4bf7e91f29a1fa99af410802420fa92560c1850654f5ae7fa0281d3d1d9",
    "moq_salt": "e905de3e41c5feb642a8ea58"
  },
  {
    "cipher_suite": 2,
    "key_id": 7,
    "track_base_key": "7369787465656e2062797465206b6579",
    "serialized_full_track_name":
      "020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f",
    "moq_secret":
      "e5e76a372058231c56eedca06436c94e6f6bab38d759687367c92048faf93f18",
    "moq_key_label":
      "4d4f5120312e3020536563757265204f626a6563747320536563726574206b657920020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00020000000000000007",
    "moq_salt_label":
      "4d4f5120312e30205365637265742073616c7420020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00020000000000000007",
    "moq_key":
      "12acb1032ea6b0c8ee2c1f9cfe052f0d13220782a559c50e669645951bb15ed1c93ae2ff02b411649e0aa99aec19b865",
    "moq_salt": "17efc7dfcc10786fa00771b8"
  },
  {
    "cipher_suite": 4,
    "key_id": 7,
    "track_base_key": "7369787465656e2062797465206b6579",
    "serialized_full_track_name":
      "020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f",
    "moq_secret":
      "e5e76a372058231c56eedca06436c94e6f6bab38d759687367c92048faf93f18",
    "moq_key_label":
      "4d4f5120312e3020536563757265204f626a6563747320536563726574206b657920020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00040000000000000007",
    "moq_salt_label":
      "4d4f5120312e30205365637265742073616c7420020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00040000000000000007",
    "moq_key": "eb3b95606d7c4775688c121e8f06832c",
    "moq_salt": "dc11a8d516c299f44b24be8d"
  },
  {
    "cipher_suite": 5,
    "key_id": 7,
    "track_base_key":
      "615d3235362d6269742d626173652d6b65792d666f722d746573742121212121",
    "serialized_full_track_name":
      "020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f",
    "moq_secret":
      "f633519ec99705bae4bcc7fe0f88ccd3c0301355d97d2265773d8b80ccf23ca39d500bc2d5399315bf78bfc5ed69f8be7b6799cfb35691ffe2db6126ab9e897d",
    "moq_key_label":
      "4d4f5120312e3020536563757265204f626a6563747320536563726574206b657920020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00050000000000000007",
    "moq_salt_label":
      "4d4f5120312e30205365637265742073616c7420020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00050000000000000007",
    "moq_key":
      "03a7b0a238bde6d398c0c8de14538c31c8f84a4356a01f5ca00d9a46d4046953",
    "moq_salt": "2c82451648c8d25e94b8dbdc"
  }
]
~~~

## Nonce and AAD Formation

Each entry tests CTR construction from Group ID and Object ID, nonce
formation by XOR with salt, and SECURE_OBJECT_AAD serialization. All
entries use AES_128_GCM_SHA256_128 (cipher suite 0x0004) with Key ID 7.

~~~json
[
  {
    "group_id": 0,
    "object_id": 0,
    "publisher_priority": 0,
    "key_id": 7,
    "serialized_immutable_properties": "",
    "moq_salt": "dc11a8d516c299f44b24be8d",
    "ctr": "000000000000000000000000",
    "nonce": "dc11a8d516c299f44b24be8d",
    "aad": "0000000000000000000000000000020107"
  },
  {
    "group_id": 42,
    "object_id": 1,
    "publisher_priority": 128,
    "key_id": 7,
    "serialized_immutable_properties": "",
    "moq_salt": "dc11a8d516c299f44b24be8d",
    "ctr": "000000000000002a00000001",
    "nonce": "dc11a8d516c299de4b24be8c",
    "aad": "000000000000002a000000018000020107"
  },
  {
    "group_id": 18446744073709551615,
    "object_id": 4294967295,
    "publisher_priority": 255,
    "key_id": 7,
    "serialized_immutable_properties": "",
    "moq_salt": "dc11a8d516c299f44b24be8d",
    "ctr": "ffffffffffffffffffffffff",
    "nonce": "23ee572ae93d660bb4db4172",
    "aad": "ffffffffffffffffffffffffff00020107"
  }
]
~~~

## Full Encryption

Each entry tests the complete encryption pipeline including key
derivation, nonce formation, AAD construction, and AEAD encryption. The
`plaintext` field shows the serialized input to AEAD: `varint(payload_len)
|| payload || encrypted_properties_list`. All entries include both
immutable properties (which affect the AAD) and encrypted properties
(which are encrypted with the payload).

Common inputs (ASCII values shown for readability):

* `track_base_key`: "sixteen byte key" (16B) or
  "a]256-bit-base-key-for-test!!!!!" (32B)
* `original_payload`: "hello from moq"
* `immutable_properties`: property type 0x0004, value "relay-ok"
* `encrypted_properties_list`: property type 0x0100, value "for-eyes-only"

~~~json
[
  {
    "cipher_suite": 1,
    "key_id": 7,
    "track_base_key": "7369787465656e2062797465206b6579",
    "namespace_tuples": ["example.com", "meeting-123"],
    "track_name": "video",
    "serialized_full_track_name":
      "020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f",
    "group_id": 42,
    "object_id": 1,
    "publisher_priority": 128,
    "immutable_properties": "00040872656c61792d6f6b",
    "original_payload": "68656c6c6f2066726f6d206d6f71",
    "encrypted_properties_list":
      "000a1001000d666f722d657965732d6f6e6c79",
    "plaintext":
      "0e68656c6c6f2066726f6d206d6f71000a1001000d666f722d657965732d6f6e6c79",
    "moq_secret":
      "e5e76a372058231c56eedca06436c94e6f6bab38d759687367c92048faf93f18",
    "moq_key_label":
      "4d4f5120312e3020536563757265204f626a6563747320536563726574206b657920020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00010000000000000007",
    "moq_salt_label":
      "4d4f5120312e30205365637265742073616c7420020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00010000000000000007",
    "moq_key":
      "36543f1f0d00ea1c6ecacaab3ec878772ef6e4bf7e91f29a1fa99af410802420fa92560c1850654f5ae7fa0281d3d1d9",
    "moq_salt": "e905de3e41c5feb642a8ea58",
    "ctr": "000000000000002a00000001",
    "nonce": "e905de3e41c5fe9c42a8ea59",
    "aad":
      "000000000000002a00000001800002010700040872656c61792d6f6b",
    "ciphertext":
      "170654428664c29b3eab20a76e86ab2c2fc210b218b38eb556974021b7804b1d7ced925e33e3d6080e8157d4"
  },
  {
    "cipher_suite": 2,
    "key_id": 7,
    "track_base_key": "7369787465656e2062797465206b6579",
    "namespace_tuples": ["example.com", "meeting-123"],
    "track_name": "video",
    "serialized_full_track_name":
      "020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f",
    "group_id": 42,
    "object_id": 1,
    "publisher_priority": 128,
    "immutable_properties": "00040872656c61792d6f6b",
    "original_payload": "68656c6c6f2066726f6d206d6f71",
    "encrypted_properties_list":
      "000a1001000d666f722d657965732d6f6e6c79",
    "plaintext":
      "0e68656c6c6f2066726f6d206d6f71000a1001000d666f722d657965732d6f6e6c79",
    "moq_secret":
      "e5e76a372058231c56eedca06436c94e6f6bab38d759687367c92048faf93f18",
    "moq_key_label":
      "4d4f5120312e3020536563757265204f626a6563747320536563726574206b657920020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00020000000000000007",
    "moq_salt_label":
      "4d4f5120312e30205365637265742073616c7420020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00020000000000000007",
    "moq_key":
      "12acb1032ea6b0c8ee2c1f9cfe052f0d13220782a559c50e669645951bb15ed1c93ae2ff02b411649e0aa99aec19b865",
    "moq_salt": "17efc7dfcc10786fa00771b8",
    "ctr": "000000000000002a00000001",
    "nonce": "17efc7dfcc107845a00771b9",
    "aad":
      "000000000000002a00000001800002010700040872656c61792d6f6b",
    "ciphertext":
      "df0fd1431b6883bcb841fa14d4588630aaf11c92363b536ecc08273a27ac4f47bd72fca55f29cd1fad9b"
  },
  {
    "cipher_suite": 4,
    "key_id": 7,
    "track_base_key": "7369787465656e2062797465206b6579",
    "namespace_tuples": ["example.com", "meeting-123"],
    "track_name": "video",
    "serialized_full_track_name":
      "020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f",
    "group_id": 42,
    "object_id": 1,
    "publisher_priority": 128,
    "immutable_properties": "00040872656c61792d6f6b",
    "original_payload": "68656c6c6f2066726f6d206d6f71",
    "encrypted_properties_list":
      "000a1001000d666f722d657965732d6f6e6c79",
    "plaintext":
      "0e68656c6c6f2066726f6d206d6f71000a1001000d666f722d657965732d6f6e6c79",
    "moq_secret":
      "e5e76a372058231c56eedca06436c94e6f6bab38d759687367c92048faf93f18",
    "moq_key_label":
      "4d4f5120312e3020536563757265204f626a6563747320536563726574206b657920020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00040000000000000007",
    "moq_salt_label":
      "4d4f5120312e30205365637265742073616c7420020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00040000000000000007",
    "moq_key": "eb3b95606d7c4775688c121e8f06832c",
    "moq_salt": "dc11a8d516c299f44b24be8d",
    "ctr": "000000000000002a00000001",
    "nonce": "dc11a8d516c299de4b24be8c",
    "aad":
      "000000000000002a00000001800002010700040872656c61792d6f6b",
    "ciphertext":
      "facafee5c450bd140759bdffa6eef6948ae6dbfdb7ba87cf3e161a641b27f952eb4f13b18e351d4e7e344675f0dc96e0cd5e"
  },
  {
    "cipher_suite": 5,
    "key_id": 7,
    "track_base_key":
      "615d3235362d6269742d626173652d6b65792d666f722d746573742121212121",
    "namespace_tuples": ["example.com", "meeting-123"],
    "track_name": "video",
    "serialized_full_track_name":
      "020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f",
    "group_id": 42,
    "object_id": 1,
    "publisher_priority": 128,
    "immutable_properties": "00040872656c61792d6f6b",
    "original_payload": "68656c6c6f2066726f6d206d6f71",
    "encrypted_properties_list":
      "000a1001000d666f722d657965732d6f6e6c79",
    "plaintext":
      "0e68656c6c6f2066726f6d206d6f71000a1001000d666f722d657965732d6f6e6c79",
    "moq_secret":
      "f633519ec99705bae4bcc7fe0f88ccd3c0301355d97d2265773d8b80ccf23ca39d500bc2d5399315bf78bfc5ed69f8be7b6799cfb35691ffe2db6126ab9e897d",
    "moq_key_label":
      "4d4f5120312e3020536563757265204f626a6563747320536563726574206b657920020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00050000000000000007",
    "moq_salt_label":
      "4d4f5120312e30205365637265742073616c7420020b6578616d706c652e636f6d0b6d656574696e672d31323305766964656f00050000000000000007",
    "moq_key":
      "03a7b0a238bde6d398c0c8de14538c31c8f84a4356a01f5ca00d9a46d4046953",
    "moq_salt": "2c82451648c8d25e94b8dbdc",
    "ctr": "000000000000002a00000001",
    "nonce": "2c82451648c8d27494b8dbdd",
    "aad":
      "000000000000002a00000001800002010700040872656c61792d6f6b",
    "ciphertext":
      "09399b821a1452a320a8bf927c004c71f8fd34449070f99746ff6ab0ef67a4f93b7f889e64d194a7b18a7a946184fed15386"
  }
]
~~~
