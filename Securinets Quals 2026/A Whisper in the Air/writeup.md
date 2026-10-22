# A Whisper in the Air — Writeup

> **Spoilers:** This writeup includes the recovered passkey, keys, and flag.

## Overview

The capture is a set of raw BLE Link Layer frames. The useful path is to identify the keyboard's pairing connection, recover its legacy pairing passkey, decrypt the key distribution, match the later encrypted connection to that bond, and decode its HID reports. The line order is useful within a capture, but it is not a timestamp across connections.

## 1. Split and identify the connections

Each frame starts with an access address, followed by the Link Layer header and payload. A `CONNECT_IND` is carried on the advertising access address and includes the access address that will identify the new data connection. Group subsequent frames by that assigned address; do not combine all frames that happen to be adjacent in the text file.

In `capture1.txt`, the keyboard connection uses access address `9b7c3d2e`. Its `CONNECT_IND` contains initiator address `66554433221a` and responder address `c0ffee001337`; both address types are public (`iat = rat = 0`). Other captures contain decoy or failed activity. `capture4.txt` is the later connection to follow after recovering the bond key.

## 2. Locate the SMP pairing exchange

For each data connection, inspect Link Layer data frames for L2CAP packets on CID `0x0006`, the Security Manager Protocol (SMP) channel. In the successful connection the Pairing Request and Pairing Response are:

```text
Preq = 01 04 00 05 10 01 03
Pres = 02 02 00 05 10 01 03
```

The IO capabilities (`0x04`, KeyboardDisplay; `0x02`, KeyboardOnly) and AuthReq (`0x05`, bonding plus MITM, without Secure Connections) indicate legacy Passkey Entry. The Link Layer header's access-address and address-type fields, along with the captured request and response, are inputs to the confirm calculation.

The SMP Confirm and Random values in this exchange are:

```text
Initiator Confirm = b001329c6765ffa3fe65eea51b497a9b
Responder Confirm = 17e05c2334545c6d4d880df1c6ccaec9
Initiator Random  = a3f10b7729c84e5d61b2905fd4c3e180
Responder Random  = 5c8e2d41f06b9a37c21d4e8f0a6b7c93
```

## 3. Recover and validate the passkey

Try the six-digit passkey range using the standard numeric TK encoding. The Bluetooth legacy `c1` function is:

```text
p1 = Pres || Preq || rat || iat
p2 = 00000000 || IA || RA
c1(TK, r, ...) = AES(TK, AES(TK, r XOR p1) XOR p2)
```

The captured multi-octet values are serialized on air in little-endian order. Reverse each captured field individually before passing it to a conventional AES implementation; do not reverse the assembled `p1` or `p2` as a whole. Reverse the calculated confirm before comparing it to the captured confirm.

The matching passkey is `731904`, giving:

```text
TK = 000000000000000000000000000b2b00
```

With the AES inputs in the order above, the calculated confirms are:

```text
Initiator c1 = 9b7a491ba5ee65fea3ff65679c3201b0
Initiator c1 reversed for the capture = b001329c6765ffa3fe65eea51b497a9b
Responder c1 = c9aeccc6f10d884d6d5c5434235ce017
Responder c1 reversed for the capture = 17e05c2334545c6d4d880df1c6ccaec9
```

Both calculated on-air confirms match their corresponding captured values. A candidate that matches only one side is not enough. The `c1` definition and byte construction are specified in the [Bluetooth Core Specification, Security Manager](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html).

## 4. Derive the STK and decrypt the pairing key distribution

Use the verified TK and the pairing randoms in the legacy `s1` function:

```text
STK = s1(TK, LP_RAND_R, LP_RAND_I)
STK = d3a35578548aa7eb02853cb0d76d16c4
```

After reversing the captured random fields, take the least-significant 64 bits of the responder random followed by the least-significant 64 bits of the initiator random. Here the AES input to `s1` is `379a6bf0412d8e5c5d4ec829770bf1a3`.

The first connection's `LL_ENC_REQ` and `LL_ENC_RSP` provide:

```text
LL_ENC_REQ: RAND=0000000000000000 EDIV=0000 SKDm=1122334455667788 IVm=aabbccdd
LL_ENC_RSP: SKDs=8877665544332211 IVs=11223344
```

Normalize each SKD half and concatenate responder then initiator: `SKD = reverse(SKDs) || reverse(SKDm)`. The IV is `IVm || IVs`. The session key is `AES(STK, SKD)`. This gives:

```text
SKD = 11223344556677888877665544332211
IV  = aabbccdd11223344
Session key = 366ac1088418edd2998c2a921e17b377
```

Decrypt the first encrypted SMP key-distribution packets with AES-CCM and accept them only when the MIC validates. They reveal:

```text
LTK  = f0e1d2c3b4a5968778695a4b3c2d1e0f
EDIV = cf4c
RAND = 1122334455667788
```

For example, the authenticated plaintexts (including their L2CAP and SMP headers) are:

```text
11000600060f1e2d3c4b5a69788796a5b4c3d2e1f0
0b00060007cf4c1122334455667788
```

The first is SMP Encryption Information; reversing its on-air LTK bytes yields the LTK shown above. The second is Master Identification and contains EDIV followed by RAND.

The LTK is carried in SMP Encryption Information; EDIV and RAND follow in the Master Identification command. The spec describes `s1` and this legacy key-distribution flow in the same [Security Manager specification](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/security-manager-specification.html).

## 5. Link the later capture and authenticate its packets

In `capture4.txt`, the later `LL_ENC_REQ` uses EDIV `cf4c` and RAND `1122334455667788`, matching the values from the pairing. That ties this connection to the recovered bond.

Its encryption parameters are:

```text
LL_ENC_REQ: RAND=1122334455667788 EDIV=cf4c SKDm=deadbeef00112233 IVm=cafe0001
LL_ENC_RSP: SKDs=33221100efbeadde IVs=0002feca
```

Derive the later session parameters from its `LL_ENC_REQ`/`LL_ENC_RSP` and the LTK:

```text
SKD = deadbeef0011223333221100efbeadde
IV  = cafe00010002feca
Session key = 790b0a707f7bc1bb4ef1cf5742621726
```

Use the same `SKD = reverse(SKDs) || reverse(SKDm)`, `IV = IVm || IVs`, and `session_key = AES(LTK, SKD)` construction for this reconnect.

For each encrypted packet, construct the nonce as the four-byte little-endian packet counter, the direction bit (`0x00` or `0x80`), and the eight-byte IV. Use the Link Layer header masked with `0xe3` as authenticated data, and verify the four-byte MIC. Track counters separately by direction: the missing packet creates a counter jump from `10` to `11` in direction 0. One frame is an exact Link Layer retransmission; authenticate it using its original counter, but do not advance the counter twice. This leaves 77 unique authenticated packets and one duplicate.

## 6. Reassemble ATT and decode the HID reports

Reassemble fragmented Link Layer data into L2CAP packets, then inspect ATT traffic. Pair Read Requests with their Responses to recover the HID Report Map and Report Reference instead of assuming the keyboard uses the standard boot report.

The Report Map is 61 bytes and contains a HID long-item marker `FE 00 FF`. Consume the long item's size, tag, and payload before continuing to parse the descriptor. The Report Reference is `02 01`: report ID 2, input report. Its data contains a modifier byte, a reserved byte, five key slots, and a vendor sequence byte.

The notifications arrive on ATT handle `0x0014`; each payload is nine bytes including report ID 2. The input layout is: report ID, modifier, reserved byte, five key slots, then the vendor sequence byte. Track key-down transitions, modifiers, and releases; use the French AZERTY layout when converting HID usage IDs to characters. The vendor sequence begins `0, 2`, exposing the missing report/release in the capture. Decoding the reports yields:

```text
Securinets{bl3_k3yb0ard_w34k_TK}
```

## Validation chain

The solve is reproducible because each stage checks the next one: both SMP confirms validate the passkey; AES-CCM MICs validate the pairing key-distribution packets; EDIV/RAND match the reconnect; reconnect packets authenticate under the derived session key; and the decrypted, descriptor-guided HID reports produce the flag.
