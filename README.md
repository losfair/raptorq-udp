# raptorq-udp

Simple tool to transmit RaptorQ-encoded data over UDP.

Packet format:

```
|---------------------|----------------------------|------|
| blake3(file)[0..16] | blake3(packet_body)[0..16] | body |
|---------------------|----------------------------|------|
```
