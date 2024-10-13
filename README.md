# raptorq-udp

Simple tool to transmit RaptorQ-encoded data over UDP.

Packet format:

```
|---------------------|----------------------------|------|
| sha256(file)[0..16] | sha256(packet_body)[0..16] | body |
|---------------------|----------------------------|------|
```
