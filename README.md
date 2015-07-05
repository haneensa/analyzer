# Introduction
A packet analyzer is a program that intercepts the traffic passing through a network interface. 

# Description
The analyzer works as follow:
- it capture the packets of specified application layer protocols
- output the header fields
- optionally log the captured header information into a trace file
- allow sophisticated filtering capabilities through the "Berkeley Packet Filter" BPF language

# Command line interface

```
./sniffer --protocol <protocol name> | --bpf <filter language> [--log <log filename>]
```

```
Where:
--protocol <protocol name>: captures the packets generated by the specified protocol. 
--bpf <fileter language>: captures the packets filtered by the defined "filter language"
--log <log filename>: outputs the extracted packet header information into the specified log file
```

# Outputs
For each captured packet, the analyzer output the following information:

1. packet length
2. MAC source address, MAC destination address
3. source IP, destination IP, time to live (TTL)
4. source port, destination port
