# Collectd decoder

A simple collectd network packat decoder written in python. It has support for
encrypted packets.

It doesn't do anything smart. It just does it best decoding packets and prints
them to stdout.

Only tested with collectd 4.10 packet formats

## Usage

Capture data first, keep your tcpdump as specific as possible:

```
$ sudo tcpdump -nn -i eth0 -w dump.pcap udp and port 25826 and host 13.0.0.37

```

Then parse:

```
$ python3 ./collectd_decoder.py -f dump.pcap [-p enc_passwd]
```

Output should look something like:

```
########################################
HOST rofl.copter.ninja
TIMEHR Thu May 1 10:00:01 2019
INTERVALHR 300
PLUGIN table
PLUGIN_INSTANCE cpu
TYPE gauge
TYPE_INSTANCE load
VALUES [['GAUGE', 9000.1]]
```
