## to get raw packets

- for query
    - `nc -u -l 1053 > raw_packets/query_packet.txt` start a server and capture packets
    - `dig +retry=0 -p 1053 @127.0.0.1 +noedns google.com` get the packet
- for response
    - use the captured query packet 
    - `nc -u 8.8.8.8 53 < raw_packets/query_packet.txt > raw_packets/response_packet.txt`

- to inspect
    - `hexdump -C raw_packets/query_packet.txt`







