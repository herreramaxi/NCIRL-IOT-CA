#usr/bin/bash

dirResults="scratch/.Results"

echo "Create scratch/.Results folder if not exists"
if [ ! -d $dirResults ]
then
     mkdir $dirResults
fi

echo "Delete avgResults.csv"
rm scratch/.Results/avgResults.csv

echo "Executing TCP simulations..."
./waf --run "scratch/tcp-pcap-nanosec-example-n-nodes --nodes=2"
./waf --run "scratch/tcp-pcap-nanosec-example-n-nodes --nodes=3"
./waf --run "scratch/tcp-pcap-nanosec-example-n-nodes --nodes=6"
./waf --run "scratch/tcp-pcap-nanosec-example-n-nodes --nodes=9"
./waf --run "scratch/tcp-pcap-nanosec-example-n-nodes --nodes=10"
./waf --run "scratch/tcp-pcap-nanosec-example-n-nodes --nodes=15"
./waf --run "scratch/tcp-pcap-nanosec-example-n-nodes --nodes=20"

echo "Executing UDP simulations..."
./waf --run "scratch/udp-client-server-n-nodes --nodes=2"
./waf --run "scratch/udp-client-server-n-nodes --nodes=3"
./waf --run "scratch/udp-client-server-n-nodes --nodes=6"
./waf --run "scratch/udp-client-server-n-nodes --nodes=9"
./waf --run "scratch/udp-client-server-n-nodes --nodes=10"
./waf --run "scratch/udp-client-server-n-nodes --nodes=15"
./waf --run "scratch/udp-client-server-n-nodes --nodes=20"
