# NCIRL-IOT-CA

## How to setup your NS3 scratch folder
Copy the following files into your folder "ns-allinone-3.26\ns-3.26\scratch":
* [executeSimulations.sh](https://github.com/herreramaxi/NCIRL-IOT-CA/blob/main/executeSimulations.sh)
* [tcp-pcap-nanosec-example-n-nodes.cc](https://github.com/herreramaxi/NCIRL-IOT-CA/blob/main/tcp-pcap-nanosec-example-n-nodes.cc)
* [udp-client-server-n-nodes.cc](https://github.com/herreramaxi/NCIRL-IOT-CA/blob/main/udp-client-server-n-nodes.cc)

## How to run simulations
1. Go to folder ns-allinone-3.26\ns-3.26
2. Execute the following: ./scratch/executeSimulations.sh

### Expected results
* All the TCP and UDP simulations are executed.
* A folder ".Results" is created on "ns-allinone-3.26\ns-3.26\scratch".
* The folder ".Results" contains the simulations results.

## Results
### avgResults.csv
This file contains the average results of each simulation. 
For TCP simulations, the ACK package is ignored (destinationPort != 9). [tcp-pcap-nanosec-example-n-nodes.cc#L492](https://github.com/herreramaxi/NCIRL-IOT-CA/blob/abbf3f7cb951dc95d511ff56f4e5c1ef11a7e60d/tcp-pcap-nanosec-example-n-nodes.cc#L492)
* [.Results/avgResults.csv](https://github.com/herreramaxi/NCIRL-IOT-CA/blob/main/.Results/avgResults.csv)

### TCP results
They are saved into ".Results" folder.

#### flowMonitor results
* The convension name is: tcpResults-N-nodes.xml
* Example: [.Results/tcpResults-2-nodes.xml](https://github.com/herreramaxi/NCIRL-IOT-CA/blob/main/.Results/tcpResults-2-nodes.xml)

#### Flow statistics/metrics
* The convension name is: tcpResults-N-nodes.csv
* Example: [.Results/tcpResults-2-nodes.csv](https://github.com/herreramaxi/NCIRL-IOT-CA/blob/main/.Results/tcpResults-2-nodes.csv)

### UDP results
They are saved into ".Results" folder.

#### flowMonitor results
* The convension name is: udpResults-N-nodes.xml
* Example: [.Results/udpResults-2-nodes.xml](https://github.com/herreramaxi/NCIRL-IOT-CA/blob/main/.Results/udpResults-2-nodes.xml)

#### Flow statistics/metrics
* The convension name is: udpResults-N-nodes.csv
* Example: [.Results/udpResults-2-nodes.csv](https://github.com/herreramaxi/NCIRL-IOT-CA/blob/main/.Results/udpResults-2-nodes.csv)
