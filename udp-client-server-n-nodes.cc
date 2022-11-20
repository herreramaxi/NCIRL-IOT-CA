/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// Network topology
//
//       n0    n1
//       |     |
//       =======
//         LAN
//
// - UDP flows from n0 to n1

#include <fstream>
#include <sys/stat.h>
#include "ns3/core-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/mobility-module.h"
#include "ns3/ipv4-flow-classifier.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("UdpClientServerExample");


uint64_t totaltxBytes;
uint64_t totalrxBytes;
uint32_t totaltxPackets;
uint32_t totalrxPackets;
uint32_t totalLostPackets;
double totalDelaySum;
double totalJitterSum;
double simulationTimeSum;
double avgDelay;
double avgJitter;
double avgThroughput;
int maxNodes;
//****************************************
// Support functions for stdout
//****************************************
void print(std::string str)
{
  std::cout << str;
}

void print(std::string label, uint64_t metric)
{
  std::cout << "  " << label << ": " << metric << "\n";
}

void print(std::string label, uint32_t metric)
{
  std::cout << "  " << label << ": " << metric << "\n";
}

void print(std::string label, uint32_t metric, std::string unit)
{
  std::cout << "  " << label << ": " << metric << unit << "\n";
}

void print(std::string label, int64_t metric, std::string unit)
{
  std::cout << "  " << label << ": " << metric << unit << "\n";
}

void print(std::string label, uint64_t metric, std::string unit)
{
  std::cout << "  " << label << ": " << metric << unit << "\n";
}

void print(std::string label, double metric, std::string unit)
{
  std::cout << "  " << label << ": " << metric << unit << "\n";
}

void print(std::string label, Time metric)
{
  std::cout << "  " << label
            << ": " << metric << " = " << metric.GetSeconds() << "s"
            << "\n";
}

void PrintFlowStats(FlowId flowId, FlowMonitor::FlowStats flowStats, Ipv4FlowClassifier::FiveTuple t)
{
  std::cout << "Flow " << flowId << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";

  print("Tx Bytes", flowStats.txBytes);
  print("Rx Bytes", flowStats.rxBytes);
  print("Sent Packets", flowStats.txPackets);
  print("Received Packets", flowStats.rxPackets);
  print("Lost Packets", flowStats.txPackets - flowStats.rxPackets);
  print("Packet delivery ratio", flowStats.rxPackets * 100 / flowStats.txPackets);
  print("Packet loss ratio", (flowStats.txPackets - flowStats.rxPackets) * 100 / flowStats.txPackets);
  print("delaySum", flowStats.delaySum);
  print("jitterSum", flowStats.jitterSum);
  print("timeLastRxPacket -timeFirstRxPacket", flowStats.timeLastRxPacket.GetSeconds() - flowStats.timeFirstRxPacket.GetSeconds(), "s");
  print("Delay", (double)flowStats.delaySum.GetMilliSeconds() / flowStats.rxPackets, "ms");
  print("Jitter", (double)flowStats.jitterSum.GetMilliSeconds() / (flowStats.rxPackets - 1), "ms");
  print("Throughput", (double)flowStats.rxBytes * 8.0 / (flowStats.timeLastRxPacket.GetSeconds() - flowStats.timeFirstRxPacket.GetSeconds()) / 1000000, "Mbps");
}

void PrintTotalResults(int count)
{
  print("=================TOTAL RESULTS=======================\n");
  print("Total Tx Bytes", totaltxBytes, "bytes");
  print("Total Rx Bytes", totalrxBytes, "bytes");
  print("Total Sent Packets", totaltxPackets);
  print("Total Received Packets", totalrxPackets);
  print("Total Lost Packets", totalLostPackets);
  print("Packet delivery ratio", (double)totalrxPackets * 100 / totaltxPackets, "%");
  print("Packet loss ratio", (double)(totaltxPackets - totalrxPackets) * 100 / totaltxPackets, "%");
  print("Total Simulation time", (double)simulationTimeSum, "s");
  print("Avg Simulation time", (double)simulationTimeSum/count, "s");
  print("End to end delay", (double)totalDelaySum, "s");
  print("End to end jitter", (double)totalJitterSum, "s");
  print("Avg Delay", avgDelay / count, "ms");
  print("Avg Jitter", avgJitter / count, "ms");
  print("Avg Throughput", avgThroughput / count, "Mbps");
}

//****************************************
// Support functions for CSV file
//****************************************

bool fileExists(const std::string &filename)
{
  struct stat buf;
  if (stat(filename.c_str(), &buf) != -1)
  {
    return true;
  }
  return false;
}

void appendNewLine(std::ofstream &file)
{
  file << "\n";
}

void appendNoDelimiter(std::ofstream &file, std::string str)
{
  file << str;
}

void appendTo(std::ofstream &file, const char *str)
{
  file << str << ",";
}

void appendTo(std::ofstream &file, std::string str)
{
  file << str << ",";
}

void appendTo(std::ofstream &file, uint16_t data)
{
  appendTo(file, std::to_string(data));
}

void appendTo(std::ofstream &file, uint32_t data)
{
  appendTo(file, std::to_string(data));
}

void appendTo(std::ofstream &file, uint64_t data)
{
  appendTo(file, std::to_string(data));
}

void appendTo(std::ofstream &file, int64_t data)
{
  appendTo(file, std::to_string(data));
}

void appendTo(std::ofstream &file, double data)
{
  appendTo(file, std::to_string(data));
}

void appendTo(std::ofstream &file, Ipv4Address data)
{
  file << data << ",";
}

void PrintHeaderToCsv(std::ofstream &file)
{
  appendTo(file, "Flow");
  appendTo(file, "Source IP");
  appendTo(file, "Source Port");
  appendTo(file, "Target IP");
  appendTo(file, "Target Port");
  appendTo(file, "Tx Bytes");
  appendTo(file, "Rx Bytes");
  appendTo(file, "Sent Packets");
  appendTo(file, "Received Packets");
  appendTo(file, "Lost Packets");
  appendTo(file, "Packet delivery ratio");
  appendTo(file, "Packet loss ratio");
  appendTo(file, "delaySum (s)");
  appendTo(file, "jitterSum (s)");
  appendTo(file, "timeLastRxPacket (s)");
  appendTo(file, "TimeFirstRxPacket (s)");
  appendTo(file, "timeLastRxPacket - timeFirstRxPacket (s)");
  appendTo(file, "Delay (ms)");
  appendTo(file, "Jitter (ms)");
  appendTo(file, "Throughput (Mbps)");
  appendNewLine(file);
}

void PrintFlowStatsToCsv(std::ofstream &file, FlowId flowId, FlowMonitor::FlowStats second, Ipv4FlowClassifier::FiveTuple t)
{
  appendTo(file, flowId);
  appendTo(file, t.sourceAddress);
  appendTo(file, t.sourcePort);
  appendTo(file, t.destinationAddress);
  appendTo(file, t.destinationPort);
  appendTo(file, second.txBytes);
  appendTo(file, second.rxBytes);
  appendTo(file, second.txPackets);
  appendTo(file, second.rxPackets);
  appendTo(file, second.txPackets - second.rxPackets);
  appendTo(file, second.rxPackets * 100 / second.txPackets);
  appendTo(file, (second.txPackets - second.rxPackets) * 100 / second.txPackets);
  appendTo(file, second.delaySum.GetSeconds());
  appendTo(file, second.jitterSum.GetSeconds());
  appendTo(file, second.timeLastRxPacket.GetSeconds());
  appendTo(file, second.timeFirstRxPacket.GetSeconds());
  appendTo(file, second.timeLastRxPacket.GetSeconds() - second.timeFirstRxPacket.GetSeconds());
  appendTo(file, (double)second.delaySum.GetMilliSeconds() / second.rxPackets);
  appendTo(file, (double)second.jitterSum.GetMilliSeconds() / (second.rxPackets - 1));
  appendTo(file, (double)second.rxBytes * 8.0 / (second.timeLastRxPacket.GetSeconds() - second.timeFirstRxPacket.GetSeconds()) / 1000000);
  appendNewLine(file);
}

void PrintTotalResultsToCsv(std::ofstream &myfile, int count)
{
  appendTo(myfile, "Average");
  appendTo(myfile, "");
  appendTo(myfile, "");
  appendTo(myfile, "");
  appendTo(myfile, "");
  appendTo(myfile, totaltxBytes/count);
  appendTo(myfile, totalrxBytes/count);
  appendTo(myfile, totaltxPackets/count);
  appendTo(myfile, totalrxPackets/count);
  appendTo(myfile, totalLostPackets/count);
  appendTo(myfile, (double)totalrxPackets * 100 / totaltxPackets);
  appendTo(myfile, (double)(totaltxPackets - totalrxPackets) * 100 / totaltxPackets);
  appendTo(myfile, totalDelaySum/count);
  appendTo(myfile, totalJitterSum/count);
  appendTo(myfile, "");
  appendTo(myfile, "");
  appendTo(myfile, simulationTimeSum/count);
  appendTo(myfile, avgDelay / count);
  appendTo(myfile, avgJitter / count);
  appendTo(myfile, avgThroughput / count);
}

void PrintHeaderResultsToCsv(std::ofstream &file)
{
  appendTo(file, "Protocol");
  appendTo(file, "Nodes");
  appendTo(file, "Tx Bytes");
  appendTo(file, "Rx Bytes");
  appendTo(file, "Sent Packets");
  appendTo(file, "Received Packets");
  appendTo(file, "Lost Packets");
  appendTo(file, "Packet delivery ratio");
  appendTo(file, "Packet loss ratio");
  appendTo(file, "delaySum (s)");
  appendTo(file, "jitterSum (s)");
  appendTo(file, "simulation time (s)");
  appendTo(file, "Delay (ms)");
  appendTo(file, "Jitter (ms)");
  appendTo(file, "Throughput (Mbps)");
  appendNewLine(file);
}

void AppendAvgResultsToCsv(std::ofstream &file, int count)
{
  appendTo(file, "UDP");
  appendTo(file, (uint32_t)maxNodes);
  appendTo(file, totaltxBytes/count);
  appendTo(file, totalrxBytes/count);
  appendTo(file, totaltxPackets/count);
  appendTo(file, totalrxPackets/count);
  appendTo(file, totalLostPackets/count);
  appendTo(file, (double)totalrxPackets * 100 / totaltxPackets);
  appendTo(file, (double)(totaltxPackets - totalrxPackets) * 100 / totaltxPackets);
  appendTo(file, totalDelaySum/count);
  appendTo(file, totalJitterSum/count);
  appendTo(file, simulationTimeSum/count);
  appendTo(file, avgDelay / count);
  appendTo(file, avgJitter / count);
  appendTo(file, avgThroughput / count);
  appendNewLine(file);
}

//****************************************
// Support functions for stats calculations
//****************************************

void InitializeStats()
{
  totaltxBytes = 0;
  totalrxBytes = 0;
  totaltxPackets = 0;
  totalrxPackets = 0;
  totalLostPackets = 0;
  totalDelaySum = 0;
  totalJitterSum = 0;
  simulationTimeSum = 0;
  avgDelay = 0;
  avgJitter = 0;
  avgThroughput = 0;
}

void CalculateTotalStats(FlowMonitor::FlowStats flowStats)
{
  totaltxBytes += flowStats.txBytes;
  totalrxBytes += flowStats.rxBytes;
  totaltxPackets += flowStats.txPackets;
  totalrxPackets += flowStats.rxPackets;
  totalLostPackets += (flowStats.txPackets - flowStats.rxPackets);
  totalDelaySum += flowStats.delaySum.GetSeconds();
  totalJitterSum += flowStats.jitterSum.GetSeconds();
  simulationTimeSum += (flowStats.timeLastRxPacket.GetSeconds() - flowStats.timeFirstRxPacket.GetSeconds());
  avgDelay += ((double)flowStats.delaySum.GetMilliSeconds() / flowStats.rxPackets);
  avgJitter += ((double)flowStats.jitterSum.GetMilliSeconds() / (flowStats.rxPackets - 1));
  avgThroughput += ((double)flowStats.rxBytes * 8.0 / (flowStats.timeLastRxPacket.GetSeconds() - flowStats.timeFirstRxPacket.GetSeconds()) / 1000000);
}

int main(int argc, char *argv[])
{
  //
  // Enable logging for UdpClient and
  //
  // LogComponentEnable("UdpClient", LOG_LEVEL_INFO);
  // LogComponentEnable("UdpServer", LOG_LEVEL_INFO);

  maxNodes = 2;
  CommandLine cmd;
  cmd.AddValue("nodes", "Total number of nodes", maxNodes);
  cmd.Parse(argc, argv);

  InitializeStats();

  //
  // Explicitly create the nodes required by the topology (shown above).
  //
  NS_LOG_INFO("Create nodes.");
  NodeContainer n;
  n.Create(maxNodes);

  InternetStackHelper internet;
  internet.Install(n);

  NS_LOG_INFO("Create channels.");
  //
  // Explicitly create the channels required by the topology (shown above).
  //
  CsmaHelper csma;
  csma.SetChannelAttribute("DataRate", DataRateValue(DataRate(5000000)));
  // csma.SetChannelAttribute("DataRate", DataRateValue(DataRate(500000)));
  csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
  csma.SetDeviceAttribute("Mtu", UintegerValue(1400));
  NetDeviceContainer d = csma.Install(n);

  //
  // We've got the "hardware" in place.  Now we need to add IP addresses.
  //
  NS_LOG_INFO("Assign IP Addresses.");

  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i = ipv4.Assign(d);
  Address *serverAddreses = new Address[maxNodes - 1];

  for (int j = 0; j < maxNodes - 1; j++)
  {
    serverAddreses[j] = Address(i.GetAddress(j + 1));
  }

  NS_LOG_INFO("Create Applications.");
  //
  // Create one udpServer applications on node one.
  //
  uint16_t port = 4000;
  UdpServerHelper server(port);
  ApplicationContainer apps;

  for (int j = 0; j < maxNodes - 1; j++)
  {
    apps = server.Install(n.Get(j + 1));
  }

  apps.Start(Seconds(1.0));
  apps.Stop(Seconds(25.0));

  //
  // Create one UdpClient application to send UDP datagrams from node zero to
  // node one.
  //
  uint32_t MaxPacketSize = 1024;
  Time interPacketInterval = Seconds(0.05);
//  Time interPacketInterval = Seconds(0.005);
  uint32_t maxPacketCount = 320;

  for (int j = 0; j < maxNodes - 1; j++)
  {
    UdpClientHelper client(serverAddreses[j], port);
    client.SetAttribute("MaxPackets", UintegerValue(maxPacketCount));
    client.SetAttribute("Interval", TimeValue(interPacketInterval));
    client.SetAttribute("PacketSize", UintegerValue(MaxPacketSize));
    apps = client.Install(n.Get(0));
  }

  apps.Start(Seconds(2.0));
  apps.Stop(Seconds(25.0));

  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowHelper;
  flowMonitor = flowHelper.InstallAll();
  //
  // Now, do the actual simulation.
  //
  NS_LOG_INFO("Run Simulation.");
  Simulator::Stop(Seconds(25.0));
  Simulator::Run();

  flowMonitor->CheckForLostPackets();

  std::ofstream myfile;
  myfile.open("scratch/.Results/udpResults-" + std::to_string(maxNodes) + "-nodes.csv");
  PrintHeaderToCsv(myfile);

 bool exists = fileExists("scratch/.Results/avgResults.csv");

  std::ofstream avgResultsFile;
  avgResultsFile.open("scratch/.Results/avgResults.csv", std::ios_base::app);

  if (!exists)
  {
    PrintHeaderResultsToCsv(avgResultsFile);
  }

  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
  std::map<FlowId, FlowMonitor::FlowStats> stats = flowMonitor->GetFlowStats();
  int count = 0;

  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i != stats.end(); ++i)
  {
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
    if (t.destinationPort != port)
    {
      continue;
    }

    PrintFlowStats(i->first, i->second, t);
    PrintFlowStatsToCsv(myfile, i->first, i->second, t);

    CalculateTotalStats(i->second);
    count++;
  }

  PrintTotalResults(count);
  PrintTotalResultsToCsv(myfile, count);
  AppendAvgResultsToCsv(avgResultsFile, count);

  myfile.close();
  avgResultsFile.close();

  flowMonitor->SerializeToXmlFile("scratch/.Results/udpResults-" + std::to_string(maxNodes) + "-nodes.xml", true, true);
  Simulator::Destroy();
  NS_LOG_INFO("Done.");

  delete (serverAddreses);
}
