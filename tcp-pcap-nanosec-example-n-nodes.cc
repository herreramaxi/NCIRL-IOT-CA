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

// ============================================================ //
// BASED ON tcp-bulk-send.cc                                    //
// ============================================================ //

// Network topology
//
//       n0 ----------- n1
//            500 Kbps
//             2 ms
//
// - Flow from n0 to n1 using BulkSendApplication.
// - Tracing of queues and packet receptions to file "tcp-pcap-nanosec-example.pcap"
//     when tracing is turned on.
// - Trace file timestamps are recorded in nanoseconds, when requested
//

// ============================================================ //
// NOTE: You can check the "magic" number of a pcap file with   //
//       the following command:                                 //
//                                                              // myfile << "This is the first cell in the first column.\n";
//                    od -N4 -tx1 filename.pcap                 //
//                                                              //
// ============================================================ //

#include <string>
#include <fstream>
#include <iostream>
#include "ns3/core-module.h"
#include "ns3/nstime.h"
#include "ns3/on-off-helper.h"
#include "ns3/applications-module.h"
#include "ns3/csma-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/network-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TcpPcapNanosecExample");

void print(std::string label, uint64_t metric)
{
  std::cout << "  " << label << ":   " << metric << "\n";
}
void print(std::string label, int64_t metric, std::string unit)
{
  std::cout << "  " << label << ":   " << metric << unit << "\n";
}

void print(std::string label, uint64_t metric, std::string unit)
{
  std::cout << "  " << label << ":   " << metric << unit << "\n";
}

void print(std::string label, double metric, std::string unit)
{
  std::cout << "  " << label << ":   " << metric << unit << "\n";
}

void print(std::string label, Time metric)
{
  std::cout << "  " << label
            << ":   " << metric << " = " << metric.GetSeconds() << "s"
            << "\n";
}

void printTocsv(std::ofstream &file, std::string str)
{
  file << str;
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

//"Flow,Source IP, Source Port,Target IP, Target Port,Tx Bytes,Rx Bytes,delaySum,rxPackets,jitterSum,timeLastRxPacket,TimeFirstRxPacket,timeLastRxPacket -timeFirstRxPacket,Delay,Jitter,Throughput \n");
void printTocsv(std::ofstream &file, FlowId flowId, FlowMonitor::FlowStats second, Ipv4FlowClassifier::FiveTuple t)
{

  // file << flowId << "," << t.sourceAddress << "," << t.sourcePort << ","
  // << t.destinationAddress << "," << t.destinationPort << "," <<
  // second.txBytes << ","
  // << second.rxBytes << "," << second.delaySum << "," << second.rxPackets << "," << second.jitterSum << "," << second.timeLastRxPacket.GetSeconds() << "s"
  //      << "," << second.timeFirstRxPacket.GetSeconds() << "s"
  //      << "," << second.timeLastRxPacket.GetSeconds() - second.timeFirstRxPacket.GetSeconds() << "s"
  //      << "," << (double)second.delaySum.GetMilliSeconds() / second.rxPackets << "ms"
  //      << "," << (double)second.jitterSum.GetMilliSeconds() / (second.rxPackets - 1) << "ms"
  //      << "," << second.rxBytes * 8.0 / (second.timeLastRxPacket.GetSeconds() - second.timeFirstRxPacket.GetSeconds()) / 1024 / 1024 << "Mbps"
  //      << "\n";

  appendTo(file, flowId);
  appendTo(file, t.sourceAddress);
  appendTo(file, t.sourcePort);
  appendTo(file, t.destinationAddress);
  appendTo(file, t.destinationPort);
  appendTo(file, second.txBytes);
  appendTo(file, second.rxBytes);
  appendTo(file, second.delaySum.GetSeconds());
  appendTo(file, second.rxPackets);
  appendTo(file, second.jitterSum.GetSeconds());
  appendTo(file, second.timeLastRxPacket.GetSeconds());
  appendTo(file, second.timeFirstRxPacket.GetSeconds());
  appendTo(file, second.timeLastRxPacket.GetSeconds() - second.timeFirstRxPacket.GetSeconds());
  appendTo(file, (double)second.delaySum.GetMilliSeconds() / second.rxPackets);
  appendTo(file, (double)second.jitterSum.GetMilliSeconds() / (second.rxPackets - 1));
  appendTo(file, (double)second.rxBytes * 8.0 / (second.timeLastRxPacket.GetSeconds() - second.timeFirstRxPacket.GetSeconds()) / 1024 / 1024);
  printTocsv(file, "\n");
}

int main(int argc, char *argv[])
{

  bool tracing = false;
  bool nanosec = false;
  uint32_t maxBytes = 327680;
  int maxNodes = 2;
  //
  // Allow the user to override any of the defaults at
  // run-time, via command-line arguments
  //
  CommandLine cmd;
  cmd.AddValue("tracing", "Flag to enable tracing", tracing);
  cmd.AddValue("nanosec", "Flag to use nanosecond timestamps for pcap as default", nanosec);
  cmd.AddValue("maxBytes", "Total number of bytes for application to send", maxBytes);
  cmd.AddValue("nodes", "Total number of nodes", maxNodes);
  cmd.Parse(argc, argv);

  //
  // If requested via the --nanosec cmdline flag, generate nanosecond timestamp for pcap traces
  //
  if (nanosec)
  {
    Config::SetDefault("ns3::PcapFileWrapper::NanosecMode", BooleanValue(true));
  }

  //
  // Explicitly create the nodes required by the topology (shown above).
  //
  NS_LOG_INFO("Create nodes.");
  NodeContainer nodes;
  nodes.Create(maxNodes);

  NS_LOG_INFO("Create channels.");

  //
  // Install the internet stack on the nodes
  //
  InternetStackHelper internet;
  internet.Install(nodes);

  //

  CsmaHelper csma;
  csma.SetChannelAttribute("DataRate", DataRateValue(DataRate(5000000)));
  csma.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2)));
  csma.SetDeviceAttribute("Mtu", UintegerValue(1400));
  NetDeviceContainer devices = csma.Install(nodes);

  // We've got the "hardware" in place.  Now we need to add IP addresses.
  //
  NS_LOG_INFO("Assign IP Addresses.");
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer i = ipv4.Assign(devices);

  NS_LOG_INFO("Create Applications.");

  //
  // Create a BulkSendApplication and install it on node 0
  //
  uint16_t port = 9; // well-known echo port number

  //
  // Explicitly create the point-to-point link required by the topology (shown above).
  //
  ApplicationContainer sourceApps;
  for (int j = 1; j < maxNodes; j++)
  {
    OnOffHelper onoff("ns3::TcpSocketFactory", InetSocketAddress(i.GetAddress(j), port));
    onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1.0]"));
    onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0.0]"));
    onoff.SetAttribute("PacketSize", StringValue("1024"));
    onoff.SetAttribute("DataRate", StringValue("500kb/s"));
    onoff.SetAttribute("MaxBytes", UintegerValue(327680));

    sourceApps = onoff.Install(nodes.Get(0));
  }

  sourceApps.Start(Seconds(0.0));
  sourceApps.Stop(Seconds(10.0));

  //
  // Create a PacketSinkApplication and install it on node 1
  //
  ApplicationContainer sinkApps;
  for (int j = 1; j < maxNodes; j++)
  {
    PacketSinkHelper sink("ns3::TcpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
    sinkApps = sink.Install(nodes.Get(j));
    sinkApps.Start(Seconds(0.0));
    sinkApps.Stop(Seconds(10.0));
  }

  Ptr<FlowMonitor> monitor;
  FlowMonitorHelper flowHelper;
  monitor = flowHelper.InstallAll();

  //
  // Now, do the actual simulation.
  //
  NS_LOG_INFO("Run Simulation.");
  Simulator::Stop(Seconds(20.0));
  Simulator::Run();

  monitor->CheckForLostPackets();

  std::ofstream myfile;
  myfile.open("tcpResults-" + std::to_string(maxNodes) + "-nodes.csv");
  printTocsv(myfile, "Flow,Source IP,Source Port,Target IP, Target Port,Tx Bytes,Rx Bytes,delaySum (s),rxPackets,jitterSum (s),timeLastRxPacket (s),TimeFirstRxPacket (s),timeLastRxPacket -timeFirstRxPacket (s),Delay (ms),Jitter (ms),Throughput (Mbps) \n");

  Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
  std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();

  for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin(); i != stats.end(); ++i)
  {
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
    if (t.destinationPort != port)
    {
      continue;
    }

    std::cout << "Flow " << i->first << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";

    print("Tx Bytes", i->second.txBytes);
    print("Rx Bytes", i->second.rxBytes);
    print("delaySum", i->second.delaySum);
    print("rxPackets", i->second.rxPackets);
    print("jitterSum", i->second.jitterSum);
    print("timeLastRxPacket", i->second.timeLastRxPacket);
    print("TimeFirstRxPacket", i->second.timeFirstRxPacket);
    print("timeLastRxPacket -timeFirstRxPacket", i->second.timeLastRxPacket.GetSeconds() - i->second.timeFirstRxPacket.GetSeconds(), "s");
    print("Delay", (double)i->second.delaySum.GetMilliSeconds() / i->second.rxPackets, "ms");
    print("Jitter", (double)i->second.jitterSum.GetMilliSeconds() / (i->second.rxPackets - 1), "ms");

    printTocsv(myfile, i->first, i->second, t);
  }

  myfile.close();

  monitor->SerializeToXmlFile("tcpResults-" + std::to_string(maxNodes) + "-nodes.xml", true, true);
  Simulator::Destroy();
  NS_LOG_INFO("Done.");
}
