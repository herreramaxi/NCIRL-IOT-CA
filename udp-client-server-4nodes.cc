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
#include "ns3/core-module.h"
#include "ns3/core-module.h"
#include "ns3/csma-module.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/mobility-module.h"


using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("UdpClientServerExample");

int
main (int argc, char *argv[])
{
//
// Enable logging for UdpClient and
//
  LogComponentEnable ("UdpClient", LOG_LEVEL_INFO);
  LogComponentEnable ("UdpServer", LOG_LEVEL_INFO);

  bool useV6 = false;
  Address serverAddress; /////CA TIP: add server address variables
  Address serverAddress2; /////CA TIP: add server address variables
  Address serverAddress3; /////CA TIP: add server address variables


  CommandLine cmd;
  cmd.AddValue ("useIpv6", "Use Ipv6", useV6);
  cmd.Parse (argc, argv);

//
// Explicitly create the nodes required by the topology (shown above).
//
  NS_LOG_INFO ("Create nodes.");
  NodeContainer n;
  n.Create (4);


  InternetStackHelper internet;
  internet.Install (n);

  NS_LOG_INFO ("Create channels.");
//
// Explicitly create the channels required by the topology (shown above).
//
  CsmaHelper csma;
  csma.SetChannelAttribute ("DataRate", DataRateValue (DataRate (5000000)));
  csma.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));
  csma.SetDeviceAttribute ("Mtu", UintegerValue (1400));
  NetDeviceContainer d = csma.Install (n);

//
// We've got the "hardware" in place.  Now we need to add IP addresses.
//
  NS_LOG_INFO ("Assign IP Addresses.");
  if (useV6 == false)
    {
      Ipv4AddressHelper ipv4;
      ipv4.SetBase ("10.1.1.0", "255.255.255.0");
      Ipv4InterfaceContainer i = ipv4.Assign (d);
      serverAddress = Address (i.GetAddress (1));
      serverAddress2 = Address (i.GetAddress (2)); ////CA TIP: get servers addresses
      serverAddress3 = Address (i.GetAddress (3)); ////CA TIP: add servers addresses

    }
  else
    {
      Ipv6AddressHelper ipv6;
      ipv6.SetBase ("2001:0000:f00d:cafe::", Ipv6Prefix (64));
      Ipv6InterfaceContainer i6 = ipv6.Assign (d);
      serverAddress = Address(i6.GetAddress (1,1));
    }

  NS_LOG_INFO ("Create Applications.");
//
// Create one udpServer applications on node one.
//
  uint16_t port = 4000;
  UdpServerHelper server (port);
  ApplicationContainer apps = server.Install (n.Get (1));
  apps = server.Install (n.Get (2)); ////CA TIP: add the server applications
  apps = server.Install (n.Get (3)); ////CA TIP: add the server applications

  apps.Start (Seconds (1.0));
  apps.Stop (Seconds (20.0));

//
// Create one UdpClient application to send UDP datagrams from node zero to
// node one.
//
  uint32_t MaxPacketSize = 1024;
  Time interPacketInterval = Seconds (0.05);
  uint32_t maxPacketCount = 320;
  UdpClientHelper client (serverAddress, port);
  client.SetAttribute ("MaxPackets", UintegerValue (maxPacketCount));
  client.SetAttribute ("Interval", TimeValue (interPacketInterval));
  client.SetAttribute ("PacketSize", UintegerValue (MaxPacketSize));
  
  UdpClientHelper client2 (serverAddress2, port); ////CA TIP: add the client applications
  client2.SetAttribute ("MaxPackets", UintegerValue (maxPacketCount)); ////CA TIP: add the client applications
  client2.SetAttribute ("Interval", TimeValue (interPacketInterval)); ////CA TIP: add the client applications
  client2.SetAttribute ("PacketSize", UintegerValue (MaxPacketSize)); ////CA TIP: add the client applications
  
  UdpClientHelper client3 (serverAddress3, port); ////CA TIP: add the client applications
  client3.SetAttribute ("MaxPackets", UintegerValue (maxPacketCount)); ////CA TIP: add the client applications
  client3.SetAttribute ("Interval", TimeValue (interPacketInterval)); ////CA TIP: add the client applications
  client3.SetAttribute ("PacketSize", UintegerValue (MaxPacketSize)); ////CA TIP: add the client applications
  
  
  apps = client.Install (n.Get (0));
  apps = client2.Install (n.Get (0)); ////CA TIP: add the client applications
  apps = client3.Install (n.Get (0)); ////CA TIP: add the client applications

  apps.Start (Seconds (2.0));
  apps.Stop (Seconds (20.0));

  Ptr<FlowMonitor> flowMonitor;
  FlowMonitorHelper flowHelper;
  flowMonitor = flowHelper.InstallAll();
//
// Now, do the actual simulation.
//
  NS_LOG_INFO ("Run Simulation.");
  Simulator::Stop (Seconds (25.0));
  Simulator::Run ();
  flowMonitor->SerializeToXmlFile("udp-results-4nodes.xml", true, true);
  Simulator::Destroy ();
  NS_LOG_INFO ("Done.");
}
