import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.StandardHost;

network HierarchicalNetwork
{
    types:
        channel HighSpeedLink extends ned.DatarateChannel
        {
            delay = 1ms;
            datarate = 100Mbps;
        }
        channel LowSpeedLink extends ned.DatarateChannel
        {
            delay = 3ms;
            datarate = 100Mbps;
        }

    submodules:
        configurator: Ipv4NetworkConfigurator { 
            @display("p=100,50"); 
        }

		nodeClient: StandardHost {
            @display("p=100,250");
            numApps = 2; 
            app[0].typename = "DNSClient";
            app[1].typename = "DNSClient";
        }

        dnsLocal: StandardHost {
            @display("p=300,250");
            numApps = 1;
            app[0].typename = "DNSServer";
        }

        dnsRoot: StandardHost {
            @display("p=500,250");
            numApps = 1;
            app[0].typename = "DNSServer";
        }

    connections:
        nodeClient.ethg++ <--> HighSpeedLink <--> dnsLocal.ethg++;
        dnsLocal.ethg++ <--> LowSpeedLink <--> dnsRoot.ethg++;
}