import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.StandardHost;

network BasicNetwork
{
    types:
        channel StandardEth extends ned.DatarateChannel
        {
            delay = 1ms;
            datarate = 100Mbps;
        }

    submodules:
        hostClient: StandardHost {
            @display("p=100,200");
            numApps = 1;
            app[0].typename = "DNSClient";
        }
        
        hostServer: StandardHost {
            @display("p=300,200");
            numApps = 1;
            app[0].typename = "DNSServer";
        }

        configurator: Ipv4NetworkConfigurator {
            @display("p=100,50");
        }

    connections:
        hostClient.ethg++ <--> StandardEth <--> hostServer.ethg++;
}