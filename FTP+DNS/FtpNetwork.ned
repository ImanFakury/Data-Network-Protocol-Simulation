import inet.node.inet.StandardHost;
import inet.node.inet.Router;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;

network FtpNetwork
{
    submodules:
        configurator: Ipv4NetworkConfigurator {}
        clientHost: StandardHost {}
        serverHost: StandardHost {}
        router: Router {}

    connections:
        clientHost.pppg++ <--> { datarate = 10Mbps; delay = 1ms; } <--> router.pppg++;
        serverHost.pppg++ <--> { datarate = 10Mbps; delay = 1ms; } <--> router.pppg++;
}