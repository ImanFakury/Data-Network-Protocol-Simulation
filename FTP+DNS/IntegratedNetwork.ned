import inet.node.ethernet.Eth100M;
import inet.node.inet.StandardHost;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.ethernet.EthernetSwitch;

network IntegratedNetwork
{
    submodules:
        configurator: Ipv4NetworkConfigurator {}
        clientNode: StandardHost { @display("p=100,250"); }
        dnsNode: StandardHost { @display("p=300,100"); }
        ftpNode: StandardHost { @display("p=300,400"); }
        switch: EthernetSwitch { @display("p=200,250"); }

    connections:
        clientNode.ethg++ <--> Eth100M <--> switch.ethg++;
        dnsNode.ethg++ <--> Eth100M <--> switch.ethg++;
        ftpNode.ethg++ <--> Eth100M <--> switch.ethg++;
}