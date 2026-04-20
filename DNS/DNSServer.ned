import inet.applications.contract.IApp;

// Acts as a domain name resolver node
simple DNSServer like IApp
{
    parameters:
        // Caching capabilities for hierarchical topologies
        bool useCache = default(true);
        
        // Time to live attached to positive responses (in seconds)
        int defaultTtl = default(10);

        // XML data source containing authoritative records
        xml databaseConfig;
        
        // Port to bind to
        int bindPort = default(53);

        // Upper-level DNS server configurations
        bool isHierarchical = default(false);
        string parentIpAddress = default("");
        int parentPort = default(53);

        // Simulated processing delays
        double minProcessingTime @unit(s) = default(1ms);
        double maxProcessingTime @unit(s) = default(5ms);

        @display("i=block/app");

    gates:
        output socketOut;
        input socketIn;
}