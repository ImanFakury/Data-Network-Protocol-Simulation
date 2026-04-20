import inet.applications.contract.IApp;

// Initiates DNS queries to a specified server
simple DNSClient like IApp
{
    parameters:
        // When to send the first query
        double bootTime @unit(s) = default(1s);
        
        // The domain to resolve
        string domainName;

        // Destination server details
        string targetServerIp;
        int targetServerPort = default(53);

        // Local binding port (-1 for ephemeral)
        int bindPort = default(-1);

        // --- BONUS INTEGRATION PARAMETERS ---
        bool triggerFtp = default(false);
        string ftpModulePath = default("^.app[1]");

        @display("i=block/app");

    gates:
        output socketOut;
        input socketIn;
}