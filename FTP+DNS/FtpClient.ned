import inet.applications.contract.IApp;

simple FtpClient like IApp
{
    parameters:
        string serverAddress = default("");  // IP of FTP server
        int controlPort = default(21);
        string username = default("user");
        string filename = default("data.txt");
        string ftpCommand = default("RETR"); // Can be RETR or STOR
        int dataPort = default(2020);
        
        // --- BONUS INTEGRATION PARAMETER ---
        bool waitForDns = default(false);

    gates:
        input socketIn;
        output socketOut;
}