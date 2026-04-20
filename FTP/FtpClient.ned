import inet.applications.contract.IApp;

simple FtpClient like IApp
{
    parameters:
        string serverAddress;     // IP of FTP server
        int controlPort = default(21);
        string username = default("user");
        string filename = default("data.txt");
        string ftpCommand = default("RETR"); // Can be RETR or STOR
        int dataPort = default(2020);

    gates:
        input socketIn;
        output socketOut;
}