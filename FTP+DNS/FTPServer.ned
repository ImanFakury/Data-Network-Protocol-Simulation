import inet.applications.contract.IApp;

simple FtpServer like IApp
{
    parameters:
        int controlPort = default(21);

    gates:
        input socketIn;
        output socketOut;
}