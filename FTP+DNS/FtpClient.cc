#include "FtpClient.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "inet/common/InitStages.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/tcp/TcpCommand_m.h"
#include <vector>

Define_Module(FtpClient);
using namespace inet;

void FtpClient::initialize(int stage) {
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        controlPort = par("controlPort");
        username = par("username").stdstringValue();
        filename = par("filename").stdstringValue();
        ftpCommand = par("ftpCommand").stdstringValue();
        dataPort = par("dataPort");
    }

    if (stage == INITSTAGE_APPLICATION_LAYER) {
        controlSocket.setOutputGate(gate("socketOut"));
        controlSocket.setCallback(this);

        // Active mode: client listens for incoming DATA connections
        dataListenerSocket.setOutputGate(gate("socketOut"));
        dataListenerSocket.setCallback(this);
        dataListenerSocket.bind(dataPort);
        dataListenerSocket.listen();

        // Check if we should connect immediately or wait for DNS
        if (!par("waitForDns").boolValue()) {
            L3AddressResolver resolver;
            serverAddr = resolver.resolve(par("serverAddress"));
            controlSocket.connect(serverAddr, controlPort);
        } else {
            EV_INFO << "FTP Client initialized in Standby Mode. Waiting for DNS resolution...\n";
        }
    }
}

void FtpClient::connectToServer(inet::Ipv4Address ip) {
    Enter_Method_Silent(); // <--- THIS IS THE MAGIC FIX

    serverAddr = ip;
    EV_INFO << "Received Target IP from DNS. Initiating FTP Control Connection to: " << serverAddr.str() << "\n";
    controlSocket.connect(serverAddr, controlPort);
}

void FtpClient::handleMessageWhenUp(cMessage *msg) {
    if (controlSocket.belongsToSocket(msg)) { controlSocket.processMessage(msg); return; }
    if (dataListenerSocket.belongsToSocket(msg)) { dataListenerSocket.processMessage(msg); return; }
    if (dataSocket && dataSocket->belongsToSocket(msg)) { dataSocket->processMessage(msg); return; }
    delete msg;
}

void FtpClient::socketEstablished(TcpSocket *socket) {
    if (socket == &controlSocket) {
        EV_INFO << "Control connection established.\n";
    }
}

void FtpClient::socketAvailable(TcpSocket *socket, TcpAvailableInfo *availableInfo) {
    if (socket != &dataListenerSocket)
        return;

    EV_INFO << "Incoming DATA connection available, newSocketId="
            << availableInfo->getNewSocketId() << "\n";

    if (dataSocket)
        delete dataSocket;

    dataSocket = new TcpSocket(availableInfo);
    dataSocket->setOutputGate(gate("socketOut"));
    dataSocket->setCallback(this);

    dataListenerSocket.accept(availableInfo->getNewSocketId());

    if (ftpCommand == "STOR") {
        EV_INFO << "Data connection accepted for STOR. Sending file...\n";
        sendFile();
    }
}

void FtpClient::socketDataArrived(TcpSocket *socket, Packet *packet, bool) {
    auto bytesChunk = packet->peekDataAsBytes();
    const auto& bytes = bytesChunk->getBytes();

    if (socket == &controlSocket) {
        std::string received(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        EV_INFO << "CONTROL received: " << received << "\n";

        if (received.rfind("220", 0) == 0) {
            sendControlCommand("USER " + username + "\r\n", "USER");
        }
        else if (received.rfind("230", 0) == 0) {
            std::string ip = getLocalIpv4();
            int a, b, c, d;
            sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d);

            char buffer[128];
            sprintf(buffer, "PORT %d,%d,%d,%d,%d,%d\r\n",
                    a, b, c, d, dataPort / 256, dataPort % 256);

            sendControlCommand(buffer, "PORT");
        }
        else if (received.rfind("200", 0) == 0) {
            sendControlCommand(ftpCommand + " " + filename + "\r\n", ftpCommand.c_str());
        }
    }
    else if (dataSocket && socket == dataSocket) {
        if (!outFile.is_open())
            outFile.open("client_received_" + filename, std::ios::binary);

        outFile.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    delete packet;
}

void FtpClient::sendControlCommand(const std::string& cmd, const char *name) {
    auto payload = makeShared<BytesChunk>(std::vector<uint8_t>(cmd.begin(), cmd.end()));
    auto packet = new Packet(name);
    packet->insertAtBack(payload);
    controlSocket.send(packet);
}

std::string FtpClient::getLocalIpv4() {
    L3AddressResolver resolver;
    return resolver.addressOf(getParentModule(), L3AddressResolver::ADDR_IPv4).str();
}

void FtpClient::sendFile() {
    if (!dataSocket) return;

    std::ifstream inFile(filename, std::ios::binary);
    if (!inFile) {
        EV_WARN << "Client file not found: " << filename << "\n";
        dataSocket->close();
        return;
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(inFile)),
                                 std::istreambuf_iterator<char>());

    auto packet = new Packet("file_data");
    packet->insertAtBack(makeShared<BytesChunk>(buffer));
    dataSocket->send(packet);
    dataSocket->close();
}

void FtpClient::socketPeerClosed(TcpSocket *socket) {
    if (dataSocket && socket == dataSocket) {
        if (outFile.is_open())
            outFile.close();
    }
    socket->close();
}

void FtpClient::finish() {
    if (outFile.is_open()) outFile.close();
    if (dataSocket) delete dataSocket;
}
