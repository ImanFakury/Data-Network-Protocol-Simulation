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
        L3AddressResolver resolver;
        serverAddr = resolver.resolve(par("serverAddress"));

        controlSocket.setOutputGate(gate("socketOut"));
        controlSocket.setCallback(this);
        controlSocket.connect(serverAddr, controlPort);

        // Active mode: client listens for incoming DATA connections
        dataListenerSocket.setOutputGate(gate("socketOut"));
        dataListenerSocket.setCallback(this);
        dataListenerSocket.bind(dataPort);
        dataListenerSocket.listen();
    }
}

void FtpClient::handleMessageWhenUp(cMessage *msg) {
    if (controlSocket.belongsToSocket(msg)) { controlSocket.processMessage(msg); return; }
    if (dataListenerSocket.belongsToSocket(msg)) { dataListenerSocket.processMessage(msg); return; }
    if (dataSocket && dataSocket->belongsToSocket(msg)) { dataSocket->processMessage(msg); return; }
    delete msg;
}

void FtpClient::socketEstablished(TcpSocket *socket) {
    // Only relevant for outbound connect sockets; accepted data sockets will not call this in your flow
    // For STOR, we actually start sending once the incoming data connection is accepted (see socketAvailable)
    if (socket == &controlSocket) {
        EV_INFO << "Control connection established.\n";
    }
}

void FtpClient::socketAvailable(TcpSocket *socket, TcpAvailableInfo *availableInfo) {
    if (socket != &dataListenerSocket)
        return;

    EV_INFO << "Incoming DATA connection available, newSocketId="
            << availableInfo->getNewSocketId() << "\n";

    // IMPORTANT: create the forked socket USING availableInfo (so connId matches newSocketId)
    if (dataSocket)
        delete dataSocket;

    dataSocket = new TcpSocket(availableInfo);
    dataSocket->setOutputGate(gate("socketOut"));
    dataSocket->setCallback(this);

    // IMPORTANT: accept must be called on the LISTEN socket
    dataListenerSocket.accept(availableInfo->getNewSocketId());

    // If we're uploading, send file once the data channel is ready (we can send immediately after accept)
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
        // Optional: if server sends 150/226/550 etc you could log/handle them
    }
    else if (dataSocket && socket == dataSocket) {
        // Data for RETR arrives here
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
    if (!dataSocket) {
        EV_WARN << "sendFile() called but dataSocket is null.\n";
        return;
    }

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
