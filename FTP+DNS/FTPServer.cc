#include "FtpServer.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "inet/common/InitStages.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/tcp/TcpCommand_m.h"

Define_Module(FtpServer);
using namespace inet;

void FtpServer::initialize(int stage) {
    ApplicationBase::initialize(stage);
    if (stage == INITSTAGE_LOCAL)
        controlPort = par("controlPort");

    if (stage == INITSTAGE_APPLICATION_LAYER) {
        listenSocket.setOutputGate(gate("socketOut"));
        listenSocket.setCallback(this);
        listenSocket.bind(controlPort);
        listenSocket.listen();
    }
}

void FtpServer::handleMessageWhenUp(cMessage *msg) {
    if (listenSocket.belongsToSocket(msg)) { listenSocket.processMessage(msg); return; }
    if (controlSocket && controlSocket->belongsToSocket(msg)) { controlSocket->processMessage(msg); return; }
    if (dataSocket.belongsToSocket(msg)) { dataSocket.processMessage(msg); return; }
    delete msg;
}

void FtpServer::socketAvailable(TcpSocket *socket, TcpAvailableInfo *availableInfo) {
    if (socket != &listenSocket)
        return;

    EV_INFO << "Incoming CONTROL connection available, newSocketId="
            << availableInfo->getNewSocketId() << "\n";

    // IMPORTANT: create the forked socket USING availableInfo (so connId matches newSocketId)
    if (controlSocket)
        delete controlSocket;

    controlSocket = new TcpSocket(availableInfo);
    controlSocket->setOutputGate(gate("socketOut"));
    controlSocket->setCallback(this);

    // IMPORTANT: accept must be called on the LISTEN socket
    listenSocket.accept(availableInfo->getNewSocketId());
}

void FtpServer::socketEstablished(TcpSocket *socket) {
    if (socket == controlSocket) {
        EV_INFO << "Control channel established. Sending greeting...\n";
        sendReply(controlSocket, "220 FTP Server Ready\r\n", "220");
    }
    else if (socket == &dataSocket && transferMode == "RETR") {
        EV_INFO << "Data channel established for RETR. Sending file...\n";
        sendFile();
    }
}

void FtpServer::socketDataArrived(TcpSocket *socket, Packet *packet, bool) {
    auto bytesChunk = packet->peekDataAsBytes();
    const auto& bytes = bytesChunk->getBytes();

    if (socket == controlSocket) {
        std::string received(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        EV_INFO << "CONTROL received: " << received << "\n";

        if (received.rfind("USER", 0) == 0) {
            sendReply(socket, "230 Logged in\r\n", "230");
        }
        else if (received.rfind("PORT", 0) == 0) {
            int a,b,c,d,p1,p2;
            if (sscanf(received.c_str(), "PORT %d,%d,%d,%d,%d,%d", &a,&b,&c,&d,&p1,&p2) == 6) {
                char ip[32];
                sprintf(ip, "%d.%d.%d.%d", a,b,c,d);
                clientDataAddr = L3AddressResolver().resolve(ip);
                clientDataPort = p1 * 256 + p2;

                EV_INFO << "Parsed PORT: " << ip << ":" << clientDataPort << "\n";
                sendReply(socket, "200 PORT OK\r\n", "200");
            }
            else {
                sendReply(socket, "501 Syntax error in PORT\r\n", "501");
            }
        }
        else if (received.rfind("RETR", 0) == 0 || received.rfind("STOR", 0) == 0) {
            transferMode = received.substr(0, 4);

            currentFilename = received.substr(5);
            auto pos = currentFilename.find_last_not_of("\r\n");
            if (pos != std::string::npos) currentFilename.erase(pos + 1);
            else currentFilename.clear();

            EV_INFO << "Command: " << transferMode << " file=" << currentFilename << "\n";

            if (clientDataPort < 0) {
                sendReply(socket, "503 Bad sequence (PORT required)\r\n", "503");
            } else {
                sendReply(socket, "150 Opening data connection\r\n", "150");
                dataSocket.setOutputGate(gate("socketOut"));
                dataSocket.setCallback(this);
                dataSocket.connect(clientDataAddr, clientDataPort);
            }
        }
        else {
            sendReply(socket, "502 Command not implemented\r\n", "502");
        }
    }
    else if (socket == &dataSocket) {
        // Data for STOR arrives here
        if (!outFile.is_open())
            outFile.open("server_received_" + currentFilename, std::ios::binary);

        outFile.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    }

    delete packet;
}

void FtpServer::sendFile() {
    std::ifstream inFile(currentFilename, std::ios::binary);
    if (!inFile) {
        // Requirement: send error if file missing
        sendReply(controlSocket, "550 File not found\r\n", "550");
        dataSocket.close();
        return;
    }

    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(inFile)),
                                 std::istreambuf_iterator<char>());

    auto packet = new Packet("file_data");
    packet->insertAtBack(makeShared<BytesChunk>(buffer));
    dataSocket.send(packet);
    dataSocket.close();

    sendReply(controlSocket, "226 Transfer complete\r\n", "226");
}

void FtpServer::sendReply(TcpSocket *socket, const std::string& text, const char *name) {
    auto payload = makeShared<BytesChunk>(std::vector<uint8_t>(text.begin(), text.end()));
    auto packet = new Packet(name);
    packet->insertAtBack(payload);
    socket->send(packet);
}

void FtpServer::socketPeerClosed(TcpSocket *socket) {
    if (socket == &dataSocket) {
        if (outFile.is_open())
            outFile.close();

        if (transferMode == "STOR")
            sendReply(controlSocket, "226 Transfer complete\r\n", "226");
    }
    socket->close();
}

void FtpServer::finish() {
    if (outFile.is_open()) outFile.close();
    if (controlSocket) delete controlSocket;
}
