#pragma once

#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/tcp/TcpSocket.h"
#include "inet/networklayer/common/L3Address.h"
#include <fstream>
#include <string>

using namespace omnetpp;

class FtpServer : public inet::ApplicationBase, public inet::TcpSocket::ICallback
{
  protected:
    inet::TcpSocket listenSocket;
    inet::TcpSocket *controlSocket = nullptr;
    inet::TcpSocket dataSocket;

    int controlPort = 21;
    inet::L3Address clientDataAddr;
    int clientDataPort = -1;
    std::string currentFilename;
    std::string transferMode;
    std::ofstream outFile;

  protected:
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;

    virtual void socketAvailable(inet::TcpSocket *socket, inet::TcpAvailableInfo *availableInfo) override;
    virtual void socketEstablished(inet::TcpSocket *socket) override;
    virtual void socketDataArrived(inet::TcpSocket *socket, inet::Packet *packet, bool urgent) override;
    virtual void socketPeerClosed(inet::TcpSocket *socket) override;

    virtual void handleStartOperation(inet::LifecycleOperation *) override {}
    virtual void handleStopOperation(inet::LifecycleOperation *) override {}
    virtual void handleCrashOperation(inet::LifecycleOperation *) override {}
    virtual void socketClosed(inet::TcpSocket *) override {}
    virtual void socketFailure(inet::TcpSocket *, int) override {}
    virtual void socketStatusArrived(inet::TcpSocket *, inet::TcpStatusInfo *) override {}
    virtual void socketDeleted(inet::TcpSocket *) override {}

    void sendReply(inet::TcpSocket *socket, const std::string& text, const char *name);
    void sendFile();
};
