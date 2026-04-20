#pragma once

#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/tcp/TcpSocket.h"
#include "inet/networklayer/common/L3Address.h"
#include <fstream>
#include <string>

using namespace omnetpp;

class FtpClient : public inet::ApplicationBase, public inet::TcpSocket::ICallback
{
  protected:
    inet::TcpSocket controlSocket;
    inet::TcpSocket dataListenerSocket;
    inet::TcpSocket *dataSocket = nullptr;

    inet::L3Address serverAddr;

    int controlPort = 21;
    std::string username;
    std::string filename;
    std::string ftpCommand;
    int dataPort = 2020;

    std::ofstream outFile;

  protected:
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;

    virtual void socketEstablished(inet::TcpSocket *socket) override;
    virtual void socketDataArrived(inet::TcpSocket *socket, inet::Packet *packet, bool urgent) override;
    virtual void socketAvailable(inet::TcpSocket *socket, inet::TcpAvailableInfo *availableInfo) override;
    virtual void socketPeerClosed(inet::TcpSocket *socket) override;

    virtual void handleStartOperation(inet::LifecycleOperation *) override {}
    virtual void handleStopOperation(inet::LifecycleOperation *) override {}
    virtual void handleCrashOperation(inet::LifecycleOperation *) override {}
    virtual void socketClosed(inet::TcpSocket *) override {}
    virtual void socketFailure(inet::TcpSocket *, int) override {}
    virtual void socketStatusArrived(inet::TcpSocket *, inet::TcpStatusInfo *) override {}
    virtual void socketDeleted(inet::TcpSocket *) override {}

  protected:
    void sendControlCommand(const std::string& cmd, const char *name);
    std::string getLocalIpv4();
    void sendFile();
};
