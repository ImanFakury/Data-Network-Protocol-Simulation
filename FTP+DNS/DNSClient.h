#pragma once

#include <vector>
#include <string>
#include <map>

#include "inet/networklayer/contract/ipv4/Ipv4Address.h"
#include "inet/common/packet/Packet.h"
#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3Address.h"

using namespace omnetpp;

class DNSClient : public inet::ApplicationBase, public inet::UdpSocket::ICallback
{
  protected:
    // Config parameters
    std::string targetDomain;
    std::string srvIpString;
    int srvPort = 53;
    int localBindPort = -1;
    simtime_t startDelay;

    bool ftpTriggered = false; // Prevents triggering FTP multiple times on cache refresh

    // Networking
    inet::L3Address resolvedSrvAddr;
    inet::UdpSocket udpSocket;

    // Timer events
    cMessage *evtRefresh = nullptr;
    cMessage *evtStart = nullptr;

    // Local Memory Cache
    struct ResolvedEntry {
        inet::Ipv4Address resolvedIp;
        uint32_t lifetimeSecs = 0;
        simtime_t expirationTime;
    };
    std::map<std::string, ResolvedEntry> localCache;

  protected:
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void finish() override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void initialize(int stage) override;

    virtual void handleStopOperation(inet::LifecycleOperation *operation) override;
    virtual void handleCrashOperation(inet::LifecycleOperation *operation) override;
    virtual void handleStartOperation(inet::LifecycleOperation *operation) override;

    // Socket callbacks
    virtual void socketClosed(inet::UdpSocket *sock) override;
    virtual void socketErrorArrived(inet::UdpSocket *sock, inet::Indication *ind) override;
    virtual void socketDataArrived(inet::UdpSocket *sock, inet::Packet *pkt) override;

  private:
    void dispatchQuery(const std::string& target);
    void planNextRefresh(simtime_t triggerTime);

    // Byte array helpers
    static uint32_t fetch32(const std::vector<uint8_t>& buf, size_t pos);
    static uint16_t fetch16(const std::vector<uint8_t>& buf, size_t pos);
    static void push32(std::vector<uint8_t>& buf, uint32_t val);
    static void push16(std::vector<uint8_t>& buf, uint16_t val);

    // Protocol formatters
    std::vector<uint8_t> constructDnsMessage(uint16_t trxId, const std::string& domainStr);
    std::vector<uint8_t> encodeDomainFormat(const std::string& domainStr);

    // Parsers
    std::string extractDomain(const std::vector<uint8_t>& payload, size_t& cursor, int recursionLevel = 0);
    bool decodeServerReply(const std::vector<uint8_t>& rawData, inet::Ipv4Address& parsedIp, uint32_t& parsedTtl, uint8_t& parsedRcode);
};
