#pragma once

#include <string>
#include <map>
#include <vector>

#include "inet/networklayer/contract/ipv4/Ipv4Address.h"
#include "inet/common/packet/Packet.h"
#include "inet/applications/base/ApplicationBase.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3Address.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

// Included tags for INET 4.5 standard
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/networklayer/common/L3AddressTag_m.h"

using namespace omnetpp;

class DNSServer : public inet::ApplicationBase, public inet::UdpSocket::ICallback
{
  protected:
    // Core Parameters
    int bindingPort = 53;
    int fixedTtl = 10;
    cXMLElement *xmlSource = nullptr;

    simtime_t minProcessDelay;
    simtime_t maxProcessDelay;

    bool allowCaching = true;
    bool isHierarchicalMode = false;

    inet::L3Address parentAddress;
    std::string parentIpStr;
    int parentPort = 53;

    inet::UdpSocket udpSocket;

    // Data structures
    std::map<std::string, inet::Ipv4Address> dbRecords;

    struct TtlCacheEntry {
        inet::Ipv4Address targetIp;
        uint32_t ttlLimit = 0;
        simtime_t dropTime;
    };
    std::map<std::string, TtlCacheEntry> cacheStorage;

    struct InFlightQuery {
        inet::L3Address originClient;
        std::string requestedDomain;
        int originPort = -1;
    };
    std::map<uint16_t, InFlightQuery> waitingQueries;

  protected:
    virtual int numInitStages() const override { return inet::NUM_INIT_STAGES; }
    virtual void finish() override;
    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;

    virtual void handleCrashOperation(inet::LifecycleOperation *operation) override;
    virtual void handleStopOperation(inet::LifecycleOperation *operation) override;
    virtual void handleStartOperation(inet::LifecycleOperation *operation) override;

    // INET Callbacks
    virtual void socketClosed(inet::UdpSocket *sock) override;
    virtual void socketDataArrived(inet::UdpSocket *sock, inet::Packet *pkt) override;
    virtual void socketErrorArrived(inet::UdpSocket *sock, inet::Indication *ind) override;

  private:
    simtime_t calculateComputeDelay() const;
    void populateDatabase();

    // Lookups
    bool findInCache(const std::string& domainStr, inet::Ipv4Address& outputIp) const;
    bool findInDatabase(const std::string& domainStr, inet::Ipv4Address& outputIp) const;
    void writeToCache(const std::string& domainStr, const inet::Ipv4Address& ipVal, uint32_t ttlVal);

    // Helpers
    static void write16(std::vector<uint8_t>& buf, uint16_t data);
    static void write32(std::vector<uint8_t>& buf, uint32_t data);
    static uint16_t extract16(const std::vector<uint8_t>& buf, size_t pos);
    static uint32_t extract32(const std::vector<uint8_t>& buf, size_t pos);

    // Packet Processing
    void dispatchDatagram(const char *pktName, const std::vector<uint8_t>& rawBytes, const inet::L3Address& targetDest, int targetPort);
    std::string unwrapDomainStr(const std::vector<uint8_t>& payload, size_t& offsetPointer, int recursionLimit = 0);
    bool inspectIncomingPkt(const std::vector<uint8_t>& rawData, uint16_t& parsedId, bool& isReplyFlag, uint8_t& retCode, std::string& domainStr);

    // Response Generators
    std::vector<uint8_t> createNxDomainReply(const std::vector<uint8_t>& originalReq, uint16_t reqId);
    std::vector<uint8_t> createSuccessReply(const std::vector<uint8_t>& originalReq, uint16_t reqId, uint32_t respTtl, const inet::Ipv4Address& respIp);
};
