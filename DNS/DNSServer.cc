#include "DNSServer.h"

Define_Module(DNSServer);

using namespace inet;

void DNSServer::initialize(int stageVal)
{
    ApplicationBase::initialize(stageVal);

    if (stageVal == INITSTAGE_LOCAL) {
        bindingPort = par("bindPort");
        xmlSource = par("databaseConfig").xmlValue();

        minProcessDelay = par("minProcessingTime");
        maxProcessDelay = par("maxProcessingTime");

        isHierarchicalMode = par("isHierarchical");
        allowCaching = par("useCache");
        parentIpStr = par("parentIpAddress").stdstringValue();
        parentPort = par("parentPort");

        fixedTtl = par("defaultTtl");
    }
    else if (stageVal == INITSTAGE_APPLICATION_LAYER) {
        udpSocket.setOutputGate(gate("socketOut"));
        udpSocket.setCallback(this);
        udpSocket.bind(bindingPort);

        if (isHierarchicalMode && !parentIpStr.empty()) {
            parentAddress = L3AddressResolver().resolve(parentIpStr.c_str());
        }

        populateDatabase();
    }
}

void DNSServer::handleCrashOperation(LifecycleOperation *operation)
{
    cacheStorage.clear();
    waitingQueries.clear();
}

void DNSServer::handleStopOperation(LifecycleOperation *operation)
{
    udpSocket.close();
    cacheStorage.clear();
    waitingQueries.clear();
}

void DNSServer::handleStartOperation(LifecycleOperation *operation) { /* no-op */ }

void DNSServer::finish()
{
    ApplicationBase::finish();
}

void DNSServer::handleMessageWhenUp(cMessage *msg)
{
    // Delays are processed via self-messages
    if (msg->isSelfMessage()) {
        auto *payloadData = static_cast<std::vector<uint8_t>*>(msg->getContextPointer());
        if (!payloadData) { delete msg; return; }

        if (strcmp(msg->getName(), "cmdRelayUp") == 0) {
            dispatchDatagram("FwdReq", *payloadData, parentAddress, parentPort);
        }
        else {
            int tgtPort = (int)msg->par("tgtPort").longValue();
            const char *tgtStr = msg->par("tgtAddr").stringValue();

            L3Address resolvedTgt = L3AddressResolver().resolve(tgtStr);
            dispatchDatagram("DnsAns", *payloadData, resolvedTgt, tgtPort);
        }

        delete payloadData;
        delete msg;
        return;
    }

    udpSocket.processMessage(msg);
}

void DNSServer::socketErrorArrived(UdpSocket *sock, Indication *ind)
{
    EV_WARN << "[Serv-App] Sockets error caught: " << ind->getName() << "\n";
    delete ind;
}

void DNSServer::socketClosed(UdpSocket *sock)
{
    EV_INFO << "[Serv-App] Disconnected active sockets.\n";
}

void DNSServer::populateDatabase()
{
    dbRecords.clear();
    if (!xmlSource) {
        EV_WARN << "[Serv-App] No database XML linked! Operating strictly on cache/forwarding.\n";
        return;
    }

    for (cXMLElement *node = xmlSource->getFirstChild(); node; node = node->getNextSibling()) {
        if (strcmp(node->getTagName(), "record") == 0) {
            const char *attrName = node->getAttribute("name");
            const char *attrIp = node->getAttribute("ip");
            if (attrIp && attrName) {
                dbRecords[std::string(attrName)] = Ipv4Address(attrIp);
            }
        }
    }

    EV_INFO << "[Serv-App] Loaded " << dbRecords.size() << " static entries into memory.\n";
}

bool DNSServer::findInDatabase(const std::string& domainStr, Ipv4Address& outputIp) const
{
    auto iter = dbRecords.find(domainStr);
    if (iter == dbRecords.end()) return false;
    outputIp = iter->second;
    return true;
}

bool DNSServer::findInCache(const std::string& domainStr, Ipv4Address& outputIp) const
{
    auto iter = cacheStorage.find(domainStr);
    if (iter == cacheStorage.end()) return false;
    if (simTime() >= iter->second.dropTime) return false;
    outputIp = iter->second.targetIp;
    return true;
}

void DNSServer::writeToCache(const std::string& domainStr, const Ipv4Address& ipVal, uint32_t ttlVal)
{
    if (!allowCaching) return;
    TtlCacheEntry cEntry;
    cEntry.targetIp = ipVal;
    cEntry.ttlLimit = ttlVal;
    cEntry.dropTime = simTime() + SimTime(ttlVal, SIMTIME_S);
    cacheStorage[domainStr] = cEntry;
}

simtime_t DNSServer::calculateComputeDelay() const
{
    if (maxProcessDelay <= minProcessDelay) return minProcessDelay;
    return uniform(minProcessDelay.dbl(), maxProcessDelay.dbl());
}

void DNSServer::socketDataArrived(UdpSocket *sock, Packet *pkt)
{
    int fromPort = pkt->getTag<L4PortInd>()->getSrcPort();
    auto fromIp = pkt->getTag<L3AddressInd>()->getSrcAddress();

    auto chunk = pkt->peekData<BytesChunk>();
    const auto& byteData = chunk->getBytes();

    bool isReply = false;
    uint16_t txId = 0;
    std::string queryTarget;
    uint8_t retCd = 0;

    if (!inspectIncomingPkt(byteData, txId, isReply, retCd, queryTarget)) {
        EV_WARN << "[Serv-App] Corrupted payload dropped.\n";
        delete pkt;
        return;
    }

    if (isReply) {
        auto iter = waitingQueries.find(txId);
        if (iter != waitingQueries.end()) {
            if (retCd == 0) {
                // Parse out the Answer to cache it
                size_t offsetCur = 12;
                uint16_t qs = extract16(byteData, 4);
                uint16_t ans = extract16(byteData, 6);

                for (uint16_t n = 0; n < qs; n++) {
                    (void)unwrapDomainStr(byteData, offsetCur);
                    offsetCur += 4;
                }

                for (uint16_t n = 0; n < ans; n++) {
                    (void)unwrapDomainStr(byteData, offsetCur);
                    if (offsetCur + 10 > byteData.size()) break;

                    uint16_t tType = extract16(byteData, offsetCur); offsetCur += 2;
                    uint16_t tClass = extract16(byteData, offsetCur); offsetCur += 2;
                    uint32_t tTtl = extract32(byteData, offsetCur); offsetCur += 4;
                    uint16_t tLen = extract16(byteData, offsetCur); offsetCur += 2;

                    if (tType == 1 && tClass == 1 && tLen == 4 && offsetCur + 4 <= byteData.size()) {
                        Ipv4Address rIp(byteData[offsetCur], byteData[offsetCur+1], byteData[offsetCur+2], byteData[offsetCur+3]);
                        writeToCache(iter->second.requestedDomain, rIp, tTtl);
                        break;
                    }
                    offsetCur += tLen;
                }
            }

            dispatchDatagram("ProxyRep", byteData, iter->second.originClient, iter->second.originPort);
            waitingQueries.erase(iter);
        }

        delete pkt;
        return;
    }

    EV_INFO << "[Serv-App] Query IN >> ID=" << txId << " Domain=" << queryTarget
            << " Via=" << fromIp << ":" << fromPort << "\n";

    Ipv4Address resolvedAddr;
    bool resolutionSuccess = false;

    if (findInCache(queryTarget, resolvedAddr)) {
        resolutionSuccess = true;
        EV_INFO << "[Serv-App] Result pulled from CACHE >> " << queryTarget << " = " << resolvedAddr << "\n";
    }
    else if (findInDatabase(queryTarget, resolvedAddr)) {
        resolutionSuccess = true;
        EV_INFO << "[Serv-App] Result pulled from LOCAL DB >> " << queryTarget << " = " << resolvedAddr << "\n";
    }

    simtime_t processTime = calculateComputeDelay();

    if (resolutionSuccess) {
        uint32_t ttlOutput = (uint32_t)fixedTtl;
        writeToCache(queryTarget, resolvedAddr, ttlOutput);

        auto payloadGen = createSuccessReply(byteData, txId, ttlOutput, resolvedAddr);

        auto asyncJob = new cMessage("sendSuccessEvent");
        asyncJob->setContextPointer(new std::vector<uint8_t>(std::move(payloadGen)));
        asyncJob->addPar("tgtAddr") = fromIp.str().c_str();
        asyncJob->addPar("tgtPort") = (long)fromPort;
        scheduleAt(simTime() + processTime, asyncJob);
    }
    else {
        if (isHierarchicalMode && !parentIpStr.empty()) {
            waitingQueries[txId] = InFlightQuery{fromIp, queryTarget, fromPort};

            auto asyncJob = new cMessage("cmdRelayUp");
            asyncJob->setContextPointer(new std::vector<uint8_t>(byteData));
            scheduleAt(simTime() + processTime, asyncJob);
        }
        else {
            auto payloadGen = createNxDomainReply(byteData, txId);

            auto asyncJob = new cMessage("sendFailEvent");
            asyncJob->setContextPointer(new std::vector<uint8_t>(std::move(payloadGen)));
            asyncJob->addPar("tgtAddr") = fromIp.str().c_str();
            asyncJob->addPar("tgtPort") = (long)fromPort;
            scheduleAt(simTime() + processTime, asyncJob);
        }
    }

    delete pkt;
}

void DNSServer::dispatchDatagram(const char *pktName, const std::vector<uint8_t>& rawBytes, const L3Address& targetDest, int targetPort)
{
    auto pkt = new Packet(pktName);
    pkt->insertAtBack(makeShared<BytesChunk>(rawBytes));
    udpSocket.sendTo(pkt, targetDest, targetPort);
}

bool DNSServer::inspectIncomingPkt(const std::vector<uint8_t>& rawData, uint16_t& parsedId, bool& isReplyFlag, uint8_t& retCode, std::string& domainStr)
{
    if (rawData.size() < 12) return false;

    parsedId = extract16(rawData, 0);

    uint16_t flagData = extract16(rawData, 2);
    isReplyFlag = (flagData & 0x8000) != 0;
    retCode = (uint8_t)(flagData & 0x0F);

    uint16_t queryCount = extract16(rawData, 4);
    if (queryCount < 1) return false;

    size_t cursor = 12;
    domainStr = unwrapDomainStr(rawData, cursor);
    return true;
}

std::string DNSServer::unwrapDomainStr(const std::vector<uint8_t>& payload, size_t& offsetPointer, int recursionLimit)
{
    if (recursionLimit > 10) return "";

    std::string construct;
    while (offsetPointer < payload.size()) {
        uint8_t curLen = payload[offsetPointer];

        if ((curLen & 0xC0) == 0xC0) {
            if (offsetPointer + 1 >= payload.size()) return construct;
            uint16_t ptrValue = ((uint16_t)(curLen & 0x3F) << 8) | payload[offsetPointer + 1];
            offsetPointer += 2;

            size_t ptrOffset = ptrValue;
            std::string subStr = unwrapDomainStr(payload, ptrOffset, recursionLimit + 1);
            if (!construct.empty() && !subStr.empty()) construct += ".";
            construct += subStr;
            return construct;
        }

        if (curLen == 0) {
            offsetPointer += 1;
            return construct;
        }

        offsetPointer += 1;
        if (offsetPointer + curLen > payload.size()) return construct;

        if (!construct.empty()) construct += ".";
        construct.append((const char*)&payload[offsetPointer], (size_t)curLen);
        offsetPointer += curLen;
    }
    return construct;
}

void DNSServer::write16(std::vector<uint8_t>& buf, uint16_t data)
{
    buf.push_back((uint8_t)((data >> 8) & 0xFF));
    buf.push_back((uint8_t)(data & 0xFF));
}

void DNSServer::write32(std::vector<uint8_t>& buf, uint32_t data)
{
    buf.push_back((uint8_t)((data >> 24) & 0xFF));
    buf.push_back((uint8_t)((data >> 16) & 0xFF));
    buf.push_back((uint8_t)((data >> 8) & 0xFF));
    buf.push_back((uint8_t)(data & 0xFF));
}

uint16_t DNSServer::extract16(const std::vector<uint8_t>& buf, size_t pos)
{
    return (uint16_t(buf.at(pos)) << 8) | uint16_t(buf.at(pos + 1));
}

uint32_t DNSServer::extract32(const std::vector<uint8_t>& buf, size_t pos)
{
    return (uint32_t(buf.at(pos)) << 24) | (uint32_t(buf.at(pos + 1)) << 16) | (uint32_t(buf.at(pos + 2)) << 8) | uint32_t(buf.at(pos + 3));
}

std::vector<uint8_t> DNSServer::createSuccessReply(const std::vector<uint8_t>& originalReq, uint16_t reqId, uint32_t respTtl, const Ipv4Address& respIp)
{
    std::vector<uint8_t> packetData = originalReq;
    if (packetData.size() < 12) packetData.resize(12);

    packetData[0] = (reqId >> 8) & 0xFF;
    packetData[1] = reqId & 0xFF;

    uint16_t standardFlags = 0x8180;
    packetData[2] = (standardFlags >> 8) & 0xFF;
    packetData[3] = standardFlags & 0xFF;

    packetData[4] = 0; packetData[5] = 1;
    packetData[6] = 0; packetData[7] = 1;
    packetData[8] = 0; packetData[9] = 0;
    packetData[10]= 0; packetData[11]=0;

    size_t qEnd = 12;
    (void)unwrapDomainStr(packetData, qEnd);
    qEnd += 4;
    packetData.resize(qEnd);

    write16(packetData, 0xC00C);
    write16(packetData, 1);
    write16(packetData, 1);
    write32(packetData, respTtl);
    write16(packetData, 4);

    packetData.push_back(respIp.getDByte(0));
    packetData.push_back(respIp.getDByte(1));
    packetData.push_back(respIp.getDByte(2));
    packetData.push_back(respIp.getDByte(3));

    return packetData;
}

std::vector<uint8_t> DNSServer::createNxDomainReply(const std::vector<uint8_t>& originalReq, uint16_t reqId)
{
    std::vector<uint8_t> packetData = originalReq;
    if (packetData.size() < 12) packetData.resize(12);

    packetData[0] = (reqId >> 8) & 0xFF;
    packetData[1] = reqId & 0xFF;

    uint16_t failFlags = 0x8183;
    packetData[2] = (failFlags >> 8) & 0xFF;
    packetData[3] = failFlags & 0xFF;

    packetData[6] = 0; packetData[7] = 0;
    packetData[8] = 0; packetData[9] = 0;
    packetData[10]= 0; packetData[11]=0;

    return packetData;
}
