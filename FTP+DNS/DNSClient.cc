#include "DNSClient.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "FtpClient.h"
Define_Module(DNSClient);

using namespace inet;

void DNSClient::initialize(int currentStage)
{
    ApplicationBase::initialize(currentStage);

    if (currentStage == INITSTAGE_LOCAL) {
        startDelay = par("bootTime");
        targetDomain = par("domainName").stdstringValue();
        srvPort = par("targetServerPort");
        srvIpString = par("targetServerIp").stdstringValue();
        localBindPort = par("bindPort");

        evtRefresh = new cMessage("msgRefreshDns");
        evtStart = new cMessage("msgStartDns");

        // BONUS INTEGRATION: register signal
     //   dnsResolvedSignal = registerSignal("dnsResolved");
    }
    else if (currentStage == INITSTAGE_APPLICATION_LAYER) {
        udpSocket.setCallback(this);
        udpSocket.setOutputGate(gate("socketOut"));

        int activePort = (localBindPort >= 0) ? localBindPort : 0;
        udpSocket.bind(activePort);

        resolvedSrvAddr = L3AddressResolver().resolve(srvIpString.c_str());

        scheduleAt(simTime() + startDelay, evtStart);
    }
}

void DNSClient::handleStartOperation(LifecycleOperation *operation) { /* no-op */ }

void DNSClient::handleCrashOperation(LifecycleOperation *operation)
{
    cancelEvent(evtRefresh);
    cancelEvent(evtStart);
}

void DNSClient::handleStopOperation(LifecycleOperation *operation)
{
    cancelEvent(evtStart);
    cancelEvent(evtRefresh);
    udpSocket.close();
}

void DNSClient::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (msg == evtRefresh) {
            EV_INFO << "[Client-App] Cache record expired, sending fresh query for: " << targetDomain << "\n";
            dispatchQuery(targetDomain);
        }
        else if (msg == evtStart) {
            EV_INFO << "[Client-App] Booting sequence complete, firing first query for: " << targetDomain << "\n";
            dispatchQuery(targetDomain);
        }
        return;
    }

    udpSocket.processMessage(msg);
}

void DNSClient::socketDataArrived(UdpSocket *sock, Packet *pkt)
{
    auto chunkBytes = pkt->peekData<BytesChunk>();
    const auto& rawVec = chunkBytes->getBytes();

    uint8_t codeRet = 0;
    uint32_t timeToLive = 0;
    Ipv4Address addressFound;

    bool isSuccessful = decodeServerReply(rawVec, addressFound, timeToLive, codeRet);

    if (isSuccessful) {
        ResolvedEntry entryData;
        entryData.resolvedIp = addressFound;
        entryData.lifetimeSecs = timeToLive;
        entryData.expirationTime = simTime() + SimTime(timeToLive, SIMTIME_S);

        localCache[targetDomain] = entryData;

        EV_INFO << "[Client-App] Successfully mapped " << targetDomain << " to " << addressFound.str()
                << " | Valid for: " << timeToLive << "s (Drops at " << entryData.expirationTime << ")\n";

        planNextRefresh(entryData.expirationTime);

        // --- BONUS INTEGRATION LOGIC: WAKE UP FTP ---
        if (par("triggerFtp").boolValue() && !ftpTriggered) {
            ftpTriggered = true;
            // Directly grab app[1] (the FTP Client) on the same host
            cModule *ftpMod = getParentModule()->getSubmodule("app", 1);
            if (ftpMod) {
                FtpClient *ftpClient = dynamic_cast<FtpClient*>(ftpMod);
                if (ftpClient) {
                    EV_INFO << "[Client-App] Triggering FTP Client with resolved IP: " << addressFound.str() << "\n";
                    ftpClient->connectToServer(addressFound);
                } else {
                    EV_WARN << "[Client-App] Found app[1], but it is not FtpClient!\n";
                }
            } else {
                EV_WARN << "[Client-App] Integration mode active, but FTP module not found at app[1]!\n";
            }
        }
    }
    else {
        EV_WARN << "[Client-App] Query rejected or failed for " << targetDomain
                << " (RCODE: " << int(codeRet) << "). Aborting cache write.\n";
        cancelEvent(evtRefresh);
    }

    delete pkt;
}
void DNSClient::socketClosed(UdpSocket *sock)
{
    EV_INFO << "[Client-App] UDP Socket connection terminated.\n";
}

void DNSClient::socketErrorArrived(UdpSocket *sock, Indication *ind)
{
    EV_WARN << "[Client-App] UDP exception caught: " << ind->getName() << "\n";
    delete ind;
}

void DNSClient::finish()
{
    ApplicationBase::finish();
    cancelAndDelete(evtStart);
    cancelAndDelete(evtRefresh);
    evtRefresh = evtStart = nullptr;
}

void DNSClient::planNextRefresh(simtime_t triggerTime)
{
    cancelEvent(evtRefresh);
    scheduleAt(triggerTime + 1e-6, evtRefresh);
}

void DNSClient::dispatchQuery(const std::string& target)
{
    uint16_t reqId = (uint16_t)uniform(0, 65535);

    auto generatedPayload = constructDnsMessage(reqId, target);
    auto packetObj = new Packet(("Query-" + target).c_str());
    packetObj->insertAtBack(makeShared<BytesChunk>(generatedPayload));

    udpSocket.sendTo(packetObj, resolvedSrvAddr, srvPort);
}

std::vector<uint8_t> DNSClient::constructDnsMessage(uint16_t trxId, const std::string& domainStr)
{
    std::vector<uint8_t> buffer;
    buffer.reserve(64);

    push16(buffer, trxId);
    push16(buffer, 0x0100);
    push16(buffer, 1);
    push16(buffer, 0);
    push16(buffer, 0);
    push16(buffer, 0);

    auto qBytes = encodeDomainFormat(domainStr);
    buffer.insert(buffer.end(), qBytes.begin(), qBytes.end());
    push16(buffer, 1);
    push16(buffer, 1);

    return buffer;
}

std::vector<uint8_t> DNSClient::encodeDomainFormat(const std::string& domainStr)
{
    std::vector<uint8_t> encoded;
    size_t pointer = 0;
    while (true) {
        size_t dotPos = domainStr.find('.', pointer);
        std::string fragment = (dotPos == std::string::npos) ? domainStr.substr(pointer) : domainStr.substr(pointer, dotPos - pointer);
        encoded.push_back((uint8_t)fragment.size());
        encoded.insert(encoded.end(), fragment.begin(), fragment.end());
        if (dotPos == std::string::npos) break;
        pointer = dotPos + 1;
    }
    encoded.push_back(0);
    return encoded;
}

void DNSClient::push16(std::vector<uint8_t>& buf, uint16_t val)
{
    buf.push_back((uint8_t)((val >> 8) & 0xFF));
    buf.push_back((uint8_t)(val & 0xFF));
}

void DNSClient::push32(std::vector<uint8_t>& buf, uint32_t val)
{
    buf.push_back((uint8_t)((val >> 24) & 0xFF));
    buf.push_back((uint8_t)((val >> 16) & 0xFF));
    buf.push_back((uint8_t)((val >> 8) & 0xFF));
    buf.push_back((uint8_t)(val & 0xFF));
}

uint16_t DNSClient::fetch16(const std::vector<uint8_t>& buf, size_t pos)
{
    return (uint16_t(buf.at(pos)) << 8) | uint16_t(buf.at(pos + 1));
}

uint32_t DNSClient::fetch32(const std::vector<uint8_t>& buf, size_t pos)
{
    return (uint32_t(buf.at(pos)) << 24) | (uint32_t(buf.at(pos + 1)) << 16) | (uint32_t(buf.at(pos + 2)) << 8) | uint32_t(buf.at(pos + 3));
}

std::string DNSClient::extractDomain(const std::vector<uint8_t>& payload, size_t& cursor, int recursionLevel)
{
    if (recursionLevel > 10) return "";

    std::string resultStr;
    while (cursor < payload.size()) {
        uint8_t segmentLen = payload[cursor];

        if ((segmentLen & 0xC0) == 0xC0) {
            if (cursor + 1 >= payload.size()) return resultStr;
            uint16_t jumpTarget = ((uint16_t)(segmentLen & 0x3F) << 8) | payload[cursor + 1];
            cursor += 2;

            size_t newCursor = jumpTarget;
            std::string nested = extractDomain(payload, newCursor, recursionLevel + 1);
            if (!resultStr.empty() && !nested.empty()) resultStr += ".";
            resultStr += nested;
            return resultStr;
        }

        if (segmentLen == 0) {
            cursor += 1;
            return resultStr;
        }

        cursor += 1;
        if (cursor + segmentLen > payload.size()) return resultStr;

        if (!resultStr.empty()) resultStr += ".";
        resultStr.append((const char*)&payload[cursor], (size_t)segmentLen);
        cursor += segmentLen;
    }
    return resultStr;
}

bool DNSClient::decodeServerReply(const std::vector<uint8_t>& rawData, Ipv4Address& parsedIp, uint32_t& parsedTtl, uint8_t& parsedRcode)
{
    if (rawData.size() < 12) return false;

    uint16_t headFlags = fetch16(rawData, 2);
    parsedRcode = uint8_t(headFlags & 0x0F);

    uint16_t qCount = fetch16(rawData, 4);
    uint16_t aCount = fetch16(rawData, 6);

    bool isResp = (headFlags & 0x8000) != 0;
    if (!isResp || parsedRcode != 0) return false;

    size_t cursor = 12;
    for (uint16_t i = 0; i < qCount; i++) {
        (void)extractDomain(rawData, cursor);
        if (cursor + 4 > rawData.size()) return false;
        cursor += 4;
    }

    for (uint16_t i = 0; i < aCount; i++) {
        (void)extractDomain(rawData, cursor);
        if (cursor + 10 > rawData.size()) return false;

        uint16_t rType = fetch16(rawData, cursor); cursor += 2;
        uint16_t rClass = fetch16(rawData, cursor); cursor += 2;
        uint32_t rTtl = fetch32(rawData, cursor); cursor += 4;
        uint16_t rLen = fetch16(rawData, cursor); cursor += 2;

        if (cursor + rLen > rawData.size()) return false;

        if (rType == 1 && rClass == 1 && rLen == 4) {
            parsedTtl = rTtl;
            parsedIp = Ipv4Address(rawData[cursor], rawData[cursor+1], rawData[cursor+2], rawData[cursor+3]);
            return true;
        }
        cursor += rLen;
    }

    return false;
}
