
#include "FTPParser.hpp"

using namespace GView::Type::PCAP;

PayloadDataParserInterface* FTP::FTPParser::ParsePayload(
      const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface)
{
    const auto connPayload = payloadInformation.payload;
    if (payloadInformation.payload->size < 10)
        return nullptr;

    auto& var = payloadInformation.payload->location;
    if (memcmp(payloadInformation.payload->location, "220", 3) != 0 && memcmp(payloadInformation.payload->location, "120", 3) != 0 &&
              memcmp(payloadInformation.payload->location,
        "421", 3) != 0 && memcmp(payloadInformation.payload->location, "221", 3) != 0)
        return nullptr;

    uint32 src = 0;
    for (auto& packet : *payloadInformation.packets) {
        if (packet.packetData.linkLayer.has_value()) {
            if (packet.packetData.linkLayer->type == LinkType::IPV4) {
                auto ipv4 = (IPv4Header*) packet.packetData.linkLayer->header;
            }
        }
        if (packet.packetData.transportLayer.has_value()) {
            if (packet.packetData.transportLayer->transportLayer == IP_Protocol::TCP) {
                auto tcp = (TCPHeader*) packet.packetData.transportLayer->transportLayerHeader;
            }
        }

        if (packet.payload.size > 0) //current payload has payload
        {
            //..
            packet.payload.location;
        }
    }

    

    callbackInterface->AddConnectionSummary("FTP initial connection");
    callbackInterface->AddConnectionAppLayerName("FTP");

    auto& applicationLayers = callbackInterface->GetApplicationLayers();

    StreamTcpLayer layer = {};
    const char* name     = "DemoLayer";
    layer.name = std::make_unique<uint8[]>(strlen(name) +1);
    memcpy(layer.name.get(), name, strlen(name) + 1);
    applicationLayers.emplace_back(std::move(layer));

    StreamTcpLayer layer2 = {};
    const char* name2           = "CanBeOpened";
    layer2.name                 = std::make_unique<uint8[]>(strlen(name2) + 1);
    memcpy(layer2.name.get(), name2, strlen(name2) + 1);

    const char* data = "user \"Some\" has connected \nthe file \"music.mp3\" has been downloaded";
    layer2.payload.size = strlen(data) + 1;
    layer2.payload.location = new uint8[layer2.payload.size + 1];
    memcpy(layer2.payload.location, data, layer2.payload.size + 1);

    applicationLayers.emplace_back(std::move(layer2));


    const uint8* startPtr = connPayload->location;
    const uint8* startline = connPayload->location;
    const uint8* endPtr   = connPayload->location + connPayload->size;
    
    bool command = 0;
    while (startPtr < endPtr) {
        if (*startPtr == 0x0D || *startPtr == 0x0a) {
            
            if (startPtr - startline > 0) {
                unsigned char* sequence = new unsigned char[startPtr - startline];
                std::memcpy(sequence, startline, startPtr - startline);
                sequence[startPtr - startline + 1] = '\0';
                startline                          = startPtr + 2;
                if (memcmp(sequence, "USER", 4) == 0) {
                    StreamTcpLayer layer = {};
                    const char* name     = "Username: ";
                    unsigned char* onlyName = sequence + 5;

                    size_t nameLength         = std::strlen(name);
                    size_t modifiedDataLength = std::strlen(reinterpret_cast<const char*>(onlyName));

                    size_t totalLength = nameLength + modifiedDataLength + 1;
                    char* concatenated = new char[totalLength];
                    std::memcpy(concatenated, name, nameLength);
                    std::memcpy(concatenated + nameLength, onlyName, modifiedDataLength);
                    concatenated[totalLength - 1] = '\0';

                    layer.name = std::make_unique<uint8[]>(strlen(concatenated) + 1);
                    memcpy(layer.name.get(), concatenated, strlen(concatenated) + 1);
                    applicationLayers.emplace_back(std::move(layer));
                }

            }
        
        }
        startPtr++;
    }
    return this;
}
