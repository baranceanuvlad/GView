
#include "FTPParser.hpp"

using namespace GView::Type::PCAP;

PayloadDataParserInterface* FTP::FTPParser::ParsePayload(
      const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface)
{
    const auto connPayload = payloadInformation.payload;
    if (payloadInformation.payload->size < 10)
        return nullptr;

    if (memcmp(payloadInformation.payload->location, "220", 3) != 0)
        return nullptr;

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
    return this;
}
