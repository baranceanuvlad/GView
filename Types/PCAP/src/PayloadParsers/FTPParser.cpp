
#include "FTPParser.hpp"

using namespace GView::Type::PCAP;

void appendToUnsignedChar(unsigned char*& buffer, size_t& currentSize, const unsigned char* newData, size_t newDataSize)
{
    size_t newSize           = currentSize + newDataSize;
    unsigned char* newBuffer = new unsigned char[newSize];

    if (currentSize > 0) {
        std::memcpy(newBuffer, buffer, currentSize);
    }

    std::memcpy(newBuffer + currentSize, newData, newDataSize);
    delete[] buffer;
    buffer      = newBuffer;
    currentSize = newSize;
}

void appendToUnsignedChar(unsigned char*& buffer, size_t& currentSize, const char* newData)
{
    size_t newDataSize = std::strlen(newData);
    size_t newSize           = currentSize + newDataSize;
    unsigned char* newBuffer = new unsigned char[newSize];
    if (currentSize > 0) {
        std::memcpy(newBuffer, buffer, currentSize);
    }
    std::memcpy(newBuffer + currentSize, reinterpret_cast<const unsigned char*>(newData), newDataSize);
    delete[] buffer;
    buffer      = newBuffer;
    currentSize = newSize;
}

const char* appendToUnsignedChar(unsigned char*& buffer, const char* newData)
{
    size_t currentSize = buffer ? std::strlen(reinterpret_cast<const char*>(buffer)) : 0;
    size_t newDataSize = std::strlen(newData);
    size_t newSize           = currentSize + newDataSize;
    unsigned char* newBuffer = new unsigned char[newSize + 1]; 

    if (currentSize > 0) {
        std::memcpy(newBuffer, buffer, currentSize);
    }
    std::memcpy(newBuffer + currentSize, reinterpret_cast<const unsigned char*>(newData), newDataSize);
    newBuffer[newSize] = '\0';
    return reinterpret_cast<const char*>(newBuffer);
}

bool searchIfCommandExists(const unsigned char* input, const std::unordered_map<std::string, std::string>& map)
{
    const unsigned char* spacePos = reinterpret_cast<const unsigned char*>(std::strpbrk(reinterpret_cast<const char*>(input), " \r"));

    size_t length = (spacePos != nullptr) ? (spacePos - input) : std::strlen(reinterpret_cast<const char*>(input));

    std::string key(reinterpret_cast<const char*>(input), length);

    return map.find(key) != map.end();
}

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

    StreamTcpLayer summaryLayer = {};
    const char* name2           = "Summary";
    summaryLayer.name           = std::make_unique<uint8[]>(strlen(name2) + 1);
    memcpy(summaryLayer.name.get(), name2, strlen(name2) + 1);

    
    const uint8* startPtr = connPayload->location;
    const uint8* startline = connPayload->location;
    const uint8* endPtr   = connPayload->location + connPayload->size;
    unsigned char* command = nullptr;
    unsigned char* response = nullptr;
    unsigned char* summary  = nullptr;
    size_t summary_size     = 0;
    unsigned char* username = nullptr;

    
    bool isACommand = 0;
    while (startPtr < endPtr) {
        if (*startPtr == 0x0D || *startPtr == 0x0a) {
            
            if (startPtr - startline > 0) {

                if (isACommand) {
                    command = new unsigned char[startPtr - startline];
                    std::memcpy(command, startline, startPtr - startline);
                    command[startPtr - startline] = '\0';
                } else {
                    response = new unsigned char[startPtr - startline];
                    std::memcpy(response, startline, startPtr - startline);
                    response[startPtr - startline] = '\0';
                }

                startline                          = startPtr + 2;

                if (!isACommand && command != nullptr) {

                
                    if (memcmp(command, "USER", 4) == 0) {
                        username = command + 5;

                        if (memcmp(response, "331", 3) == 0) {
                            const char* message = " tried to log in but the password is needed\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }

                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " tried to log in but the credentials are incorrect\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }

                    }

                    if (memcmp(command, "PASS", 4) == 0) {
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " had written the password but the credentials are incorrect\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }

                        if (memcmp(response, "230", 3) == 0) {
                            const char* message = " introduced the password and ";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(response, "230", 3) == 0) {
                        StreamTcpLayer layer      = {};
                        const char* name          = "Username: ";
                        size_t nameLength         = std::strlen(name);
                        size_t modifiedDataLength = std::strlen(reinterpret_cast<const char*>(username));

                        size_t totalLength = nameLength + modifiedDataLength + 1;
                        char* concatenated = new char[totalLength];
                        std::memcpy(concatenated, name, nameLength);
                        std::memcpy(concatenated + nameLength, username, modifiedDataLength);
                        concatenated[totalLength - 1] = '\0';

                        layer.name = std::make_unique<uint8[]>(strlen(concatenated) + 1);
                        memcpy(layer.name.get(), concatenated, strlen(concatenated) + 1);
                        applicationLayers.emplace_back(std::move(layer));
                        const char* message = " has logged succesfully\n";
                        message             = appendToUnsignedChar(username, message);
                        appendToUnsignedChar(summary, summary_size, message);
                    }

                    if (memcmp(command, "SYST", 4) == 0 and memcmp(response,"215",3) == 0) {
                        const char* message = " has asked for the operating system at the server\n";
                        message             = appendToUnsignedChar(username, message);
                        appendToUnsignedChar(summary, summary_size, message);
                        unsigned char* opsys = response + 4;
                        const char* message2  = " is the operating system at the server\n";
                        message2              = appendToUnsignedChar(opsys, message2);
                        appendToUnsignedChar(summary, summary_size, message2);

                    }

                    /*
                    if (!searchIfCommandExists(command, ftp_transfer_parameter_commands) && !searchIfCommandExists(command, ftp_access_control_commands) &&
                        !searchIfCommandExists(command, ftp_service_commands)) {
                        const char* message = " has run a command which is not a standard FTP command\n";
                        message = appendToUnsignedChar(username, message);
                        appendToUnsignedChar(summary, summary_size, message);
                        message = " is the command run by the user\n";
                        message             = appendToUnsignedChar(command, message);
                        appendToUnsignedChar(summary, summary_size, message);
                    }
                    */
                }

                isACommand = 1 - isACommand;

            }
        
        }
        startPtr++;
    }


    summaryLayer.payload.size     = strlen(reinterpret_cast<const char*>(summary)) + 1;
    summaryLayer.payload.location = new uint8[summaryLayer.payload.size + 1];
    memcpy(summaryLayer.payload.location, summary, summaryLayer.payload.size + 1);

    applicationLayers.emplace_back(std::move(summaryLayer));
    return this;
}
