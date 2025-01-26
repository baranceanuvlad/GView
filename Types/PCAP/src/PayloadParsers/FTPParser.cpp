
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
    size_t newDataSize       = std::strlen(newData);
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
    size_t currentSize       = buffer ? std::strlen(reinterpret_cast<const char*>(buffer)) : 0;
    size_t newDataSize       = std::strlen(newData);
    size_t newSize           = currentSize + newDataSize;
    unsigned char* newBuffer = new unsigned char[newSize + 1];

    if (currentSize > 0) {
        std::memcpy(newBuffer, buffer, currentSize);
    }
    std::memcpy(newBuffer + currentSize, reinterpret_cast<const unsigned char*>(newData), newDataSize);
    newBuffer[newSize] = '\0';
    return reinterpret_cast<const char*>(newBuffer);
}

const char* appendUnsignedCharToConstChar(const char* str1, const unsigned char* str2)
{
    size_t len1    = std::strlen(str1);
    size_t len2    = std::strlen(reinterpret_cast<const char*>(str2));
    char* combined = new char[len1 + len2 + 1];

    std::strcpy(combined, str1);
    std::strcat(combined, reinterpret_cast<const char*>(str2));
    return combined;
}

const char* appendConstChar(const char* str1, const char* str2)
{
    size_t len1    = std::strlen(str1);
    size_t len2    = std::strlen(str2);
    char* combined = new char[len1 + len2 + 1];
    std::strcpy(combined, str1);
    std::strcat(combined, str2);
    return combined;
}

bool searchIfCommandExists(const unsigned char* input, const std::unordered_map<std::string, std::string>& map)
{
    const unsigned char* spacePos = reinterpret_cast<const unsigned char*>(std::strpbrk(reinterpret_cast<const char*>(input), " \r"));

    size_t length = (spacePos != nullptr) ? (spacePos - input) : std::strlen(reinterpret_cast<const char*>(input));

    std::string key(reinterpret_cast<const char*>(input), length);

    return map.find(key) != map.end();
}

PayloadDataParserInterface* FTP::FTPParser::ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface)
{
    const auto connPayload = payloadInformation.payload;
    if (payloadInformation.payload->size < 10)
        return nullptr;

    auto& var = payloadInformation.payload->location;
    char locationValue[4];                                               
    std::memcpy(locationValue, payloadInformation.payload->location, 3); 
    locationValue[3] = '\0';                                             
    if (memcmp(payloadInformation.payload->location, "220", 3) != 0 && memcmp(payloadInformation.payload->location, "120", 3) != 0 &&
        memcmp(payloadInformation.payload->location, "421", 3) != 0 && memcmp(payloadInformation.payload->location, "221", 3) != 0)
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

        if (packet.payload.size > 0) // current payload has payload
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
    layer.name           = std::make_unique<uint8[]>(strlen(name) + 1);
    memcpy(layer.name.get(), name, strlen(name) + 1);
    applicationLayers.emplace_back(std::move(layer));

    StreamTcpLayer summaryLayer = {};
    const char* name2           = "Summary";
    summaryLayer.name           = std::make_unique<uint8[]>(strlen(name2) + 1);
    memcpy(summaryLayer.name.get(), name2, strlen(name2) + 1);

    const uint8* startPtr   = connPayload->location;
    const uint8* startline  = connPayload->location;
    const uint8* endPtr     = connPayload->location + connPayload->size;
    unsigned char* command  = nullptr;
    unsigned char* response = nullptr;
    unsigned char* summary  = nullptr;
    size_t summary_size     = 0;
    unsigned char* username = nullptr;

    bool isACommand = 0;
    for (; startPtr < endPtr; startPtr++) {
        if (*startPtr == 0x0D || *startPtr == 0x0a) {
            if (startPtr - startline > 0) {
                if (isACommand) {
                    if (*startline - '0' >= 0 and *startline - '0' <= 9) {
                        response = new unsigned char[startPtr - startline];
                        std::memcpy(response, startline, startPtr - startline);
                        response[startPtr - startline] = '\0';
                        isACommand                     = 0;
                    } else {
                        command = new unsigned char[startPtr - startline];
                        std::memcpy(command, startline, startPtr - startline);
                        command[startPtr - startline] = '\0';
                    }
                } else {
                    response = new unsigned char[startPtr - startline];
                    std::memcpy(response, startline, startPtr - startline);
                    response[startPtr - startline] = '\0';
                }

                startline = startPtr + 2;

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

                    if (memcmp(command, "SYST", 4) == 0 and memcmp(response, "215", 3) == 0) {
                        const char* message = " has asked for the operating system at the server\n";
                        message             = appendToUnsignedChar(username, message);
                        appendToUnsignedChar(summary, summary_size, message);
                        unsigned char* opsys = response + 4;
                        const char* message2 = " is the operating system at the server\n";
                        message2             = appendToUnsignedChar(opsys, message2);
                        appendToUnsignedChar(summary, summary_size, message2);
                    }

                    if (memcmp(command, "CWD", 3) == 0) {
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = " has changed the working directory to ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, "\n");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            const char* message = " has tried to change the working directory to";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but the action has not been taken\n");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = " has tried to change the working directory to";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but the action has not been taken due to folder not found or no access\n");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "PWD", 3) == 0 and memcmp(response, "257", 3) == 0) {
                        const char* message = " has asked for the server to print the current directory: ";
                        message             = appendToUnsignedChar(username, message);
                        message             = appendUnsignedCharToConstChar(message, response + 4);
                        message             = appendConstChar(message, "\n\0");
                        appendToUnsignedChar(summary, summary_size, message);
                    }

                    if (memcmp(command, "TYPE", 4) == 0) {
                        if (memcmp(response, "200", 3) == 0) {
                            const char* message = " has set the file transfer mode ";
                            message             = appendToUnsignedChar(username, message);
                            if (*(command + 5) == 'A') {
                                message = appendConstChar(message, " ASCII ");
                            }
                            if (*(command + 5) == 'E') {
                                message = appendConstChar(message, " EBCDIC ");
                            }
                            if (*(command + 5) == 'I') {
                                message = appendConstChar(message, " IMAGE ");
                            }
                            if (*(command + 5) == 'L') {
                                message = appendConstChar(message, " Local byte ");
                            }
                            if (std::strlen(reinterpret_cast<const char*>(command)) < 7 || *(command + 7) == 'N') {
                                message = appendConstChar(message, " with Byte Size Non-print\n\0");
                            } else {
                                if (*(command + 7) == 'T')
                                    message = appendConstChar(message, " with Byte Size Telnet format effectors\n\0");
                                else if (*(command + 7) == 'C')
                                    message = appendConstChar(message, " with Byte Size Carriage Control\n\0");
                                else
                                    message = appendUnsignedCharToConstChar(message, command + 7);
                            }

                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "RETR", 4) == 0) {
                        const char* message = " has requested the server to transfer the file from the following path: ";
                        message             = appendToUnsignedChar(username, message);
                        message             = appendUnsignedCharToConstChar(message, command + 5);
                        if (memcmp(response, "125", 3) == 0) {
                            message = appendConstChar(message, " and the transfer started \n\0");
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            message = appendConstChar(message, " but the file is busy \n\0");
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            message = appendConstChar(message, " but the file is unavailable \n\0");
                        }
                        appendToUnsignedChar(summary, summary_size, message);
                    }

                    if (memcmp(command, "ABOR", 4) == 0) {
                        if (memcmp(response, "225", 3) == 0) {
                            const char* message = " has successfully aborted the previous FTP command, data connection is open\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "226", 3) == 0) {
                            const char* message = " has successfully aborted the previous FTP command\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has attempted to abort the previous FTP command, but it failed due to syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has attempted to abort the previous FTP command, but it failed due to parameter issues\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has attempted to abort the previous FTP command, but the command is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has attempted to abort the previous FTP command, but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "ALLO", 4) == 0) {
                        if (memcmp(response, "200", 3) == 0) {
                            const char* message = " has allocated sufficient storage for the FTP operation\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "202", 3) == 0) {
                            const char* message = " has attempted to allocate storage, but the command is not necessary\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has attempted to allocate storage, but it failed due to syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has attempted to allocate storage, but it failed due to parameter issues\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "504", 3) == 0) {
                            const char* message = " has attempted to allocate storage, but the command is not implemented for the parameter provided\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has attempted to allocate storage, but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has attempted to allocate storage, but not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "HELP", 4) == 0) {
                        if (memcmp(response, "211", 3) == 0) {
                            const char* message = " has requested system help information and received a valid response. Server response: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, response + 4);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "214", 3) == 0) {
                            const char* message = " has requested help information and received a valid response. Server response: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, response + 4);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has requested help, but it failed due to syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has requested help, but it failed due to parameter issues\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has requested help, but the command is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has requested help, but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "NOOP", 4) == 0) {
                        if (memcmp(response, "200", 3) == 0) {
                            const char* message = " has issued a NOOP command, which succeeded\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has issued a NOOP command, but it failed due to syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has issued a NOOP command, but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "PASV", 4) == 0) {
                        if (memcmp(response, "227", 3) == 0) {
                            const char* message = " has successfully entered passive mode. Server response: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, response + 4);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has attempted to enter passive mode, but it failed due to syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has attempted to enter passive mode, but it failed due to parameter issues\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has attempted to enter passive mode, but the command is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has attempted to enter passive mode, but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has attempted to enter passive mode, but not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "PORT", 4) == 0) {
                        if (memcmp(response, "200", 3) == 0) {
                            const char* message = " has successfully specified the data connection port: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has issued a PORT command, but it failed due to syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has issued a PORT command, but it failed due to parameter issues\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has issued a PORT command, but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has issued a PORT command, but not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "QUIT", 4) == 0) {
                        if (memcmp(response, "221", 3) == 0) {
                            const char* message = " has logged out and disconnected from the FTP server\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has attempted to log out, but it failed due to syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "MDTM", 4) == 0) {
                        if (memcmp(response, "213", 3) == 0) {
                            const char* message = " has requested the last modification time of the file '";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, "'. Server response: ");
                            message             = appendUnsignedCharToConstChar(message, response + 4);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = " has tried to request the last modification time of the file '";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, "', but the file was not found.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }
                    if (memcmp(command, "ACCT", 4) == 0) {
                        if (memcmp(response, "230", 3) == 0) {
                            const char* message = " has provided account information and logged in successfully\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "202", 3) == 0) {
                            const char* message = " has issued an account command, but it was not necessary\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has attempted to provide account information but is not logged in\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has attempted to issue an account command, but it failed due to syntax error\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has attempted to issue an account command, but it failed due to parameter issues\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "503", 3) == 0) {
                            const char* message = " has attempted to issue an account command, but the sequence of commands was incorrect\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has attempted to issue an account command, but the service is not available\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }
                    if (memcmp(command, "APPE", 4) == 0) {
                        const char* baseMessage = " has issued the APPE (Append) command for file: ";
                        baseMessage             = appendToUnsignedChar(username, baseMessage);
                        const char* filePath    = reinterpret_cast<const char*>(command + 5);

                        if (memcmp(response, "125", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " and the transfer is starting.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "150", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " and the file status is okay. Data connection is about to open.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "226", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " and the file transfer is complete.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " and the requested file action is complete.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "425", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the data connection could not be opened.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "426", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the connection was closed and the transfer was aborted.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "451", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the action was aborted due to a local processing error.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "551", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the action was aborted due to a page type unknown error.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "552", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the action was aborted due to insufficient storage.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the user is not logged in.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the file is unavailable (e.g., not found, no access).\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the command failed due to a syntax error.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the command failed due to a parameter issue.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the command is not implemented.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, " but the service is not available.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }
                    if (memcmp(command, "LIST", 4) == 0) {
                        const char* baseMessage = " has issued the LIST command to retrieve the directory/file information";
                        baseMessage             = appendToUnsignedChar(username, baseMessage);
                        const char* filePath    = reinterpret_cast<const char*>(command + 5);

                        if (memcmp(response, "125", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Data connection is already open; transfer is starting.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "150", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". File status okay; about to open data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "226", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Closing data connection. Transfer completed successfully.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Requested file action okay and completed.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "425", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Cannot open data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "426", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Connection closed; transfer aborted.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "451", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Action aborted: local error in processing.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Requested file action not taken. File is busy.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". User is not logged in.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Syntax error in command.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Syntax error in parameters or arguments.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Command not implemented.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Service not available, closing control connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "NLST", 4) == 0) {
                        const char* baseMessage = " has issued the NLST command to retrieve a list of file names";
                        baseMessage                 = appendToUnsignedChar(username, baseMessage);
                        const char* filePath    = reinterpret_cast<const char*>(command + 5);

                        if (memcmp(response, "125", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Data connection is already open; transfer is starting.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "150", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". File status okay; about to open data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "226", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Closing data connection. Transfer completed successfully.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Requested file action okay and completed.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "425", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Cannot open data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "426", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Connection closed; transfer aborted.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "451", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Action aborted: local error in processing.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Requested file action not taken. File is busy.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". User is not logged in.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Syntax error in command.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Syntax error in parameters or arguments.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Command not implemented.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Service not available, closing control connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }
                    if (memcmp(command, "STOR", 4) == 0) {
                        const char* baseMessage = " has issued the STOR command to upload a file to the server";
                        baseMessage             = appendToUnsignedChar(username, baseMessage);
                        const char* filePath    = reinterpret_cast<const char*>(command + 5);

                        if (memcmp(response, "125", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Data connection is already open; transfer is starting.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "150", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". File status okay; about to open data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "226", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Transfer completed successfully; closing data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Requested file action okay and completed.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "425", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Cannot open data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "426", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Connection closed; transfer aborted.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "451", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Action aborted: local error in processing.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Requested file action not taken; file is busy.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "552", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Action aborted due to insufficient storage space.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "553", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Action aborted; file name not allowed.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". User is not logged in.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Syntax error in command.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Syntax error in parameters or arguments.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, filePath);
                            message             = appendConstChar(message, ". Service not available, closing control connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }
                    if (memcmp(command, "STOU", 4) == 0) {
                        const char* baseMessage = " has issued the STOU command to store a file with a unique name";
                        baseMessage             = appendToUnsignedChar(username, baseMessage);
                        if (memcmp(response, "125", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Data connection is already open; transfer is starting.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "150", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". File status okay; about to open data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "226", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Transfer completed successfully; closing data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". File stored successfully with a unique name. Server response: ");
                            message             = appendUnsignedCharToConstChar(message, response + 4);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "425", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Cannot open data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "426", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Connection closed; transfer aborted.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "451", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Action aborted: local error in processing.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Requested file action not taken; file is busy.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "552", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Action aborted due to insufficient storage space.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "553", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Action aborted; file name not allowed.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". User is not logged in.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Syntax error in command.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Syntax error in parameters or arguments.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = appendConstChar(baseMessage, "");
                            message             = appendConstChar(message, ". Service not available, closing control connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }


                    if (memcmp(command, "CDUP", 4) == 0) {
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = " has successfully changed to the parent of the current working directory\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has issued a CDUP command, but it failed due to syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has issued a CDUP command, but it failed due to parameter issues\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has issued a CDUP command, but the command is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has issued a CDUP command, but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has issued a CDUP command, but not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = " has issued a CDUP command, but permission is denied or directory does not exist\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "DELE", 4) == 0) {
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = " has successfully deleted the file: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            const char* message = " has tried to delete the file: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the file is in use or unavailable\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to delete the file: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the command failed due to syntax error\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to delete the file: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the command failed due to parameter issues\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has tried to delete the file: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the command is not implemented\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to delete the file: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the service is not available\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to delete the file: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but not logged in\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = " has tried to delete the file: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but permission is denied or the file does not exist\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "MKD", 3) == 0) {
                        if (memcmp(response, "257", 3) == 0) {
                            const char* message = " has successfully created the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to create the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but the command failed due to syntax error\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to create the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but the command failed due to parameter issues\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has tried to create the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but the command is not implemented\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to create the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but the service is not available\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to create the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but not logged in\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = " has tried to create the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but permission is denied or the directory already exist\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "RMD", 3) == 0) {
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = " has successfully deleted the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to delete the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but the command failed due to syntax error\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to delete the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but the command failed due to parameter issues\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has tried to delete the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but the command is not implemented\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to delete the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but the service is not available\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to delete the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but not logged in\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = " has tried to delete the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 4);
                            message             = appendConstChar(message, " but permission is denied or the directory does not exist\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "SMNT", 4) == 0) {
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = " has successfully mounted or changed the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " on the server\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to mount the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the command failed due to syntax error\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to mount the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the command failed due to parameter issues\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has tried to mount the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the command is not implemented\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to mount the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the service is not available\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to mount the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but not logged in\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = " has tried to mount the directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but permission is denied or the directory does not exist\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "MODE", 4) == 0) {
                        const unsigned char* mode_type;
                        switch (*(command + 5)) {
                        case 'S':
                            mode_type = reinterpret_cast<const unsigned char*>("stream");
                            break;
                        case 'B':
                            mode_type = reinterpret_cast<const unsigned char*>("block");
                            break;
                        case 'C':
                            mode_type = reinterpret_cast<const unsigned char*>("compressed");
                            break;
                        default:
                            break;
                        }
                        if (memcmp(response, "200", 3) == 0) {
                            const char* message = " has successfully set the transfer mode for file transfers to: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, mode_type);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to set the transfer mode for file transfers to: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, mode_type);
                            message             = appendConstChar(message, " but the command failed due to syntax error\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to set the transfer mode for file transfers to: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, mode_type);
                            message             = appendConstChar(message, " but the command failed due to parameter issues\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has tried to set the transfer mode for file transfers to: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, mode_type);
                            message             = appendConstChar(message, " but the command is not implemented\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to set the transfer mode for file transfers to: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, mode_type);
                            message             = appendConstChar(message, " but not logged in\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "504", 3) == 0) {
                            const char* message = " has tried to set the transfer mode for file transfers to: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, mode_type);
                            message             = appendConstChar(message, " but the command is not implemented for that parameter\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "REIN", 4) == 0) {
                        if (memcmp(response, "220", 3) == 0) {
                            const char* message = " has successfully reset the session and is now ready for a new login or interaction\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to reset the session but the command failed due to syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has tried to reset the session but the command is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to reset the session but not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to reset the session but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }                  
                    }

                    if (memcmp(command, "REST", 4) == 0) {
                        if (memcmp(response, "350", 3) == 0) {
                            const char* message = " has successfully set the restart point for a file transfer to byte: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to set the restart point for a file transfer to byte: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the command failed due to syntax error\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to set the restart point for a file transfer to byte: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the command failed due to parameter issues\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has tried to set the restart point for a file transfer to byte: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the command is not implemented\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to set the restart point for a file transfer to byte: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but the service is not available\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to set the restart point for a file transfer to byte: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but not logged in\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = " has tried to set the restart point for a file transfer to byte: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " but permission is denied or the file is not available\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
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
    }

    summaryLayer.payload.size     = strlen(reinterpret_cast<const char*>(summary)) + 1;
    summaryLayer.payload.location = new uint8[summaryLayer.payload.size + 1];
    memcpy(summaryLayer.payload.location, summary, summaryLayer.payload.size + 1);

    applicationLayers.emplace_back(std::move(summaryLayer));
    return this;
}