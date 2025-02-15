
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

    StreamTcpLayer size_layer = {};
    const char* name_size     = "Size of files";
    size_layer.name           = std::make_unique<uint8[]>(strlen(name_size) + 1);
    memcpy(size_layer.name.get(), name_size, strlen(name_size) + 1);
    std::map<unsigned char*, unsigned char*> map_size;

    const uint8* startPtr   = connPayload->location;
    const uint8* startline  = connPayload->location;
    const uint8* endPtr     = connPayload->location + connPayload->size;
    unsigned char* command  = nullptr;
    unsigned char* response = nullptr;
    unsigned char* summary  = nullptr;
    const char* size_file   = "";
    size_t summary_size     = 0;
    size_t size_file_size   = 0;
    unsigned char* username = nullptr;
    std::map<unsigned char*, std::string> filesDownloaded;
    std::map<unsigned char*, std::string> filesUploaded;

    bool isACommand = 0;
    for (; startPtr < endPtr; startPtr++) {
        if (*startPtr == 0x0D || *startPtr == 0x0a) {
            if (startPtr - startline > 0) {
                if (isACommand) {
                    if (*startline - '0' >= 0 and *startline - '0' <= 9) {
                        response = new unsigned char[startPtr - startline];
                        std::memcpy(response, startline, startPtr - startline);
                        response[startPtr - startline] = '\0';
                        if (*(response + 3) == '-') {
                            const uint8* startline2 = startPtr;
                            while (startPtr < endPtr) {
                                if (*startPtr == 0x0D || *startPtr == 0x0a) {
                                    unsigned char* response2 = nullptr;
                                    response2                = new unsigned char[startPtr - startline2];
                                    std::memcpy(response2, startline2, startPtr - startline2);
                                    response2[startPtr - startline2] = '\0';
                                    if (*(response) == *(response2) and *(response + 1) == *(response2 + 1) and *(response + 2) == *(response2 + 2) and
                                        *(response2 + 3) != '-') {
                                        response = new unsigned char[startPtr - startline];
                                        std::memcpy(response, startline, startPtr - startline);
                                        response[startPtr - startline] = '\0';
                                        break;
                                    }
                                    startline2 = startPtr + 1;
                                }
                                startPtr++;
                            }
                        }

                        isACommand = 0;
                    } else {
                        command = new unsigned char[startPtr - startline];
                        std::memcpy(command, startline, startPtr - startline);
                        command[startPtr - startline] = '\0';
                    }
                } else {
                    response = new unsigned char[startPtr - startline];
                    std::memcpy(response, startline, startPtr - startline);
                    response[startPtr - startline] = '\0';
                    if (*(response + 3) == '-') {
                        const uint8* startline2 = startPtr;
                        while (startPtr < endPtr) {
                            if (*startPtr == 0x0D || *startPtr == 0x0a) {
                                unsigned char* response2 = nullptr;
                                response2                = new unsigned char[startPtr - startline2];
                                std::memcpy(response2, startline2, startPtr - startline2);
                                response2[startPtr - startline2] = '\0';
                                if (*(response) == *(response2) and *(response + 1) == *(response2 + 1) and *(response + 2) == *(response2 + 2) and
                                    *(response2 + 3) != '-') {
                                    response = new unsigned char[startPtr - startline];
                                    std::memcpy(response, startline, startPtr - startline);
                                    response[startPtr - startline] = '\0';
                                    break;
                                }
                                startline2 = startPtr + 1;
                            }
                            startPtr++;
                        }
                    }
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

                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " tried to log in but the command is not recognized\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }

                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = "tried to log in but there is a syntax error in parameters or arguments\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }

                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " tried to log in but the service is unavailable\n";
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
                        if (memcmp(response, "202", 3) == 0) {
                            const char* message = " introduced the password but the command is not necessary at this stage\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " introduced the password but the command is not recognized\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " introduced the password but there is a syntax error in parameters or arguments\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "503", 3) == 0) {
                            const char* message = " introduced the password but there is a bad sequence of commands\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " introduced the password but the service is closing\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "332", 3) == 0) {
                            const char* message = " introduced the password but further account information is required\n";
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

                    if (memcmp(command, "SYST", 4) == 0) {
                        if (memcmp(response, "215", 3) == 0) {
                            const char* message = " has asked for the operating system at the server\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                            unsigned char* opsys = response + 4;
                            const char* message2 = " is the operating system at the server\n";
                            message2             = appendToUnsignedChar(opsys, message2);
                            appendToUnsignedChar(summary, summary_size, message2);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " encountered a syntax error while asking for the operating system\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " encountered a syntax error in parameters while asking for the operating system\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " encountered a command not implemented error while asking for the operating system\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " encountered a service not available error while asking for the operating system\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
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
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " encountered a syntax error while attempting to change the working directory\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " encountered a syntax error in parameters while attempting to change the working directory\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " encountered a command not implemented error while attempting to change the working directory\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " encountered a service not available error while attempting to change the working directory\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " was not logged in and attempted to change the working directory\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "PWD", 3) == 0) {
                        if (memcmp(response, "257", 3) == 0) {
                            const char* message = " has asked for the server to print the current directory: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, response + 4);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }

                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " encountered a syntax error while attempting to print the current directory\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " encountered a syntax error in parameters while attempting to print the current directory\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " encountered a command not implemented error while attempting to print the current directory\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " encountered a service not available error while attempting to print the current directory\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = " was not logged in and attempted to print the current directory\n";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
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
                            message = appendConstChar(message, " and the data connection is open and the transfer started\n");
                        }
                        if (memcmp(response, "150", 3) == 0) {
                            message = appendConstChar(message, " and the file status is okay, about to open data connection\n");
                            std::string strData(reinterpret_cast<char*>(command + 5));
                            if (filesDownloaded.find(username) != filesDownloaded.end()) {
                                filesDownloaded[username] += "," + strData;
                            } else {
                                filesDownloaded[username] = strData;
                            }
                        }
                        if (memcmp(response, "110", 3) == 0) {
                            message = appendConstChar(message, " but the restart marker reply was received\n");
                        }
                        if (memcmp(response, "226", 3) == 0) {
                            message = appendConstChar(message, " and the file transfer was successful\n");
                        }
                        if (memcmp(response, "250", 3) == 0) {
                            message = appendConstChar(message, " and the requested file action was completed\n");
                        }
                        if (memcmp(response, "425", 3) == 0) {
                            message = appendConstChar(message, " but the data connection could not be opened\n");
                        }
                        if (memcmp(response, "426", 3) == 0) {
                            message = appendConstChar(message, " but the connection was closed, transfer aborted\n");
                        }
                        if (memcmp(response, "451", 3) == 0) {
                            message = appendConstChar(message, " but the requested action was aborted due to a local error\n");
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            message = appendConstChar(message, " but the file is busy\n");
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            message = appendConstChar(message, " but the file is unavailable\n");
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            message = appendConstChar(message, " but a syntax error occurred\n");
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            message = appendConstChar(message, " but a syntax error occurred in parameters\n");
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            message = appendConstChar(message, " but the service is unavailable\n");
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            message = appendConstChar(message, " but the user is not logged in\n");
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
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to request the last modification time of the file '";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, "', but the command was not understood by the server.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to request the last modification time of the file '";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, "', but the command syntax was invalid.\n\0");
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
                        const char* message =
                              std::strlen(reinterpret_cast<const char*>(command)) > 5 ? appendUnsignedCharToConstChar(baseMessage, command + 5) : baseMessage;

                        if (memcmp(response, "125", 3) == 0) {
                            message = appendConstChar(message, ". Data connection is already open; transfer is starting.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "150", 3) == 0) {
                            message = appendConstChar(message, ". File status okay; about to open data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "226", 3) == 0) {
                            message = appendConstChar(message, ". Closing data connection. Transfer completed successfully.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "250", 3) == 0) {
                            message = appendConstChar(message, ". Requested file action okay and completed.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "425", 3) == 0) {
                            message = appendConstChar(message, ". Cannot open data connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "426", 3) == 0) {
                            message = appendConstChar(message, ". Connection closed; transfer aborted.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "451", 3) == 0) {
                            message = appendConstChar(message, ". Action aborted: local error in processing.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            message = appendConstChar(message, ". Requested file action not taken. File is busy.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            message = appendConstChar(message, ". User is not logged in.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            message = appendConstChar(message, ". Syntax error in command.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            message = appendConstChar(message, ". Syntax error in parameters or arguments.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            message = appendConstChar(message, ". Command not implemented.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            message = appendConstChar(message, ". Service not available, closing control connection.\n\0");
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "NLST", 4) == 0) {
                        const char* baseMessage = " has issued the NLST command to retrieve a list of file names";
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
                            std::string strData(reinterpret_cast<char*>(command + 5));
                            if (filesUploaded.find(username) != filesUploaded.end()) {
                                filesUploaded[username] += "," + strData;
                            } else {
                                filesUploaded[username] = strData;
                            }
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
                    if (memcmp(command, "FEAT", 4) == 0) {
                        if (memcmp(response, "211", 3) == 0 || memcmp(response, "214", 3) == 0) {
                            const char* message = " has requested the feature list and received: ";
                            message             = appendToUnsignedChar(username, message);
                            message             = appendUnsignedCharToConstChar(message, response + 4);
                            message             = appendConstChar(message, "\n\0");
                            appendToUnsignedChar(summary, summary_size, message);

                            const unsigned char* startPtr = response + 4;
                            const unsigned char* endPtr   = response + std::strlen(reinterpret_cast<const char*>(response));
                            while (startPtr < endPtr) {
                                const unsigned char* lineEnd =
                                      reinterpret_cast<const unsigned char*>(std::strchr(reinterpret_cast<const char*>(startPtr), '\n'));
                                if (!lineEnd)
                                    break;

                                size_t featureLength = lineEnd - startPtr;
                                if (featureLength > 0) {
                                    std::string feature(reinterpret_cast<const char*>(startPtr), featureLength);

                                    if (feature.find("TVFS") != std::string::npos) {
                                        const char* tvfsMessage = " The server supports TVFS (Trivial Virtual File Store).\n\0";
                                        appendToUnsignedChar(summary, summary_size, tvfsMessage);
                                    } else if (feature.find("UTF8") != std::string::npos) {
                                        const char* utf8Message = " The server supports UTF8 encoding for file names.\n\0";
                                        appendToUnsignedChar(summary, summary_size, utf8Message);
                                    } else if (feature.find("MDTM") != std::string::npos) {
                                        const char* mdtmMessage = " The server supports MDTM (Modify Fact Timestamp).\n\0";
                                        appendToUnsignedChar(summary, summary_size, mdtmMessage);
                                    } else if (feature.find("REST STREAM") != std::string::npos) {
                                        const char* restMessage = " The server supports REST STREAM for restarting interrupted transfers.\n\0";
                                        appendToUnsignedChar(summary, summary_size, restMessage);
                                    } else if (feature.find("SIZE") != std::string::npos) {
                                        const char* sizeMessage = " The server supports SIZE command to retrieve file sizes.\n\0";
                                        appendToUnsignedChar(summary, summary_size, sizeMessage);
                                    } else {
                                        std::string genericFeatureMessage = " The server supports the feature: " + feature + ".\n";
                                        appendToUnsignedChar(summary, summary_size, genericFeatureMessage.c_str());
                                    }
                                }

                                startPtr = lineEnd + 1;
                            }
                        } else if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has requested the feature list, but it failed due to syntax error.\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        } else if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has requested the feature list, but the command is not implemented.\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        } else if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has requested the feature list, but the service is not available.\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "STRU", 4) == 0) {
                        if (memcmp(response, "200", 3) == 0) {
                            const char* message = " has successfully set the file structure\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to set the file structure but the command failed due to a syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to set the file structure but the command failed due to a parameter syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "504", 3) == 0) {
                            const char* message = " has tried to set the file structure but the command failed as the parameter is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to set the file structure but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to set the file structure but is not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "STAT", 4) == 0) {
                        if (memcmp(response, "211", 3) == 0) {
                            const char* message = " has successfully retrieved the system status or help reply\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "212", 3) == 0) {
                            const char* message = " has successfully retrieved the directory status\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "213", 3) == 0) {
                            const char* message = " has successfully retrieved the file status\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            const char* message = " has tried to retrieve the status but the requested file action was not taken\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to retrieve the status but the command failed due to a syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to retrieve the status but the command failed due to a parameter syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has tried to retrieve the status but the command is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to retrieve the status but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to retrieve the status but is not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "SITE", 4) == 0) {
                        if (memcmp(response, "200", 3) == 0) {
                            const char* message = " has successfully executed the SITE-specific command\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "202", 3) == 0) {
                            const char* message = " has tried to execute the SITE-specific command but it is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to execute the SITE-specific command but the command failed due to a syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to execute the SITE-specific command but the command failed due to a parameter syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to execute the SITE-specific command but is not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "RNTO", 4) == 0) {
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = " has successfully renamed the file or directory\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "532", 3) == 0) {
                            const char* message = " has tried to rename the file or directory but the command failed because the user is not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "553", 3) == 0) {
                            const char* message = " has tried to rename the file or directory but the command failed due to a name issue (e.g., invalid or "
                                                  "prohibited name)\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to rename the file or directory but the command failed due to a syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to rename the file or directory but the command failed due to a parameter syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has tried to rename the file or directory but the command is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "503", 3) == 0) {
                            const char* message =
                                  " has tried to rename the file or directory but the command sequence is incorrect (e.g., RNFR missing before RNTO)\n\0";
                            message = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to rename the file or directory but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to rename the file or directory but the user is not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "RNFR", 4) == 0) {
                        if (memcmp(response, "350", 3) == 0) {
                            const char* message = " has successfully initiated the rename process and the requested file is ready for the RNTO command\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            const char* message =
                                  " has tried to rename a file but the action was not taken because the file is unavailable (e.g., locked or busy)\n\0";
                            message = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message =
                                  " has tried to rename a file but the action failed because the file does not exist or permission is denied\n\0";
                            message = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to rename a file but the command failed due to a syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to rename a file but the command failed due to a parameter syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "502", 3) == 0) {
                            const char* message = " has tried to rename a file but the command is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to rename a file but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to rename a file but the user is not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "SIZE", 4) == 0) {
                        if (memcmp(response, "200", 3) == 0) {
                            const char* message = " has successfully executed the SIZE command. The size of the file is provided. File: ";
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " (size: <unknown>)\n\0");
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "213", 3) == 0) {
                            const char* message = " has successfully retrieved the file size. File: ";
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " (size: ");
                            message             = appendUnsignedCharToConstChar(message, response + 4);
                            message             = appendConstChar(message, " bytes)\n\0");

                            message = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                            map_size[command + 5] = response + 4;
                        }
                        if (memcmp(response, "550", 3) == 0) {
                            const char* message = " has tried to retrieve the file size, but the file does not exist or permission is denied. File: ";
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " (error: file not found or access denied)\n\0");
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to retrieve the file size, but the command failed due to a syntax error. File: ";
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " (error: syntax issue)\n\0");
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to retrieve the file size, but the command failed due to a parameter syntax error. File: ";
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " (error: incorrect parameters)\n\0");
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to retrieve the file size, but the user is not logged in. File: ";
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " (error: not logged in)\n\0");
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to retrieve the file size, but the service is temporarily unavailable. File: ";
                            message             = appendUnsignedCharToConstChar(message, command + 5);
                            message             = appendConstChar(message, " (error: service unavailable)\n\0");
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "MLST", 4) == 0) {
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = " has successfully executed the MLST command, and the information about the requested file is provided\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "150", 3) == 0) {
                            const char* message = " has initiated the MLST command, and data transfer is starting\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "226", 3) == 0) {
                            const char* message = " has successfully completed the MLST command, and the data transfer is finished\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            const char* message = " has tried to execute the MLST command, but the action was not taken because the file is unavailable (e.g., "
                                                  "locked or busy)\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to execute the MLST command, but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to execute the MLST command, but it failed due to a syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to execute the MLST command, but it failed due to a parameter syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to execute the MLST command, but the user is not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "553", 3) == 0) {
                            const char* message = " has tried to execute the MLST command, but it failed due to an invalid file or directory name\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "503", 3) == 0) {
                            const char* message = " has tried to execute the MLST command, but the command sequence is incorrect\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "504", 3) == 0) {
                            const char* message = " has tried to execute the MLST command, but it failed because the parameter is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                    }

                    if (memcmp(command, "MLSD", 4) == 0) {
                        if (memcmp(response, "250", 3) == 0) {
                            const char* message = " has successfully executed the MLSD command, and the directory listing is provided\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "150", 3) == 0) {
                            const char* message = " has initiated the MLSD command, and data transfer is starting\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "226", 3) == 0) {
                            const char* message = " has successfully completed the MLSD command, and the data transfer is finished\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "450", 3) == 0) {
                            const char* message = " has tried to execute the MLSD command, but the action was not taken because the directory is unavailable "
                                                  "(e.g., locked or busy)\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "421", 3) == 0) {
                            const char* message = " has tried to execute the MLSD command, but the service is not available\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "500", 3) == 0) {
                            const char* message = " has tried to execute the MLSD command, but it failed due to a syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "501", 3) == 0) {
                            const char* message = " has tried to execute the MLSD command, but it failed due to a parameter syntax error\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "530", 3) == 0) {
                            const char* message = " has tried to execute the MLSD command, but the user is not logged in\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "553", 3) == 0) {
                            const char* message = " has tried to execute the MLSD command, but it failed due to an invalid file or directory name\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "503", 3) == 0) {
                            const char* message = " has tried to execute the MLSD command, but the command sequence is incorrect\n\0";
                            message             = appendToUnsignedChar(username, message);
                            appendToUnsignedChar(summary, summary_size, message);
                        }
                        if (memcmp(response, "504", 3) == 0) {
                            const char* message = " has tried to execute the MLSD command, but it failed because the parameter is not implemented\n\0";
                            message             = appendToUnsignedChar(username, message);
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

    for (auto it : map_size) {
        const char* message = "";
        message             = appendUnsignedCharToConstChar(message, it.first);
        message             = appendConstChar(message, ": ");
        message             = appendUnsignedCharToConstChar(message, it.second);
        message             = appendConstChar(message, " bytes\n\0");
        size_file           = appendConstChar(size_file, message);
    }

    if (!map_size.empty() && strlen(size_file) != 0) {
        size_file                   = appendConstChar(size_file, "\n");
        size_layer.payload.size     = strlen(size_file) + 1;
        size_layer.payload.location = new uint8[size_layer.payload.size + 1];
        memcpy(size_layer.payload.location, size_file, size_layer.payload.size + 1);
    }

    applicationLayers.emplace_back(std::move(size_layer));

    const char* filesDownloadedSummary = "";
    for (const auto& pair : filesDownloaded) {
        filesDownloadedSummary = appendConstChar(filesDownloadedSummary, reinterpret_cast<const char*>(pair.first));
        filesDownloadedSummary = appendConstChar(filesDownloadedSummary, " has downloaded the following files: ");
        filesDownloadedSummary = appendConstChar(filesDownloadedSummary, pair.second.c_str());
        filesDownloadedSummary = appendConstChar(filesDownloadedSummary, "\n");
    }

    if (strlen(filesDownloadedSummary) > 0) {
        StreamTcpLayer filesDownloadedLayer   = {};
        const char* name_filesDownloadedLayer = "Files downloaded";
        filesDownloadedLayer.name             = std::make_unique<uint8[]>(strlen(name_filesDownloadedLayer) + 1);
        memcpy(filesDownloadedLayer.name.get(), name_filesDownloadedLayer, strlen(name_filesDownloadedLayer) + 1);

        filesDownloadedLayer.payload.size     = strlen(reinterpret_cast<const char*>(filesDownloadedSummary)) + 1;
        filesDownloadedLayer.payload.location = new uint8[filesDownloadedLayer.payload.size + 1];
        memcpy(filesDownloadedLayer.payload.location, filesDownloadedSummary, filesDownloadedLayer.payload.size + 1);

        applicationLayers.emplace_back(std::move(filesDownloadedLayer));
    }

    const char* filesUploadedSummary = "";
    for (const auto& pair : filesUploaded) {
        filesUploadedSummary   = appendConstChar(filesUploadedSummary, reinterpret_cast<const char*>(pair.first));
        filesUploadedSummary   = appendConstChar(filesUploadedSummary, " has uploaded the following files: ");
        filesUploadedSummary   = appendConstChar(filesUploadedSummary, pair.second.c_str());
        filesUploadedSummary   = appendConstChar(filesUploadedSummary, "\n");
    }

    if (strlen(filesUploadedSummary) > 0) {
        StreamTcpLayer filesUploadedLayer     = {};
        const char* name_filesUploadedLayer = "Files uploaded";
        filesUploadedLayer.name               = std::make_unique<uint8[]>(strlen(name_filesUploadedLayer) + 1);
        memcpy(filesUploadedLayer.name.get(), name_filesUploadedLayer, strlen(name_filesUploadedLayer) + 1);

        filesUploadedLayer.payload.size     = strlen(reinterpret_cast<const char*>(filesUploadedSummary)) + 1;
        filesUploadedLayer.payload.location = new uint8[filesUploadedLayer.payload.size + 1];
        memcpy(filesUploadedLayer.payload.location, filesUploadedSummary, filesUploadedLayer.payload.size + 1);

        applicationLayers.emplace_back(std::move(filesUploadedLayer));
    }
    return this;
}