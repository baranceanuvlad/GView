#pragma once

#include "API.hpp"

namespace GView::Type::PCAP::FTP
{

struct FTPParser : public PayloadDataParserInterface {
    std::string GetProtocolName() const override
    {
        return "FTP";
    }

    std::unordered_map<std::string, std::string> ftp_transfer_parameter_commands = {
        { "PORT", "DATA PORT" }, { "PASV", "PASSIVE" }, { "TYPE", "REPRESENTATION TYPE" }, { "STRU", "FILE STRUCTURE" }, { "MODE", "TRANSFER MODE" },
    };

    std::unordered_map<std::string, std::string> ftp_access_control_commands = {
        { "USER", "USER NAME" },
        { "PASS", "PASSWORD" },
        { "ACCT", "ACCOUNT" },
        { "CWD", "CHANGE WORKING DIRECTORY" },
        { "CDUP", "CHANGE TO PARENT DIRECTORY" },
        { "SMNT", "STRUCTURE MOUNT " },
        { "REIN", "REINITIALIZE" },
        { "QUIT", "LOGOUT " },
    };

    std::unordered_map<std::string, std::string> ftp_service_commands = {
        { "RETR", "RETRIEVE" },
        { "STOR", "STORE" },
        { "STOU", "STORE UNIQUE" },
        { "APPE", "APPEND (with create)" },
        { "ALLO", "ALLOCATE" },
        { "REST", "RESTART " },
        { "RNFR", "RENAME FROM" },
        { "RNTO", "RENAME TO" },
        { "ABOR", "ABORT" },
        { "DELE", "DELETE" },
        { "RMD", "REMOVE DIRECTORY" },
        { "MKD", "MAKE DIRECTORY" },
        { "PWD", "PRINT WORKING DIRECTORY" },
        { "LIST", "LIST" },
        { "NLST", "NAME LIST" },
        { "SITE", "SITE PARAMETERS" },
        { "SYST", "SYSYEM" },
        { "STAT", "STATUS" },
        { "HELP", "HELP" },
        { "NOOP", "NOOP" },

    };

    PayloadDataParserInterface* ParsePayload(const PayloadInformation& payloadInformation, ConnectionCallbackInterface* callbackInterface) override;
};
}