// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library TLSParser {
    struct TLSRecord {
        uint8 contentType;
        uint16 version;
        uint16 length;
        bytes data;
    }

    struct ClientHello {
        uint16 version;
        bytes32 random;
        bytes sessionId;
        uint16[] cipherSuites;
        uint8[] compressionMethods;
        bytes extensions;
    }

    struct ServerHello {
        uint16 version;
        bytes32 random;
        bytes sessionId;
        uint16 cipherSuite;
        uint8 compressionMethod;
        bytes extensions;
    }

    uint8 constant CONTENT_TYPE_HANDSHAKE = 22;
    uint8 constant CONTENT_TYPE_APPLICATION_DATA = 23;
    uint8 constant CONTENT_TYPE_ALERT = 21;
    uint8 constant CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;

    uint8 constant HANDSHAKE_TYPE_CLIENT_HELLO = 1;
    uint8 constant HANDSHAKE_TYPE_SERVER_HELLO = 2;
    uint8 constant HANDSHAKE_TYPE_CERTIFICATE = 11;
    uint8 constant HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12;
    uint8 constant HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16;
    uint8 constant HANDSHAKE_TYPE_FINISHED = 20;

    error InvalidTLSRecord();
    error InvalidHandshakeMessage();
    error UnsupportedTLSVersion();

    function parseTLSRecord(bytes memory data) internal pure returns (TLSRecord memory) {
        if (data.length < 5) revert InvalidTLSRecord();

        uint8 contentType = uint8(data[0]);
        uint16 version = (uint16(uint8(data[1])) << 8) | uint16(uint8(data[2]));
        uint16 length = (uint16(uint8(data[3])) << 8) | uint16(uint8(data[4]));

        if (data.length < 5 + length) revert InvalidTLSRecord();

        bytes memory recordData = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            recordData[i] = data[5 + i];
        }

        return TLSRecord({
            contentType: contentType,
            version: version,
            length: length,
            data: recordData
        });
    }

    function parseClientHello(bytes memory data) internal pure returns (ClientHello memory) {
        if (data.length < 34) revert InvalidHandshakeMessage();

        uint256 offset = 0;
        
        uint8 msgType = uint8(data[offset++]);
        if (msgType != HANDSHAKE_TYPE_CLIENT_HELLO) revert InvalidHandshakeMessage();

        offset += 3;

        uint16 version = (uint16(uint8(data[offset])) << 8) | uint16(uint8(data[offset + 1]));
        offset += 2;

        bytes32 random;
        assembly {
            random := mload(add(add(data, 0x20), offset))
        }
        offset += 32;

        uint8 sessionIdLength = uint8(data[offset++]);
        bytes memory sessionId = new bytes(sessionIdLength);
        for (uint256 i = 0; i < sessionIdLength; i++) {
            sessionId[i] = data[offset + i];
        }
        offset += sessionIdLength;

        uint16 cipherSuitesLength = (uint16(uint8(data[offset])) << 8) | uint16(uint8(data[offset + 1]));
        offset += 2;

        uint16[] memory cipherSuites = new uint16[](cipherSuitesLength / 2);
        for (uint256 i = 0; i < cipherSuites.length; i++) {
            cipherSuites[i] = (uint16(uint8(data[offset])) << 8) | uint16(uint8(data[offset + 1]));
            offset += 2;
        }

        uint8 compressionMethodsLength = uint8(data[offset++]);
        uint8[] memory compressionMethods = new uint8[](compressionMethodsLength);
        for (uint256 i = 0; i < compressionMethodsLength; i++) {
            compressionMethods[i] = uint8(data[offset + i]);
        }
        offset += compressionMethodsLength;

        bytes memory extensions;
        if (offset < data.length) {
            uint16 extensionsLength = (uint16(uint8(data[offset])) << 8) | uint16(uint8(data[offset + 1]));
            offset += 2;
            
            extensions = new bytes(extensionsLength);
            for (uint256 i = 0; i < extensionsLength; i++) {
                extensions[i] = data[offset + i];
            }
        }

        return ClientHello({
            version: version,
            random: random,
            sessionId: sessionId,
            cipherSuites: cipherSuites,
            compressionMethods: compressionMethods,
            extensions: extensions
        });
    }

    function parseServerHello(bytes memory data) internal pure returns (ServerHello memory) {
        if (data.length < 38) revert InvalidHandshakeMessage();

        uint256 offset = 0;
        
        uint8 msgType = uint8(data[offset++]);
        if (msgType != HANDSHAKE_TYPE_SERVER_HELLO) revert InvalidHandshakeMessage();

        offset += 3;

        uint16 version = (uint16(uint8(data[offset])) << 8) | uint16(uint8(data[offset + 1]));
        offset += 2;

        bytes32 random;
        assembly {
            random := mload(add(add(data, 0x20), offset))
        }
        offset += 32;

        uint8 sessionIdLength = uint8(data[offset++]);
        bytes memory sessionId = new bytes(sessionIdLength);
        for (uint256 i = 0; i < sessionIdLength; i++) {
            sessionId[i] = data[offset + i];
        }
        offset += sessionIdLength;

        uint16 cipherSuite = (uint16(uint8(data[offset])) << 8) | uint16(uint8(data[offset + 1]));
        offset += 2;

        uint8 compressionMethod = uint8(data[offset++]);

        bytes memory extensions;
        if (offset < data.length) {
            uint16 extensionsLength = (uint16(uint8(data[offset])) << 8) | uint16(uint8(data[offset + 1]));
            offset += 2;
            
            extensions = new bytes(extensionsLength);
            for (uint256 i = 0; i < extensionsLength; i++) {
                extensions[i] = data[offset + i];
            }
        }

        return ServerHello({
            version: version,
            random: random,
            sessionId: sessionId,
            cipherSuite: cipherSuite,
            compressionMethod: compressionMethod,
            extensions: extensions
        });
    }

    function validateTLSVersion(uint16 version) internal pure returns (bool) {
        return version == 0x0303 || version == 0x0304;
    }

    function extractHandshakeHash(bytes memory handshakeData) internal pure returns (bytes32) {
        return keccak256(handshakeData);
    }

    function computeRecordMAC(
        bytes memory record,
        bytes32 macKey,
        uint64 sequenceNumber
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(sequenceNumber, record, macKey));
    }
}