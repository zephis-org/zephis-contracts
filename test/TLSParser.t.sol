// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/tls/TLSParser.sol";

contract TLSParserWrapper {
    function parseTLSRecordWrapper(bytes memory data) external pure returns (TLSParser.TLSRecord memory) {
        return TLSParser.parseTLSRecord(data);
    }
    
    function parseClientHelloWrapper(bytes memory data) external pure returns (TLSParser.ClientHello memory) {
        return TLSParser.parseClientHello(data);
    }
    
    function parseServerHelloWrapper(bytes memory data) external pure returns (TLSParser.ServerHello memory) {
        return TLSParser.parseServerHello(data);
    }
}

contract TLSParserTest is Test {
    TLSParserWrapper wrapper;
    using TLSParser for bytes;

    function setUp() public {
        wrapper = new TLSParserWrapper();
    }

    function testParseTLSRecordValid() public pure {
        // Create a valid TLS record: ContentType(1) + Version(2) + Length(2) + Data
        bytes memory record = abi.encodePacked(
            uint8(22), // Handshake
            uint16(0x0303), // TLS 1.2
            uint16(5), // Length
            bytes5("hello")
        );
        
        TLSParser.TLSRecord memory parsed = TLSParser.parseTLSRecord(record);
        
        assertEq(parsed.contentType, 22);
        assertEq(parsed.version, 0x0303);
        assertEq(parsed.length, 5);
        assertEq(parsed.data, "hello");
    }

    function testParseTLSRecordInvalidLength() public {
        // Record too short
        bytes memory shortRecord = abi.encodePacked(uint8(22), uint16(0x0303));
        
        vm.expectRevert(TLSParser.InvalidTLSRecord.selector);
        wrapper.parseTLSRecordWrapper(shortRecord);
    }

    function testParseTLSRecordDataLengthMismatch() public {
        // Length field says 10 but only 5 bytes of data
        bytes memory record = abi.encodePacked(
            uint8(22),
            uint16(0x0303),
            uint16(10), // Says 10 bytes
            bytes5("hello") // Only 5 bytes
        );
        
        vm.expectRevert(TLSParser.InvalidTLSRecord.selector);
        wrapper.parseTLSRecordWrapper(record);
    }

    function testParseClientHelloValid() public pure {
        // Minimal valid ClientHello structure
        bytes memory clientHello = abi.encodePacked(
            uint8(1), // CLIENT_HELLO
            uint24(45), // Length (3 bytes)
            uint16(0x0303), // Protocol version
            bytes32(keccak256("client_random")), // Client random (32 bytes)
            uint8(0), // Session ID length
            uint16(4), // Cipher suites length
            uint16(0x1301), // TLS_AES_128_GCM_SHA256
            uint16(0x1302), // TLS_AES_256_GCM_SHA384
            uint8(1), // Compression methods length
            uint8(0) // No compression
        );
        
        TLSParser.ClientHello memory parsed = TLSParser.parseClientHello(clientHello);
        
        assertEq(parsed.version, 0x0303);
        assertEq(parsed.random, keccak256("client_random"));
        assertEq(parsed.sessionId.length, 0);
        assertEq(parsed.cipherSuites.length, 2);
        assertEq(parsed.cipherSuites[0], 0x1301);
        assertEq(parsed.cipherSuites[1], 0x1302);
        assertEq(parsed.compressionMethods.length, 1);
        assertEq(parsed.compressionMethods[0], 0);
    }

    function testParseClientHelloTooShort() public {
        bytes memory tooShort = abi.encodePacked(uint8(1), uint24(10));
        
        vm.expectRevert(TLSParser.InvalidHandshakeMessage.selector);
        wrapper.parseClientHelloWrapper(tooShort);
    }

    function testParseClientHelloWrongType() public {
        bytes memory wrongType = abi.encodePacked(
            uint8(2), // SERVER_HELLO instead of CLIENT_HELLO
            uint24(45),
            uint16(0x0303),
            bytes32(keccak256("client_random")),
            uint8(0),
            uint16(2),
            uint16(0x1301),
            uint8(1),
            uint8(0)
        );
        
        vm.expectRevert(TLSParser.InvalidHandshakeMessage.selector);
        wrapper.parseClientHelloWrapper(wrongType);
    }

    function testParseServerHelloValid() public pure {
        bytes memory serverHello = abi.encodePacked(
            uint8(2), // SERVER_HELLO
            uint24(38), // Length
            uint16(0x0303), // Protocol version
            bytes32(keccak256("server_random")), // Server random
            uint8(0), // Session ID length
            uint16(0x1301), // Chosen cipher suite
            uint8(0) // Compression method
        );
        
        TLSParser.ServerHello memory parsed = TLSParser.parseServerHello(serverHello);
        
        assertEq(parsed.version, 0x0303);
        assertEq(parsed.random, keccak256("server_random"));
        assertEq(parsed.sessionId.length, 0);
        assertEq(parsed.cipherSuite, 0x1301);
        assertEq(parsed.compressionMethod, 0);
    }

    function testParseServerHelloWithSessionId() public pure {
        bytes memory sessionIdData = "test_session_id";
        bytes memory serverHello = abi.encodePacked(
            uint8(2), // SERVER_HELLO
            uint24(38 + 1 + sessionIdData.length), // Length
            uint16(0x0303), // Protocol version
            bytes32(keccak256("server_random")), // Server random
            uint8(sessionIdData.length), // Session ID length
            sessionIdData, // Session ID
            uint16(0x1301), // Cipher suite
            uint8(0) // Compression method
        );
        
        TLSParser.ServerHello memory parsed = TLSParser.parseServerHello(serverHello);
        
        assertEq(parsed.sessionId, sessionIdData);
    }

    function testParseServerHelloWrongType() public {
        bytes memory wrongType = abi.encodePacked(
            uint8(1), // CLIENT_HELLO instead of SERVER_HELLO
            uint24(38),
            uint16(0x0303),
            bytes32(keccak256("server_random")),
            uint8(0),
            uint16(0x1301),
            uint8(0)
        );
        
        vm.expectRevert(TLSParser.InvalidHandshakeMessage.selector);
        wrapper.parseServerHelloWrapper(wrongType);
    }

    function testParseServerHelloTooShort() public {
        bytes memory tooShort = abi.encodePacked(uint8(2), uint24(10));
        
        vm.expectRevert(TLSParser.InvalidHandshakeMessage.selector);
        wrapper.parseServerHelloWrapper(tooShort);
    }

    function testValidateTLSVersionValid() public pure {
        assertTrue(TLSParser.validateTLSVersion(0x0303)); // TLS 1.2
        assertTrue(TLSParser.validateTLSVersion(0x0304)); // TLS 1.3
    }

    function testValidateTLSVersionInvalid() public pure {
        assertFalse(TLSParser.validateTLSVersion(0x0301)); // TLS 1.0
        assertFalse(TLSParser.validateTLSVersion(0x0302)); // TLS 1.1
        assertFalse(TLSParser.validateTLSVersion(0x0305)); // Future version
        assertFalse(TLSParser.validateTLSVersion(0x0000)); // Invalid
    }

    function testExtractHandshakeHash() public pure {
        bytes memory handshakeData = "test handshake data";
        bytes32 hash = TLSParser.extractHandshakeHash(handshakeData);
        
        assertEq(hash, keccak256(handshakeData));
    }

    function testExtractHandshakeHashEmpty() public pure {
        bytes memory emptyData = "";
        bytes32 hash = TLSParser.extractHandshakeHash(emptyData);
        
        assertEq(hash, keccak256(""));
    }

    function testComputeRecordMAC() public pure {
        bytes memory record = "test record data";
        bytes32 macKey = keccak256("mac key");
        uint64 sequenceNumber = 12345;
        
        bytes32 mac = TLSParser.computeRecordMAC(record, macKey, sequenceNumber);
        bytes32 expected = keccak256(abi.encodePacked(sequenceNumber, record, macKey));
        
        assertEq(mac, expected);
    }

    function testComputeRecordMACConsistency() public pure {
        bytes memory record = "test record";
        bytes32 macKey = keccak256("key");
        uint64 sequenceNumber = 1;
        
        bytes32 mac1 = TLSParser.computeRecordMAC(record, macKey, sequenceNumber);
        bytes32 mac2 = TLSParser.computeRecordMAC(record, macKey, sequenceNumber);
        
        assertEq(mac1, mac2);
    }

    function testComputeRecordMACDifferentSequence() public pure {
        bytes memory record = "test record";
        bytes32 macKey = keccak256("key");
        
        bytes32 mac1 = TLSParser.computeRecordMAC(record, macKey, 1);
        bytes32 mac2 = TLSParser.computeRecordMAC(record, macKey, 2);
        
        assertFalse(mac1 == mac2);
    }

    function testParseClientHelloWithExtensions() public pure {
        bytes memory extensions = "dummy_extensions";
        bytes memory header = abi.encodePacked(
            uint8(1), // CLIENT_HELLO
            uint24(45 + 2 + extensions.length), // Length with extensions
            uint16(0x0303), // Protocol version
            bytes32(keccak256("client_random")), // Client random
            uint8(0) // Session ID length
        );
        
        bytes memory middle = abi.encodePacked(
            uint16(2), // Cipher suites length
            uint16(0x1301), // Cipher suite
            uint8(1), // Compression methods length
            uint8(0) // Compression method
        );
        
        bytes memory tail = abi.encodePacked(
            uint16(extensions.length), // Extensions length
            extensions // Extensions data
        );
        
        bytes memory clientHello = abi.encodePacked(header, middle, tail);
        
        TLSParser.ClientHello memory parsed = TLSParser.parseClientHello(clientHello);
        
        assertEq(parsed.extensions, extensions);
    }

    function testParseServerHelloWithExtensions() public pure {
        bytes memory extensions = "server_extensions";
        bytes memory header = abi.encodePacked(
            uint8(2), // SERVER_HELLO
            uint24(38 + 2 + extensions.length), // Length with extensions
            uint16(0x0303), // Protocol version
            bytes32(keccak256("server_random")), // Server random
            uint8(0) // Session ID length
        );
        
        bytes memory middle = abi.encodePacked(
            uint16(0x1301), // Cipher suite
            uint8(0), // Compression method
            uint16(extensions.length) // Extensions length
        );
        
        bytes memory serverHello = abi.encodePacked(header, middle, extensions);
        
        TLSParser.ServerHello memory parsed = TLSParser.parseServerHello(serverHello);
        
        assertEq(parsed.extensions, extensions);
    }

    function testTLSRecordTypes() public pure {
        // Test all defined content types
        assertEq(TLSParser.CONTENT_TYPE_CHANGE_CIPHER_SPEC, 20);
        assertEq(TLSParser.CONTENT_TYPE_ALERT, 21);
        assertEq(TLSParser.CONTENT_TYPE_HANDSHAKE, 22);
        assertEq(TLSParser.CONTENT_TYPE_APPLICATION_DATA, 23);
    }

    function testHandshakeTypes() public pure {
        // Test all defined handshake types
        assertEq(TLSParser.HANDSHAKE_TYPE_CLIENT_HELLO, 1);
        assertEq(TLSParser.HANDSHAKE_TYPE_SERVER_HELLO, 2);
        assertEq(TLSParser.HANDSHAKE_TYPE_CERTIFICATE, 11);
        assertEq(TLSParser.HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE, 12);
        assertEq(TLSParser.HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, 16);
        assertEq(TLSParser.HANDSHAKE_TYPE_FINISHED, 20);
    }

    function testLargeClientHello() public pure {
        // Test with multiple cipher suites - simplified to reduce stack depth
        bytes memory part1 = abi.encodePacked(
            uint8(1), // CLIENT_HELLO
            uint24(55), // Length
            uint16(0x0303), // Protocol version
            bytes32(keccak256("client_random")), // Client random
            uint8(0) // Session ID length
        );
        
        bytes memory part2 = abi.encodePacked(
            uint16(12), // Cipher suites length (6 cipher suites)
            uint16(0x1301), uint16(0x1302), uint16(0x1303),
            uint16(0xC02F), uint16(0xC030), uint16(0xC02B)
        );
        
        bytes memory part3 = abi.encodePacked(
            uint8(3), // Compression methods length
            uint8(0), uint8(1), uint8(2) // Multiple compression methods
        );
        
        bytes memory clientHello = abi.encodePacked(part1, part2, part3);
        
        TLSParser.ClientHello memory parsed = TLSParser.parseClientHello(clientHello);
        
        assertEq(parsed.cipherSuites.length, 6);
        assertEq(parsed.compressionMethods.length, 3);
        assertEq(parsed.cipherSuites[0], 0x1301);
        assertEq(parsed.cipherSuites[5], 0xC02B);
        assertEq(parsed.compressionMethods[2], 2);
    }

    function testParseClientHelloWithoutExtensions() public pure {
        // Test the branch where offset >= data.length (no extensions)
        bytes memory clientHelloNoExt = abi.encodePacked(
            uint8(1), // CLIENT_HELLO
            uint24(45), // Length
            uint16(0x0303), // Protocol version
            bytes32(keccak256("client_random")), // Client random
            uint8(0), // Session ID length
            uint16(2), // Cipher suites length  
            uint16(0x1301), // Cipher suite
            uint8(1), // Compression methods length
            uint8(0) // Compression method - no extensions after this
        );
        
        TLSParser.ClientHello memory parsed = TLSParser.parseClientHello(clientHelloNoExt);
        
        assertEq(parsed.extensions.length, 0);
    }

    function testParseServerHelloWithoutExtensions() public pure {
        // Test the branch where offset >= data.length (no extensions)
        bytes memory serverHelloNoExt = abi.encodePacked(
            uint8(2), // SERVER_HELLO
            uint24(38), // Length
            uint16(0x0303), // Protocol version
            bytes32(keccak256("server_random")), // Server random
            uint8(0), // Session ID length
            uint16(0x1301), // Cipher suite
            uint8(0) // Compression method - no extensions after this
        );
        
        TLSParser.ServerHello memory parsed = TLSParser.parseServerHello(serverHelloNoExt);
        
        assertEq(parsed.extensions.length, 0);
    }

    function testParseTLSRecordEmptyData() public pure {
        // Test with zero length data
        bytes memory record = abi.encodePacked(
            uint8(23), // Application Data
            uint16(0x0303), // TLS 1.2
            uint16(0) // Zero length
        );
        
        TLSParser.TLSRecord memory parsed = TLSParser.parseTLSRecord(record);
        
        assertEq(parsed.contentType, 23);
        assertEq(parsed.version, 0x0303);
        assertEq(parsed.length, 0);
        assertEq(parsed.data.length, 0);
    }

    function testParseTLSRecordMinimumSize() public {
        // Test exactly 5 bytes (minimum size)
        bytes memory record = abi.encodePacked(
            uint8(21), // Alert
            uint16(0x0304), // TLS 1.3
            uint16(0) // Zero length
        );
        
        assertEq(record.length, 5);
        
        TLSParser.TLSRecord memory parsed = TLSParser.parseTLSRecord(record);
        assertEq(parsed.contentType, 21);
    }

    function testParseTLSRecordExactly4Bytes() public {
        // Test exactly 4 bytes (too short)
        bytes memory tooShort = new bytes(4);
        tooShort[0] = bytes1(uint8(22));
        tooShort[1] = bytes1(uint8(0x03));
        tooShort[2] = bytes1(uint8(0x03));
        tooShort[3] = bytes1(uint8(0x00));
        
        vm.expectRevert(TLSParser.InvalidTLSRecord.selector);
        wrapper.parseTLSRecordWrapper(tooShort);
    }

    function testParseClientHelloExactlyMinSize() public pure {
        // Test exactly minimum size requirement (length check is >= 34)
        bytes memory minClientHello = abi.encodePacked(
            uint8(1), // CLIENT_HELLO
            uint24(30), // Length
            uint16(0x0303), // Protocol version  
            bytes32(keccak256("min_random")), // Client random (32 bytes)
            uint8(0), // Session ID length
            uint16(0), // Cipher suites length (0)
            uint8(0) // Compression methods length (0)
        );
        
        // This will be 1+3+2+32+1+2+1 = 42 bytes total
        assertEq(minClientHello.length, 42);
        
        // Test that it doesn't revert on minimum size
        TLSParser.ClientHello memory parsed = TLSParser.parseClientHello(minClientHello);
        assertEq(parsed.version, 0x0303);
        assertEq(parsed.cipherSuites.length, 0);
        assertEq(parsed.compressionMethods.length, 0);
    }

    function testParseClientHello33Bytes() public {
        // Test 33 bytes (just below minimum)
        bytes memory tooSmall = new bytes(33);
        tooSmall[0] = bytes1(uint8(1)); // CLIENT_HELLO
        
        vm.expectRevert(TLSParser.InvalidHandshakeMessage.selector);
        wrapper.parseClientHelloWrapper(tooSmall);
    }

    function testParseServerHello37Bytes() public {
        // Test 37 bytes (just below minimum of 38)
        bytes memory tooSmall = new bytes(37);
        tooSmall[0] = bytes1(uint8(2)); // SERVER_HELLO
        
        vm.expectRevert(TLSParser.InvalidHandshakeMessage.selector);
        wrapper.parseServerHelloWrapper(tooSmall);
    }

    function testValidateTLSVersionBoundaryValues() public pure {
        // Test boundary values for TLS version validation
        assertFalse(TLSParser.validateTLSVersion(0x0302)); // TLS 1.1 (just below 1.2)
        assertTrue(TLSParser.validateTLSVersion(0x0303));  // TLS 1.2 (valid)
        assertTrue(TLSParser.validateTLSVersion(0x0304));  // TLS 1.3 (valid)  
        assertFalse(TLSParser.validateTLSVersion(0x0305)); // Future version (just above 1.3)
    }
}