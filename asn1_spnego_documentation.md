# ASN.1 DER Library and SPNEGO/GSS-API Extension Documentation

## Table of Contents
1. [Overview](#overview)
2. [Installation and Setup](#installation-and-setup)
3. [ASN.1 DER Base Library](#asn1-der-base-library)
4. [SPNEGO/GSS-API Extension](#spnegogss-api-extension)
5. [API Reference](#api-reference)
6. [Protocol Integration](#protocol-integration)
7. [Examples and Use Cases](#examples-and-use-cases)
8. [Placeholder Implementations](#placeholder-implementations)
9. [Testing](#testing)
10. [Troubleshooting](#troubleshooting)
11. [Security Considerations](#security-considerations)

## Overview

This library provides a comprehensive ASN.1 DER (Distinguished Encoding Rules) implementation in Nim, specifically designed for Windows authentication protocols. It includes a full-featured SPNEGO (Simple and Protected GSSAPI Negotiation Mechanism) and GSS-API extension for handling authentication in protocols like SMB, LDAP, and HTTP Negotiate.

### Key Features
- Complete ASN.1 DER encoding/decoding
- SPNEGO token building and parsing
- GSS-API token wrapping
- Support for Kerberos, NTLM, and other authentication mechanisms
- Cross-platform compatibility
- Zero external dependencies for core functionality

### Project Structure
```
/
├── asn1.nim                    # Base ASN.1 DER library
├── gssapi/
│   └── main.nim                # SPNEGO/GSS-API extension
├── tests/
│   ├── main.nim                # Base library tests
│   └── gssapi_tests.nim        # SPNEGO/GSS-API tests
└── examples/
    └── gssapi_examples.nim     # Usage examples
```

### Architecture
```
┌─────────────────────────────────────┐
│         Application Layer           │
│    (SMB, LDAP, HTTP, RPC, etc.)    │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│      SPNEGO/GSS-API Extension      │
│  (Token negotiation & wrapping)    │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│      ASN.1 DER Base Library        │
│   (Encoding/Decoding primitives)   │
└─────────────────────────────────────┘
```

## Installation and Setup

### Requirements
- Nim 1.6.0 or higher
- No external dependencies for core functionality

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd asn1-project

# Compile the library
nim c -d:release asn1.nim
nim c -d:release gssapi/main.nim

# Run tests
nim c -r tests/main.nim
nim c -r tests/gssapi_tests.nim

# Run examples
nim c -r examples/gssapi_examples.nim
```

### Quick Start

```nim
import asn1
import gssapi/main

# Basic ASN.1 encoding
let myInt = newAsn1Integer(42)
let encoded = encode(myInt)

# SPNEGO negotiation
let ctx = newSpnegoContext(true, @[OID_KERBEROS5, OID_NTLMSSP])
let token = ctx.createInitialToken()
```

## ASN.1 DER Base Library

### Introduction

ASN.1 (Abstract Syntax Notation One) with DER (Distinguished Encoding Rules) is the foundation for many cryptographic and authentication protocols. This library implements the core ASN.1 types and provides efficient encoding/decoding operations.

### Supported Types

| Type | Tag | Description | Usage |
|------|-----|-------------|--------|
| BOOLEAN | 0x01 | True/False values | Flags, options |
| INTEGER | 0x02 | Arbitrary precision integers | Serial numbers, versions |
| BIT STRING | 0x03 | Bit sequences | Flags, keys |
| OCTET STRING | 0x04 | Byte sequences | Raw data, hashes |
| NULL | 0x05 | Empty value | Algorithm parameters |
| OBJECT IDENTIFIER | 0x06 | Hierarchical identifiers | Algorithm IDs, attributes |
| UTF8String | 0x0C | UTF-8 text | Modern text fields |
| SEQUENCE | 0x30 | Ordered collection | Structures, certificates |
| SET | 0x31 | Unordered collection | Attributes |
| PrintableString | 0x13 | Limited ASCII | Legacy names |
| IA5String | 0x16 | ASCII text | Email, URLs |

### Basic Usage

#### Encoding Examples

```nim
import asn1

# Encode an integer
let myInt = newAsn1Integer(12345)
let encoded = encode(myInt)

# Encode a sequence
let seq = newAsn1Sequence(
  newAsn1Integer(1),
  newAsn1UTF8String("Hello"),
  newAsn1Boolean(true)
)
let seqEncoded = encode(seq)

# Encode an Object Identifier
let oid = newAsn1ObjectIdentifier("1.2.840.113549.1.1.11")
let oidEncoded = encode(oid)

# Build complex structures
let cert = newAsn1Sequence(
  newAsn1Integer(2),  # version
  newAsn1Integer(12345),  # serial
  newAsn1Sequence(  # algorithm
    newAsn1ObjectIdentifier("1.2.840.113549.1.1.11"),
    newAsn1Null()
  ),
  newAsn1UTF8String("CN=Test CA")  # issuer
)
```

#### Decoding Examples

```nim
# Decode an integer
var dec = DerDecoder(data: someBytes, pos: 0)
let decodedInt = dec.decodeInteger()
let value = decodedInt.toInt64()

# Decode a sequence
var seqDec = DerDecoder(data: seqBytes, pos: 0)
let (tag, constructed, class) = seqDec.readTag()
if tag == 16 and constructed:  # SEQUENCE tag number is 16
  let length = seqDec.readLength()
  # Process sequence contents

# Decode an OCTET STRING
let octets = dec.decodeOctetString()
let text = octets.mapIt(char(it)).join("")
```

### Advanced Features

#### Tagged Values
Support for context-specific, application, and private class tags:

```nim
var enc = DerEncoder()
enc.encodeTagged(0, classContext, false, proc(e: var DerEncoder) =
  e.encodeInteger(fromInt64(42))
)
# Produces: [0] INTEGER 42
```

#### Length Encoding
Automatic handling of short and long form length encoding:
- Short form: lengths < 128 bytes
- Long form: lengths ≥ 128 bytes (up to 4GB)

#### Integer Handling
- Proper two's complement encoding for negative numbers
- Automatic padding for sign bit preservation
- Support for arbitrary precision (limited by memory)

```nim
# Negative numbers work correctly
let negInt = newAsn1Integer(-12345)
let encoded = encode(negInt)
var dec = DerDecoder(data: encoded, pos: 0)
let decoded = dec.decodeInteger()
assert decoded.toInt64() == -12345
```

## SPNEGO/GSS-API Extension

### Introduction

SPNEGO (RFC 4178) enables negotiation of authentication mechanisms between clients and servers. It's widely used in Windows environments for protocols like SMB, LDAP, and HTTP.

### Core Components

#### Token Types

**NegTokenInit** - Initial negotiation token from client:
- `mechTypes`: List of supported mechanisms (OIDs)
- `reqFlags`: Optional context flags
- `mechToken`: Optional initial mechanism token
- `mechListMIC`: Optional integrity check

**NegTokenResp** - Response token from server:
- `negState`: Negotiation state (accept-completed, accept-incomplete, reject, request-mic)
- `supportedMech`: Selected mechanism OID
- `responseToken`: Optional response data
- `mechListMIC`: Optional integrity check

#### Supported Mechanisms

| Mechanism | OID | Description |
|-----------|-----|-------------|
| SPNEGO | 1.3.6.1.5.5.2 | Negotiation mechanism |
| Kerberos V5 | 1.2.840.113554.1.2.2 | MIT Kerberos |
| MS-Kerberos | 1.2.840.48018.1.2.2 | Microsoft Kerberos |
| NTLMSSP | 1.3.6.1.4.1.311.2.2.10 | NTLM Security Support Provider |
| NegoEx | 1.3.6.1.4.1.311.2.2.30 | Extended negotiation |

### SPNEGO Usage

#### Simple Negotiation

```nim
import gssapi/main

# Client side
let clientCtx = newSpnegoContext(true, @[OID_KERBEROS5, OID_NTLMSSP])
let initToken = clientCtx.createInitialToken()

# Server side
let serverCtx = newSpnegoContext(false, @[OID_KERBEROS5, OID_NTLMSSP])
let (response, complete) = serverCtx.processToken(initToken)

# Continue until both sides complete
```

#### With Kerberos Token

```nim
# Wrap Kerberos ticket in SPNEGO
let kerberosTicket = getKerberosTicket()  # Your implementation
let spnegoToken = createSpnegoKerberosInit(kerberosTicket, 
                                           includeNtlm = true)

# Send in authentication header
let authHeader = "Negotiate " & base64.encode(spnegoToken)
```

### GSS-API Context Flags

| Flag | Description | Use Case |
|------|-------------|----------|
| `gssDelegFlag` | Delegate credentials | Impersonation |
| `gssMutualFlag` | Mutual authentication | Verify server identity |
| `gssReplayFlag` | Replay detection | Prevent replay attacks |
| `gssSequenceFlag` | Sequence checking | Detect out-of-order |
| `gssConfFlag` | Confidentiality | Encryption support |
| `gssIntegFlag` | Integrity | Message integrity |

## API Reference

### ASN.1 DER Core Types

```nim
type
  Asn1Type = ref object of RootObj
    tag*: uint8
    class*: Asn1Class
    constructed*: bool

  Asn1Boolean = ref object of Asn1Type
    value*: bool

  Asn1Integer = ref object of Asn1Type
    value*: seq[uint8]  # Big-endian bytes

  Asn1OctetString = ref object of Asn1Type
    value*: seq[uint8]

  Asn1Sequence = ref object of Asn1Type
    elements*: seq[Asn1Type]

  Asn1ObjectIdentifier = ref object of Asn1Type
    value*: seq[uint32]
```

### Encoding Functions

```nim
# High-level encoding
proc encode*(value: Asn1Type): seq[uint8]

# Low-level encoding
proc encodeBoolean*(enc: var DerEncoder, value: bool)
proc encodeInteger*(enc: var DerEncoder, value: Asn1Integer)
proc encodeOctetString*(enc: var DerEncoder, value: seq[uint8])
proc encodeSequence*(enc: var DerEncoder, elements: seq[proc(e: var DerEncoder)])
proc encodeObjectIdentifier*(enc: var DerEncoder, oid: seq[uint32])

# Tagged values
proc encodeTagged*(enc: var DerEncoder, tagNumber: uint32, 
                   class: Asn1Class, constructed: bool, 
                   content: proc(e: var DerEncoder))
```

### Decoding Functions

```nim
proc decodeBoolean*(dec: var DerDecoder): bool
proc decodeInteger*(dec: var DerDecoder): Asn1Integer
proc decodeOctetString*(dec: var DerDecoder): seq[uint8]
proc decodeObjectIdentifier*(dec: var DerDecoder): seq[uint32]
proc decodeUTF8String*(dec: var DerDecoder): string

# Low-level parsing
proc readTag*(dec: var DerDecoder): tuple[tag: uint32, constructed: bool, class: Asn1Class]
proc readLength*(dec: var DerDecoder): int
proc readBytes*(dec: var DerDecoder, length: int): seq[uint8]
```

### SPNEGO Functions

```nim
# Token building
proc buildNegTokenInit*(token: SpnegoNegTokenInit): seq[uint8]
proc buildNegTokenResp*(token: SpnegoNegTokenResp): seq[uint8]

# Token parsing
proc parseNegTokenInit*(data: seq[uint8]): SpnegoNegTokenInit
proc parseNegTokenResp*(data: seq[uint8]): SpnegoNegTokenResp

# GSS-API wrapping
proc wrapGssApiToken*(oid: string, innerToken: seq[uint8]): seq[uint8]
proc unwrapGssApiToken*(token: seq[uint8]): tuple[oid: string, innerToken: seq[uint8]]

# Context management
proc newSpnegoContext*(isInitiator: bool, availableMechs: seq[string]): SpnegoContext
proc createInitialToken*(ctx: SpnegoContext, mechToken: seq[uint8] = @[], 
                        flags: GssFlags = {}): seq[uint8]
proc processToken*(ctx: SpnegoContext, token: seq[uint8]): 
                  tuple[responseToken: seq[uint8], isComplete: bool]

# Utilities
proc isSpnegoToken*(token: seq[uint8]): bool
proc extractMechanismToken*(token: seq[uint8]): seq[uint8]
proc createSpnegoKerberosInit*(kerberosToken: seq[uint8], 
                               includeNtlm: bool = false): seq[uint8]
```

## Protocol Integration

### HTTP Negotiate Authentication

```nim
import std/[httpclient, base64]
import gssapi/main

proc authenticateHttp*(url: string) =
  # Create SPNEGO context
  let ctx = newSpnegoContext(true, @[OID_KERBEROS5, OID_NTLMSSP])
  let initToken = ctx.createInitialToken()
  
  # First request with Negotiate header
  var client = newHttpClient()
  client.headers = newHttpHeaders({
    "Authorization": "Negotiate " & encode(initToken)
  })
  
  let response = client.get(url)
  
  # Process server challenge
  if response.code == Http401:
    let authHeader = response.headers["WWW-Authenticate"]
    if authHeader.startsWith("Negotiate "):
      let serverToken = decode(authHeader[10..^1])
      let (clientResp, done) = ctx.processToken(serverToken)
      
      # Send final authentication
      client.headers["Authorization"] = "Negotiate " & encode(clientResp)
      let finalResponse = client.get(url)
```

### SMB Authentication with NTLM Only

```nim
import asn1
import gssapi/main
import std/[base64, options]

proc createNtlmType1Message(): seq[uint8] =
  ## Create NTLM Type 1 (Negotiate) message
  result = @[]
  
  # Signature "NTLMSSP\0"
  result.add([0x4E'u8, 0x54, 0x4C, 0x4D])  # "NTLM"
  result.add([0x53'u8, 0x53, 0x50, 0x00])  # "SSP\0"
  
  # Message Type (1)
  result.add([0x01'u8, 0x00, 0x00, 0x00])
  
  # Flags (Unicode, OEM, Request Target, NTLM, Always Sign)
  let flags: uint32 = 0x00008207
  result.add([
    uint8(flags and 0xFF),
    uint8((flags shr 8) and 0xFF),
    uint8((flags shr 16) and 0xFF),
    uint8((flags shr 24) and 0xFF)
  ])
  
  # Domain and Workstation (empty for Type 1)
  result.add(newSeq[uint8](16))

proc setupSmbAuthenticationNtlmOnly*(): seq[uint8] =
  ## SMB authentication using only NTLM
  
  # Create SPNEGO context with ONLY NTLM
  let smbCtx = newSpnegoContext(true, @[OID_NTLMSSP])
  
  # Create NTLM Type 1 message
  let ntlmType1 = createNtlmType1Message()
  
  # Wrap NTLM in SPNEGO
  var negTokenInit = SpnegoNegTokenInit()
  negTokenInit.mechTypes = @[OID_NTLMSSP]  # Only NTLM
  negTokenInit.reqFlags = some({
    gssMutualFlag,
    gssIntegFlag,     # Required for SMB
    gssReplayFlag,
    gssSequenceFlag
  })
  negTokenInit.mechToken = some(ntlmType1)
  
  let spnegoToken = buildNegTokenInit(negTokenInit)
  result = wrapGssApiToken(OID_SPNEGO, spnegoToken)
```

### SMB with Kerberos Preferred, NTLM Fallback

```nim
proc setupSmbAuthenticationWithFallback*(): seq[uint8] =
  ## SMB authentication preferring Kerberos with NTLM fallback
  
  # Create context with both mechanisms
  let ctx = newSpnegoContext(true, @[OID_KERBEROS5, OID_MS_KRB5, OID_NTLMSSP])
  
  var mechToken: seq[uint8] = @[]
  var preferredMechs: seq[string] = @[]
  
  try:
    # Try Kerberos first
    mechToken = getKerberosServiceTicket("cifs/fileserver.domain.com")
    preferredMechs = @[OID_KERBEROS5, OID_MS_KRB5, OID_NTLMSSP]
    echo "Using Kerberos authentication"
  except:
    # Fall back to NTLM
    mechToken = createNtlmType1Message()
    preferredMechs = @[OID_NTLMSSP]
    echo "Falling back to NTLM authentication"
  
  # Create SPNEGO token
  var negToken = SpnegoNegTokenInit()
  negToken.mechTypes = preferredMechs
  negToken.reqFlags = some({gssMutualFlag, gssIntegFlag, gssReplayFlag})
  negToken.mechToken = some(mechToken)
  
  let spnegoToken = buildNegTokenInit(negToken)
  result = wrapGssApiToken(OID_SPNEGO, spnegoToken)
```

### LDAP SASL Bind

```nim
proc ldapSaslBind*(connection: LdapConnection, username: string) =
  # Create SPNEGO context
  let ctx = newSpnegoContext(true, @[OID_KERBEROS5])
  
  # Get Kerberos ticket for LDAP service
  let krbTicket = getKerberosServiceTicket($"ldap/{connection.host}")
  let spnegoToken = createSpnegoKerberosInit(krbTicket, false)
  
  # Build LDAP BindRequest
  let bindRequest = newAsn1Sequence(
    newAsn1Integer(3),  # LDAP version 3
    newAsn1OctetString(""),  # Empty DN for SASL
    Asn1Type(newAsn1Sequence(  # SASL authentication choice
      newAsn1OctetString("GSS-SPNEGO"),
      newAsn1OctetString(spnegoToken)
    ))
  )
  
  # Send bind request
  connection.send(encode(bindRequest))
```

## Examples and Use Cases

### Certificate Subject Creation

```nim
# Create X.509 distinguished name
proc createX509Subject*(cn, ou, o, c: string): seq[uint8] =
  var rdns: seq[Asn1Type] = @[]
  
  if c.len > 0:
    rdns.add(newAsn1Set(newAsn1Sequence(
      newAsn1ObjectIdentifier("2.5.4.6"),  # countryName
      newAsn1PrintableString(c)
    )))
  
  if o.len > 0:
    rdns.add(newAsn1Set(newAsn1Sequence(
      newAsn1ObjectIdentifier("2.5.4.10"),  # organizationName
      newAsn1UTF8String(o)
    )))
  
  if ou.len > 0:
    rdns.add(newAsn1Set(newAsn1Sequence(
      newAsn1ObjectIdentifier("2.5.4.11"),  # organizationalUnitName
      newAsn1UTF8String(ou)
    )))
  
  if cn.len > 0:
    rdns.add(newAsn1Set(newAsn1Sequence(
      newAsn1ObjectIdentifier("2.5.4.3"),  # commonName
      newAsn1UTF8String(cn)
    )))
  
  let dn = newAsn1SequenceFromSeq(rdns)
  result = encode(dn)
```

### Token Analysis Tool

```nim
proc analyzeSpnegoToken*(tokenBytes: seq[uint8]) =
  if not isSpnegoToken(tokenBytes):
    echo "Not a SPNEGO token"
    return
  
  let (oid, innerToken) = unwrapGssApiToken(tokenBytes)
  var dec = DerDecoder(data: innerToken, pos: 0)
  let (tag, _, class) = dec.readTag()
  dec.pos = 0
  
  if tag == 0 and class == classContext:
    let negTokenInit = parseNegTokenInit(innerToken)
    echo "Token type: NegTokenInit"
    echo "Mechanisms offered:"
    for mech in negTokenInit.mechTypes:
      echo "  - ", mech
    
    if negTokenInit.reqFlags.isSome:
      let flags = negTokenInit.reqFlags.get()
      echo "Requested flags:"
      if gssMutualFlag in flags: echo "  - Mutual authentication"
      if gssIntegFlag in flags: echo "  - Integrity"
      if gssConfFlag in flags: echo "  - Confidentiality"
```

## Placeholder Implementations

### Important Notice
Several functions in this library contain placeholder implementations that need completion for production use. These return dummy data and are marked with comments.

### SPNEGO/GSS-API Placeholders

#### 1. Mechanism Token Processing
**Location**: `gssapi/main.nim`, `processToken` function

**Current**:
```nim
# Placeholder response
respToken.responseToken = some(@[0x01'u8, 0x02, 0x03])
```

**Required Implementation**:
- Kerberos AP-REQ/AP-REP processing
- NTLM Type 2/3 message handling
- Session key establishment
- Credential validation

#### 2. MIC Calculation
**Not Implemented**: Message Integrity Check generation

**Required**:
- HMAC-MD5 or HMAC-SHA256 implementation
- Key derivation from security context
- Proper GSS-API checksum format

#### 3. Kerberos Integration
**Not Implemented**: `getKerberosServiceTicket`, `getKerberosApReq`

**Required**:
```nim
proc getKerberosServiceTicket*(servicePrincipal: string): seq[uint8] =
  # Connect to KDC
  # Send TGS-REQ
  # Parse TGS-REP
  # Build AP-REQ
```

#### 4. NTLM Processing
**Partially Implemented**: Type 2 and Type 3 messages

**Required**:
- NTLMv2 hash calculation
- Challenge-response computation
- Target information parsing
- Session key derivation

### ASN.1 DER Placeholders

#### 1. Time Types
**Not Implemented**: UTCTime, GeneralizedTime

**Required Format**:
- UTCTime: YYMMDDhhmmssZ
- GeneralizedTime: YYYYMMDDhhmmss[.fff]Z

#### 2. REAL Type
**Not Implemented**: Floating-point encoding

#### 3. String Validation
**Partial**: PrintableString character set validation

**Required**:
```nim
const PrintableChars = {' ', '\'', '(', ')', '+', ',', '-', '.', '/', 
                       '0'..'9', ':', '=', '?', 'A'..'Z', 'a'..'z'}
```

### Security Features Not Implemented

#### 1. Replay Protection
- Replay cache for authenticators
- Timestamp validation
- Nonce tracking

#### 2. Channel Binding
- TLS channel binding (RFC 5929)
- Binding data in tokens

#### 3. Encryption Support
- GSS-API wrap/unwrap
- Confidentiality protection
- Key derivation

### Completing the Implementation

For production use:
1. Replace all placeholder byte arrays
2. Integrate with crypto libraries
3. Add proper error handling
4. Implement security validations
5. Add logging capabilities

## Testing

### Running Tests

```bash
# Run base ASN.1 library tests
nim c -r tests/main.nim

# Run SPNEGO/GSS-API tests
nim c -r tests/gssapi_tests.nim

# Run with verbose output
nim c -r -d:verbose tests/main.nim

# Run examples
nim c -r examples/gssapi_examples.nim
```

### Test Coverage

**ASN.1 DER Base Library**:
- 70+ tests covering all types
- Edge cases and error conditions
- Round-trip encoding/decoding
- Complex structure handling

**SPNEGO/GSS-API Extension**:
- 45+ tests for token operations
- Negotiation flow testing
- Error handling scenarios
- Integration tests

### Writing Custom Tests

```nim
import unittest
import asn1
import gssapi/main

suite "Custom SPNEGO Tests":
  test "My specific scenario":
    let ctx = newSpnegoContext(true, @[OID_KERBEROS5])
    let token = ctx.createInitialToken()
    check isSpnegoToken(token)
    check token.len > 0
```

## Troubleshooting

### Common Issues and Solutions

#### Type Mismatch Errors
**Problem**: Compilation errors when mixing ASN.1 types
```nim
# Error: type mismatch
let seq = newAsn1Sequence(myInteger, mySequence)
```

**Solution**: Use explicit casting
```nim
let seq = newAsn1Sequence(myInteger, Asn1Type(mySequence))
```

#### OID Encoding Failures
**Problem**: "Invalid OID" errors

**Solutions**:
- First arc must be 0, 1, or 2
- Second arc limited to 39 when first is 0 or 1
- Use string notation: `"1.2.840.113549"`

#### SPNEGO Negotiation Failures
**Problem**: Server rejects authentication

**Check**:
- Mechanism OIDs match between client/server
- Required flags are set (especially for SMB)
- Token wrapping is correct

#### Tag Number Confusion
**Problem**: "Expected SEQUENCE" errors

**Note**: `readTag()` returns tag number (16), not full byte (0x30)
```nim
# Correct check:
if tag == 16 and constructed:  # SEQUENCE
# Not:
if tag == 0x30:  # Wrong!
```

### Debug Techniques

```nim
# Enable debug output
proc debugToken(data: seq[uint8]) =
  echo "Token hex: ", data.mapIt(it.toHex(2)).join(" ")
  var dec = DerDecoder(data: data, pos: 0)
  let (tag, constructed, class) = dec.readTag()
  echo "Tag: ", tag, " Constructed: ", constructed
  echo "Class: ", class

# Add to tests
when defined(debug):
  debugToken(myToken)
```

### Performance Optimization

```nim
# Pre-allocate buffers for large structures
var enc = DerEncoder()
enc.buffer = newSeqOfCap[uint8](1024)

# Reuse decoder instances
var dec = DerDecoder(data: data, pos: 0)
# Process multiple values with same decoder
```

## Security Considerations

### Production Deployment

1. **Never use placeholders in production** - They provide no security
2. **Validate all input** - Check lengths, ranges, and formats
3. **Use established crypto** - Don't implement your own
4. **Follow specifications** - RFC compliance is critical
5. **Enable all security features**:
   - Replay detection
   - Sequence numbering
   - Integrity checks
   - Channel binding (when available)

### SMB-Specific Security

For SMB authentication:
- Always enable signing (`gssIntegFlag`)
- Use sequence checking (`gssSequenceFlag`)
- Prefer Kerberos over NTLM
- If using NTLM, use only NTLMv2

### HTTP Negotiate Security

- Implement channel binding for HTTPS
- Validate server certificates
- Use persistent connections to avoid re-authentication
- Clear credentials after use

### LDAP Security

- Use LDAPS (LDAP over SSL/TLS) when possible
- Implement SASL security layers
- Validate server certificates
- Use strong authentication (avoid anonymous bind)

## Performance Considerations

### Memory Management

```nim
# Efficient sequence building
var elements = newSeqOfCap[Asn1Type](100)
# Add elements...
let seq = newAsn1SequenceFromSeq(elements)

# Reuse buffers
var enc {.global.} = DerEncoder()
enc.buffer.setLen(0)  # Clear for reuse
```

### Optimization Tips

1. **Pre-calculate sizes** when possible
2. **Use stack allocation** for small structures
3. **Cache encoded values** that don't change
4. **Batch operations** to reduce allocations

## Contributing

### Development Guidelines

1. **Follow Nim style guide**
2. **Add tests for new features**
3. **Document public APIs**
4. **Maintain backward compatibility**
5. **Security review for auth code**

### Submitting Changes

1. Fork the repository
2. Create feature branch
3. Add tests and documentation
4. Ensure all tests pass
5. Submit pull request

### Areas Needing Contribution

- Complete Kerberos integration
- Full NTLM implementation
- Additional ASN.1 types (TIME, REAL)
- Platform-specific optimizations
- Security audit and hardening

## References

### Specifications

- **ASN.1**: ITU-T X.680-X.683
- **DER**: ITU-T X.690
- **SPNEGO**: RFC 4178
- **GSS-API**: RFC 2743
- **Kerberos**: RFC 4120
- **NTLM**: MS-NLMP

### Related Projects

- MIT Kerberos
- Heimdal
- Samba (SMB implementation)
- OpenLDAP

## License

This library is provided for educational and integration purposes. Ensure compliance with relevant specifications and licenses when using in production.

## Appendix: Complete API List

### ASN.1 Constructors
- `newAsn1Boolean(value: bool): Asn1Boolean`
- `newAsn1Integer(value: int64): Asn1Integer`
- `newAsn1OctetString(value: seq[uint8]): Asn1OctetString`
- `newAsn1OctetString(value: string): Asn1OctetString`
- `newAsn1BitString(value: seq[uint8], unused: uint8): Asn1BitString`
- `newAsn1Null(): Asn1Null`
- `newAsn1ObjectIdentifier(oid: seq[uint32]): Asn1ObjectIdentifier`
- `newAsn1ObjectIdentifier(oid: string): Asn1ObjectIdentifier`
- `newAsn1UTF8String(value: string): Asn1String`
- `newAsn1PrintableString(value: string): Asn1String`
- `newAsn1IA5String(value: string): Asn1String`
- `newAsn1Sequence(elements: varargs[Asn1Type]): Asn1Sequence`
- `newAsn1SequenceFromSeq(elements: seq[Asn1Type]): Asn1Sequence`
- `newAsn1Set(elements: varargs[Asn1Type]): Asn1Set`
- `newAsn1SetFromSeq(elements: seq[Asn1Type]): Asn1Set`

### SPNEGO Types
- `SpnegoNegTokenInit`
- `SpnegoNegTokenResp`
- `SpnegoContext`
- `GssContext`
- `GssFlags`
- `SpnegoNegState`

### Constants
- `OID_SPNEGO = "1.3.6.1.5.5.2"`
- `OID_KERBEROS5 = "1.2.840.113554.1.2.2"`
- `OID_MS_KRB5 = "1.2.840.48018.1.2.2"`
- `OID_NTLMSSP = "1.3.6.1.4.1.311.2.2.10"`
- `OID_NEGOEX = "1.3.6.1.4.1.311.2.2.30"`

---

*Documentation Version 1.0 - Generated for ASN.1 DER and SPNEGO/GSS-API Library*