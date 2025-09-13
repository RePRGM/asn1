# Test suite for SPNEGO and GSS-API Extension
# Run with: nim c -r test_spnego_gssapi.nim

import std/[unittest, strutils, sequtils, options, base64]
import ../asn1.nim
import ../gssapi/main

# Test helper procedures
proc bytesToHex(bytes: seq[uint8]): string =
  bytes.mapIt(it.toHex(2)).join(" ")

proc hexToBytes(hex: string): seq[uint8] =
  let cleaned = hex.replace(" ", "").replace("\n", "")
  result = @[]
  for i in countup(0, cleaned.len - 2, 2):
    result.add(uint8(parseHexInt(cleaned[i..i+1])))

proc toBytes(s: string): seq[uint8] =
  for c in s:
    result.add(uint8(ord(c)))

suite "SPNEGO Token Building":
  test "Debug: Check basic structure":
    # Create the simplest possible NegTokenInit
    var negToken = SpnegoNegTokenInit()
    negToken.mechTypes = @[]  # Empty
    
    let encoded = buildNegTokenInit(negToken)
    
    # Check the structure manually
    check encoded.len >= 4  # At minimum: tag, length, sequence tag, sequence length
    check encoded[0] == 0xA0'u8  # [0] CONTEXT CONSTRUCTED
    
    # Parse the length
    var pos = 1
    var contentLen = 0
    if encoded[1] < 128:
      contentLen = int(encoded[1])
      pos = 2
    
    # Check for SEQUENCE tag
    if pos < encoded.len:
      check encoded[pos] == 0x30'u8  # SEQUENCE tag
    else:
      echo "ERROR: No SEQUENCE tag found at position ", pos
      echo "Full token: ", encoded.mapIt(it.toHex(2)).join(" ")

  # Add this debug test to see what's being built:
  test "Debug: Inspect MechTypeList structure":
    var negToken = SpnegoNegTokenInit()
    negToken.mechTypes = @[OID_KERBEROS5]
    
    let encoded = buildNegTokenInit(negToken)
    echo "Full token: ", encoded.mapIt(it.toHex(2)).join(" ")
    
    # Manually parse to see structure
    var pos = 0
    echo "Byte ", pos, ": ", encoded[pos].toHex(2), " (should be A0 - [0] CONTEXT)"
    inc pos
    
    let outerLen = int(encoded[pos])
    echo "Byte ", pos, ": ", encoded[pos].toHex(2), " (outer length: ", outerLen, ")"
    inc pos
    
    echo "Byte ", pos, ": ", encoded[pos].toHex(2), " (should be 30 - SEQUENCE)"
    inc pos
    
    let seqLen = int(encoded[pos])
    echo "Byte ", pos, ": ", encoded[pos].toHex(2), " (sequence length: ", seqLen, ")"
    inc pos
    
    echo "Byte ", pos, ": ", encoded[pos].toHex(2), " (should be A0 - [0] MechTypeList)"
    inc pos
    
    let mechListLen = int(encoded[pos])
    echo "Byte ", pos, ": ", encoded[pos].toHex(2), " (mechlist length: ", mechListLen, ")"
    inc pos
    
    echo "Byte ", pos, ": ", encoded[pos].toHex(2), " (should be 30 - SEQUENCE of OIDs???)"

  test "Create empty NegTokenInit":
    var negToken = SpnegoNegTokenInit()
    negToken.mechTypes = @[]
    
    let encoded = buildNegTokenInit(negToken)
    check encoded.len > 0
    check encoded[0] == 0xA0'u8  # [0] CONTEXT tag
  
  test "Create NegTokenInit with Kerberos":
    var negToken = SpnegoNegTokenInit()
    negToken.mechTypes = @[OID_KERBEROS5]
    
    let encoded = buildNegTokenInit(negToken)
    check encoded.len > 0
    
    # Parse it back
    let parsed = parseNegTokenInit(encoded)
    check parsed.mechTypes.len == 1
    check parsed.mechTypes[0] == OID_KERBEROS5
  
  test "Create NegTokenInit with multiple mechanisms":
    var negToken = SpnegoNegTokenInit()
    negToken.mechTypes = @[OID_KERBEROS5, OID_NTLMSSP]
    negToken.reqFlags = some({gssMutualFlag, gssReplayFlag})
    
    let encoded = buildNegTokenInit(negToken)
    check encoded.len > 0
    
    # Parse it back
    let parsed = parseNegTokenInit(encoded)
    check parsed.mechTypes.len == 2
    check parsed.mechTypes[0] == OID_KERBEROS5
    check parsed.mechTypes[1] == OID_NTLMSSP
    check parsed.reqFlags.isSome
    check gssMutualFlag in parsed.reqFlags.get()
  
  test "Create NegTokenInit with mechToken":
    var negToken = SpnegoNegTokenInit()
    negToken.mechTypes = @[OID_KERBEROS5]
    negToken.mechToken = some(@[0xDE'u8, 0xAD, 0xBE, 0xEF])
    
    let encoded = buildNegTokenInit(negToken)
    let parsed = parseNegTokenInit(encoded)
    
    check parsed.mechToken.isSome
    check parsed.mechToken.get() == @[0xDE'u8, 0xAD, 0xBE, 0xEF]
  
  test "Create NegTokenInit with MIC":
    var negToken = SpnegoNegTokenInit()
    negToken.mechTypes = @[OID_KERBEROS5]
    negToken.mechListMIC = some(@[0xAA'u8, 0xBB, 0xCC, 0xDD])
    
    let encoded = buildNegTokenInit(negToken)
    let parsed = parseNegTokenInit(encoded)
    
    check parsed.mechListMIC.isSome
    check parsed.mechListMIC.get() == @[0xAA'u8, 0xBB, 0xCC, 0xDD]

suite "SPNEGO Response Token Building":
  test "Create NegTokenResp with accept-completed":
    var respToken = SpnegoNegTokenResp()
    respToken.negState = some(acceptCompleted)
    respToken.supportedMech = some(OID_KERBEROS5)
    
    let encoded = buildNegTokenResp(respToken)
    check encoded.len > 0
    check encoded[0] == 0xA1'u8  # [1] CONTEXT tag
    
    let parsed = parseNegTokenResp(encoded)
    check parsed.negState.isSome
    check parsed.negState.get() == acceptCompleted
    check parsed.supportedMech.isSome
    check parsed.supportedMech.get() == OID_KERBEROS5
  
  test "Create NegTokenResp with accept-incomplete":
    var respToken = SpnegoNegTokenResp()
    respToken.negState = some(acceptIncomplete)
    respToken.responseToken = some(@[0x01'u8, 0x02, 0x03])
    
    let encoded = buildNegTokenResp(respToken)
    let parsed = parseNegTokenResp(encoded)
    
    check parsed.negState.get() == acceptIncomplete
    check parsed.responseToken.isSome
    check parsed.responseToken.get() == @[0x01'u8, 0x02, 0x03]
  
  test "Create NegTokenResp with reject":
    var respToken = SpnegoNegTokenResp()
    respToken.negState = some(reject)
    
    let encoded = buildNegTokenResp(respToken)
    let parsed = parseNegTokenResp(encoded)
    
    check parsed.negState.get() == reject
    check parsed.supportedMech.isNone
    check parsed.responseToken.isNone
  
  test "Create NegTokenResp with MIC":
    var respToken = SpnegoNegTokenResp()
    respToken.negState = some(requestMic)
    respToken.mechListMIC = some(@[0x11'u8, 0x22, 0x33, 0x44])
    
    let encoded = buildNegTokenResp(respToken)
    let parsed = parseNegTokenResp(encoded)
    
    check parsed.negState.get() == requestMic
    check parsed.mechListMIC.isSome
    check parsed.mechListMIC.get() == @[0x11'u8, 0x22, 0x33, 0x44]

suite "GSS-API Token Wrapping":
  test "Wrap SPNEGO token":
    let innerToken = @[0x01'u8, 0x02, 0x03, 0x04, 0x05]
    let wrapped = wrapGssApiToken(OID_SPNEGO, innerToken)
    
    check wrapped[0] == 0x60'u8  # APPLICATION 0 tag
    check wrapped.len > innerToken.len
    
    let (oid, unwrapped) = unwrapGssApiToken(wrapped)
    check oid == OID_SPNEGO
    check unwrapped == innerToken
  
  test "Wrap Kerberos token":
    let krbToken = @[0x6E'u8, 0x00, 0x00, 0x00]  # Fake AP-REQ
    let wrapped = wrapGssApiToken(OID_KERBEROS5, krbToken)
    
    check wrapped[0] == 0x60'u8
    
    let (oid, unwrapped) = unwrapGssApiToken(wrapped)
    check oid == OID_KERBEROS5
    check unwrapped == krbToken
  
  test "Wrap NTLM token":
    let ntlmToken = @[0x4E'u8, 0x54, 0x4C, 0x4D]  # "NTLM"
    let wrapped = wrapGssApiToken(OID_NTLMSSP, ntlmToken)
    
    let (oid, unwrapped) = unwrapGssApiToken(wrapped)
    check oid == OID_NTLMSSP
    check unwrapped == ntlmToken
  
  test "Check if token is SPNEGO":
    let innerToken = @[0xA0'u8, 0x00]  # Minimal NegTokenInit
    let spnegoToken = wrapGssApiToken(OID_SPNEGO, innerToken)
    let krbToken = wrapGssApiToken(OID_KERBEROS5, @[0x01'u8])
    
    check isSpnegoToken(spnegoToken) == true
    check isSpnegoToken(krbToken) == false
    check isSpnegoToken(@[0xFF'u8, 0xFF]) == false

suite "SPNEGO Context Management":
  test "Create initiator context":
    let ctx = newSpnegoContext(true, @[OID_KERBEROS5, OID_NTLMSSP])
    
    check ctx.isInitiator == true
    check ctx.availableMechs.len == 2
    check ctx.state == acceptIncomplete
    check ctx.gssContext.isEstablished == false
  
  test "Create acceptor context":
    let ctx = newSpnegoContext(false, @[OID_KERBEROS5])
    
    check ctx.isInitiator == false
    check ctx.availableMechs.len == 1
    check ctx.gssContext.isInitiator == false
  
  test "Create initial token from context":
    let ctx = newSpnegoContext(true, @[OID_KERBEROS5, OID_NTLMSSP])
    let token = ctx.createInitialToken(@[], {gssMutualFlag, gssReplayFlag})
    
    check token.len > 0
    check isSpnegoToken(token)
    check ctx.sentTokens.len == 1
    
    # Verify the token structure
    let (oid, innerToken) = unwrapGssApiToken(token)
    check oid == OID_SPNEGO
    
    let negTokenInit = parseNegTokenInit(innerToken)
    check negTokenInit.mechTypes == @[OID_KERBEROS5, OID_NTLMSSP]
    check negTokenInit.reqFlags.isSome
  
  test "Create initial token with mechToken":
    let ctx = newSpnegoContext(true, @[OID_KERBEROS5])
    let fakeKrbToken = @[0x6E'u8, 0x00, 0x00, 0x00]
    let token = ctx.createInitialToken(fakeKrbToken)
    
    let (_, innerToken) = unwrapGssApiToken(token)
    let negTokenInit = parseNegTokenInit(innerToken)
    
    check negTokenInit.mechToken.isSome
    check negTokenInit.mechToken.get() == fakeKrbToken
  
  test "Process NegTokenInit as acceptor":
    let acceptorCtx = newSpnegoContext(false, @[OID_KERBEROS5, OID_NTLMSSP])
    
    # Create a NegTokenInit to process
    var negTokenInit = SpnegoNegTokenInit()
    negTokenInit.mechTypes = @[OID_KERBEROS5, OID_NTLMSSP]
    negTokenInit.reqFlags = some({gssMutualFlag})
    
    let spnegoToken = buildNegTokenInit(negTokenInit)
    let wrappedToken = wrapGssApiToken(OID_SPNEGO, spnegoToken)
    
    let (responseToken, isComplete) = acceptorCtx.processToken(wrappedToken)
    
    check responseToken.len > 0
    check isComplete == false
    check acceptorCtx.selectedMech == OID_KERBEROS5  # Should prefer Kerberos
    check acceptorCtx.receivedTokens.len == 1
  
  test "Process NegTokenResp as initiator":
    let initiatorCtx = newSpnegoContext(true, @[OID_KERBEROS5])
    
    # Create a NegTokenResp to process
    var negTokenResp = SpnegoNegTokenResp()
    negTokenResp.negState = some(acceptCompleted)
    negTokenResp.supportedMech = some(OID_KERBEROS5)
    
    let spnegoToken = buildNegTokenResp(negTokenResp)
    let wrappedToken = wrapGssApiToken(OID_SPNEGO, spnegoToken)
    
    let (responseToken, isComplete) = initiatorCtx.processToken(wrappedToken)
    
    check isComplete == true
    check initiatorCtx.gssContext.isEstablished == true
    check initiatorCtx.state == acceptCompleted
  
  test "Reject when no common mechanism":
    let acceptorCtx = newSpnegoContext(false, @[OID_NTLMSSP])
    
    # Create a NegTokenInit with only Kerberos
    var negTokenInit = SpnegoNegTokenInit()
    negTokenInit.mechTypes = @[OID_KERBEROS5]
    
    let spnegoToken = buildNegTokenInit(negTokenInit)
    let wrappedToken = wrapGssApiToken(OID_SPNEGO, spnegoToken)
    
    # Process should result in rejection since no common mechanism
    let (responseToken, isComplete) = acceptorCtx.processToken(wrappedToken)
    
    check isComplete == true
    check acceptorCtx.state == reject
    check responseToken.len > 0
    
    # Verify the response is a reject
    let (_, innerToken) = unwrapGssApiToken(responseToken)
    let negTokenResp = parseNegTokenResp(innerToken)
    check negTokenResp.negState.get() == reject

suite "SPNEGO Helper Functions":
  test "Create SPNEGO Kerberos init token":
    let fakeKrbToken = @[0x6E'u8, 0x00, 0x00, 0x00]
    let token = createSpnegoKerberosInit(fakeKrbToken, false)
    
    check isSpnegoToken(token)
    
    let (_, innerToken) = unwrapGssApiToken(token)
    let negTokenInit = parseNegTokenInit(innerToken)
    
    check negTokenInit.mechTypes == @[OID_KERBEROS5, OID_MS_KRB5]
    check negTokenInit.mechToken.get() == fakeKrbToken
    check negTokenInit.reqFlags.isSome
  
  test "Create SPNEGO Kerberos init with NTLM":
    let fakeKrbToken = @[0x6E'u8, 0x00, 0x00, 0x00]
    let token = createSpnegoKerberosInit(fakeKrbToken, true)
    
    let (_, innerToken) = unwrapGssApiToken(token)
    let negTokenInit = parseNegTokenInit(innerToken)
    
    check negTokenInit.mechTypes.len == 3
    check OID_KERBEROS5 in negTokenInit.mechTypes
    check OID_MS_KRB5 in negTokenInit.mechTypes
    check OID_NTLMSSP in negTokenInit.mechTypes
  
  test "Extract mechanism token from NegTokenInit":
    let mechToken = @[0xAA'u8, 0xBB, 0xCC]
    
    var negTokenInit = SpnegoNegTokenInit()
    negTokenInit.mechTypes = @[OID_KERBEROS5]
    negTokenInit.mechToken = some(mechToken)
    
    let spnegoToken = buildNegTokenInit(negTokenInit)
    let wrappedToken = wrapGssApiToken(OID_SPNEGO, spnegoToken)
    
    let extracted = extractMechanismToken(wrappedToken)
    check extracted == mechToken
  
  test "Extract mechanism token from NegTokenResp":
    let respToken = @[0x11'u8, 0x22, 0x33]
    
    var negTokenResp = SpnegoNegTokenResp()
    negTokenResp.negState = some(acceptIncomplete)
    negTokenResp.responseToken = some(respToken)
    
    let spnegoToken = buildNegTokenResp(negTokenResp)
    let wrappedToken = wrapGssApiToken(OID_SPNEGO, spnegoToken)
    
    let extracted = extractMechanismToken(wrappedToken)
    check extracted == respToken
  
  test "Extract mechanism token when none present":
    var negTokenInit = SpnegoNegTokenInit()
    let emptyToken: seq[uint8] = @[]
    negTokenInit.mechTypes = @[OID_KERBEROS5]
    # No mechToken
    
    let spnegoToken = buildNegTokenInit(negTokenInit)
    let wrappedToken = wrapGssApiToken(OID_SPNEGO, spnegoToken)
    
    let extracted = extractMechanismToken(wrappedToken)
    check extracted == emptyToken

suite "GSS-API Context Flags":
  test "Encode context flags":
    let flags: GssFlags = {gssDelegFlag, gssMutualFlag, gssIntegFlag}
    let encoded = encodeContextFlags(flags)
    
    check encoded.len == 4
    # gssDelegFlag = bit 0, gssMutualFlag = bit 1, gssIntegFlag = bit 5
    # Expected: 0x00000023 (bits 0, 1, and 5 set)
    check encoded == @[0x00'u8, 0x00, 0x00, 0x23]
  
  test "Decode context flags":
    let encoded = @[0x00'u8, 0x00, 0x00, 0x23]
    let flags = decodeContextFlags(encoded)
    
    check gssDelegFlag in flags
    check gssMutualFlag in flags
    check gssIntegFlag in flags
    check gssReplayFlag notin flags
  
  test "Round-trip context flags":
    let originalFlags: GssFlags = {gssMutualFlag, gssReplayFlag, gssSequenceFlag, gssConfFlag}
    let encoded = encodeContextFlags(originalFlags)
    let decoded = decodeContextFlags(encoded)
    
    check decoded == originalFlags
  
  test "Empty flags":
    let emptyFlags: GssFlags = {}
    let encoded = encodeContextFlags(emptyFlags)
    check encoded == @[0x00'u8, 0x00, 0x00, 0x00]
    
    let decoded = decodeContextFlags(encoded)
    check decoded == {}
  
  test "All flags":
    let allFlags: GssFlags = {gssDelegFlag, gssMutualFlag, gssReplayFlag, 
                              gssSequenceFlag, gssConfFlag, gssIntegFlag,
                              gssAnonFlag, gssProtReadyFlag, gssTransFlag}
    let encoded = encodeContextFlags(allFlags)
    let decoded = decodeContextFlags(encoded)
    
    check decoded == allFlags

suite "SPNEGO Error Handling":
  test "Invalid GSS-API token":
    expect Asn1Error:
      discard unwrapGssApiToken(@[0xFF'u8, 0xFF])
  
  test "Wrong OID in processToken":
    let ctx = newSpnegoContext(true, @[OID_KERBEROS5])
    let krbToken = wrapGssApiToken(OID_KERBEROS5, @[0x01'u8])
    
    expect Asn1Error:
      discard ctx.processToken(krbToken)
  
  test "Initiator receives NegTokenInit":
    let ctx = newSpnegoContext(true, @[OID_KERBEROS5])
    
    var negTokenInit = SpnegoNegTokenInit()
    negTokenInit.mechTypes = @[OID_KERBEROS5]
    
    let spnegoToken = buildNegTokenInit(negTokenInit)
    let wrappedToken = wrapGssApiToken(OID_SPNEGO, spnegoToken)
    
    expect Asn1Error:
      discard ctx.processToken(wrappedToken)
  
  test "Non-initiator creates initial token":
    let ctx = newSpnegoContext(false, @[OID_KERBEROS5])
    
    expect Asn1Error:
      discard ctx.createInitialToken()
  
  test "Parse invalid NegTokenInit":
    let invalidData = @[0xA0'u8, 0x03, 0xFF, 0xFF, 0xFF]
    
    expect Asn1Error:
      discard parseNegTokenInit(invalidData)
  
  test "Parse invalid NegTokenResp":
    let invalidData = @[0xA1'u8, 0x03, 0xFF, 0xFF, 0xFF]
    
    expect Asn1Error:
      discard parseNegTokenResp(invalidData)

suite "SPNEGO Integration Tests":
  test "Complete negotiation flow":
    # Initiator creates initial token
    let initiatorCtx = newSpnegoContext(true, @[OID_KERBEROS5, OID_NTLMSSP])
    let initToken = initiatorCtx.createInitialToken(@[0x01'u8, 0x02], {gssMutualFlag})
    
    # Acceptor processes initial token
    let acceptorCtx = newSpnegoContext(false, @[OID_KERBEROS5, OID_NTLMSSP])
    let (acceptorResp, acceptorDone) = acceptorCtx.processToken(initToken)
    
    check acceptorDone == false
    check acceptorCtx.selectedMech == OID_KERBEROS5
    check acceptorResp.len > 0
    
    # Initiator processes response
    # In real scenario, would continue until complete
    check initiatorCtx.state == acceptIncomplete
  
  test "Base64 encoding for HTTP":
    let ctx = newSpnegoContext(true, @[OID_KERBEROS5])
    let token = ctx.createInitialToken()
    
    let base64Token = encode(token)
    check base64Token.len > 0
    
    # Verify it can be decoded
    let decoded = decode(base64Token)
    check decoded.toBytes == token
  
  test "Multiple mechanism preference order":
    let acceptorCtx = newSpnegoContext(false, @[OID_NTLMSSP, OID_KERBEROS5, OID_MS_KRB5])
    
    var negTokenInit = SpnegoNegTokenInit()
    negTokenInit.mechTypes = @[OID_MS_KRB5, OID_KERBEROS5, OID_NTLMSSP]
    
    let spnegoToken = buildNegTokenInit(negTokenInit)
    let wrappedToken = wrapGssApiToken(OID_SPNEGO, spnegoToken)
    
    let (_, _) = acceptorCtx.processToken(wrappedToken)
    
    # Should select Kerberos as it's preferred (appears first in common mechanisms)
    check acceptorCtx.selectedMech == OID_KERBEROS5
