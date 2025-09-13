# SPNEGO and GSS-API Extension for ASN.1 DER Library
# Provides token builders and wrappers for Windows authentication protocols

import std/[strutils, sequtils, tables, options]
import ../asn1.nim  # Import the base ASN.1 library

# GSS-API and SPNEGO specific OIDs
const
  # GSS-API Mechanism OIDs
  OID_SPNEGO* = "1.3.6.1.5.5.2"                    # SPNEGO mechanism
  OID_KERBEROS5* = "1.2.840.113554.1.2.2"          # Kerberos V5
  OID_KERBEROS5_USER2USER* = "1.2.840.113554.1.2.2.3"  # Kerberos user-to-user
  OID_NTLMSSP* = "1.3.6.1.4.1.311.2.2.10"          # NTLMSSP
  OID_NEGOEX* = "1.3.6.1.4.1.311.2.2.30"           # NegoEx (Extended SPNEGO)
  
  # GSS-API Generic OIDs
  OID_GSSAPI_GENERIC* = "1.2.840.113554.1.2.1"
  OID_GSSAPI_KRB5_WRAP* = "1.2.840.113554.1.2.2.1"
  
  # Microsoft-specific OIDs
  OID_MS_KRB5* = "1.2.840.48018.1.2.2"             # Microsoft Kerberos
  OID_MS_PKU2U* = "1.3.6.1.5.2.7"                  # PKU2U

  TAG_NUM_SEQUENCE = 16'u32
  TAG_NUM_INTEGER = 2'u32
  TAG_NUM_BIT_STRING = 3'u32
  TAG_NUM_OCTET_STRING = 16'u32

type
  # SPNEGO Message Types
  SpnegoMessageType* = enum
    spnegoNegTokenInit = 0
    spnegoNegTokenResp = 1
    
  # SPNEGO Negotiation States
  SpnegoNegState* = enum
    acceptCompleted = 0
    acceptIncomplete = 1
    reject = 2
    requestMic = 3
  
  # GSS-API Token Types
  GssTokenType* = enum
    gssInitToken
    gssAcceptToken
    gssContinueToken
    gssErrorToken
    
  # GSS-API Flags (RFC 2744)
  GssFlags* = set[GssFlag]
  GssFlag* = enum
    gssDelegFlag = 0      # Delegate credentials
    gssMutualFlag = 1     # Mutual authentication
    gssReplayFlag = 2     # Enable replay detection
    gssSequenceFlag = 3   # Enable out-of-sequence detection
    gssConfFlag = 4       # Enable confidentiality
    gssIntegFlag = 5      # Enable integrity
    gssAnonFlag = 6       # Anonymous authentication
    gssProtReadyFlag = 7  # Protection ready
    gssTransFlag = 8      # Transferable
    
  # SPNEGO Token Structures
  SpnegoNegTokenInit* = object
    mechTypes*: seq[string]           # Supported mechanism OIDs
    reqFlags*: Option[GssFlags]       # Context flags
    mechToken*: Option[seq[uint8]]    # Initial mechanism token
    mechListMIC*: Option[seq[uint8]]  # MIC over mechanism list
    
  SpnegoNegTokenResp* = object
    negState*: Option[SpnegoNegState]     # Negotiation state
    supportedMech*: Option[string]        # Selected mechanism OID
    responseToken*: Option[seq[uint8]]    # Response token
    mechListMIC*: Option[seq[uint8]]      # MIC over mechanism list
    
  # GSS-API Token Wrapper
  GssApiToken* = object
    oid*: string                      # Mechanism OID
    tokenType*: GssTokenType
    innerToken*: seq[uint8]           # The actual token data
    
  # GSS-API Context
  GssContext* = ref object
    mechanism*: string                # Selected mechanism OID
    isInitiator*: bool
    isEstablished*: bool
    flags*: GssFlags
    localName*: string
    remoteName*: string
    sequenceNumber*: uint32
    
  # Authentication Context for multi-round negotiation
  SpnegoContext* = ref object
    gssContext*: GssContext
    availableMechs*: seq[string]
    selectedMech*: string
    state*: SpnegoNegState
    isInitiator*: bool
    sentTokens*: seq[seq[uint8]]
    receivedTokens*: seq[seq[uint8]]

# Helper function to encode context flags
proc encodeContextFlags(flags: GssFlags): seq[uint8] =
  result = newSeq[uint8](4)
  var flagBits: uint32 = 0
  for flag in flags:
    flagBits = flagBits or (1'u32 shl ord(flag))
  # Big-endian encoding
  result[0] = uint8((flagBits shr 24) and 0xFF)
  result[1] = uint8((flagBits shr 16) and 0xFF)
  result[2] = uint8((flagBits shr 8) and 0xFF)
  result[3] = uint8(flagBits and 0xFF)

proc decodeContextFlags(data: seq[uint8]): GssFlags =
  if data.len < 4:
    return {}
  let flagBits = (uint32(data[0]) shl 24) or
                 (uint32(data[1]) shl 16) or
                 (uint32(data[2]) shl 8) or
                 uint32(data[3])
  for i in 0..31:
    if (flagBits and (1'u32 shl i)) != 0:
      if i <= ord(gssTransFlag):
        result.incl(GssFlag(i))

proc buildNegTokenInit*(token: SpnegoNegTokenInit): seq[uint8] =
  # Build inner content first
  var content = DerEncoder()
  
  # [0] MechTypeList
  if token.mechTypes.len > 0:
    # Build mechanism list OIDs
    var oidBytes = DerEncoder()
    for oid in token.mechTypes:
      let oidObj = newAsn1ObjectIdentifier(oid)
      oidBytes.encodeObjectIdentifier(oidObj.value)
    
    # Wrap OIDs in SEQUENCE
    var mechSeq = DerEncoder()
    mechSeq.buffer.add(0x30'u8)  # SEQUENCE tag
    mechSeq.writeLength(oidBytes.buffer.len)
    mechSeq.buffer.add(oidBytes.buffer)
    
    content.buffer.add(0xA0'u8)  # [0] tag
    content.writeLength(mechSeq.buffer.len)
    content.buffer.add(mechSeq.buffer)
  
  # [1] ReqFlags (optional)
  if token.reqFlags.isSome:
    let flagBytes = encodeContextFlags(token.reqFlags.get())
    var flagEnc = DerEncoder()
    flagEnc.encodeBitString(flagBytes, 0)
    
    content.buffer.add(0xA1'u8)  # [1] tag
    content.writeLength(flagEnc.buffer.len)
    content.buffer.add(flagEnc.buffer)
  
  # [2] MechToken (optional)
  if token.mechToken.isSome:
    var tokEnc = DerEncoder()
    tokEnc.encodeOctetString(token.mechToken.get())
    
    content.buffer.add(0xA2'u8)  # [2] tag
    content.writeLength(tokEnc.buffer.len)
    content.buffer.add(tokEnc.buffer)
  
  # [3] MechListMIC (optional)
  if token.mechListMIC.isSome:
    var micEnc = DerEncoder()
    micEnc.encodeOctetString(token.mechListMIC.get())
    
    content.buffer.add(0xA3'u8)  # [3] tag
    content.writeLength(micEnc.buffer.len)
    content.buffer.add(micEnc.buffer)
  
  # Now wrap content in SEQUENCE
  var seq = DerEncoder()
  seq.buffer.add(0x30'u8)  # SEQUENCE tag
  seq.writeLength(content.buffer.len)
  seq.buffer.add(content.buffer)
  
  # Finally wrap in [0] CONTEXT
  var final = DerEncoder()
  final.buffer.add(0xA0'u8)  # [0] CONTEXT CONSTRUCTED
  final.writeLength(seq.buffer.len)
  final.buffer.add(seq.buffer)
  
  return final.buffer

proc buildNegTokenResp*(token: SpnegoNegTokenResp): seq[uint8] =
  ## Build a SPNEGO NegTokenResp token
  var enc = DerEncoder()
  
  # Build the content of the SEQUENCE first
  var seqContent = DerEncoder()
  
  # [0] NegState (optional)
  if token.negState.isSome:
    seqContent.encodeTagged(0, classContext, true, proc(e: var DerEncoder) =
      e.encodeInteger(fromInt64(int64(ord(token.negState.get()))))
    )
  
  # [1] SupportedMech (optional)
  if token.supportedMech.isSome:
    let oid = newAsn1ObjectIdentifier(token.supportedMech.get())
    seqContent.encodeTagged(1, classContext, true, proc(e: var DerEncoder) =
      e.encodeObjectIdentifier(oid.value)
    )
  
  # [2] ResponseToken (optional)
  if token.responseToken.isSome:
    seqContent.encodeTagged(2, classContext, true, proc(e: var DerEncoder) =
      e.encodeOctetString(token.responseToken.get())
    )
  
  # [3] MechListMIC (optional)
  if token.mechListMIC.isSome:
    seqContent.encodeTagged(3, classContext, true, proc(e: var DerEncoder) =
      e.encodeOctetString(token.mechListMIC.get())
    )
  
  # Wrap in SEQUENCE
  var seqEnc = DerEncoder()
  seqEnc.writeTag(uint8(tagSequence), true)
  seqEnc.writeLength(seqContent.buffer.len)
  seqEnc.buffer.add(seqContent.buffer)
  
  # Wrap in [1] CONTEXT tag for NegTokenResp
  enc.writeTag(0xA1'u8, true, classContext)  # [1] CONTEXT CONSTRUCTED
  enc.writeLength(seqEnc.buffer.len)
  enc.buffer.add(seqEnc.buffer)
  
  result = enc.buffer

# GSS-API Token Wrappers
proc wrapGssApiToken*(oid: string, innerToken: seq[uint8]): seq[uint8] =
  ## Wrap a token in GSS-API framing per RFC 2743
  ## Format: [APPLICATION 0] IMPLICIT SEQUENCE {
  ##           thisMech MechType,
  ##           innerContextToken ANY DEFINED BY thisMech
  ##         }
  var enc = DerEncoder()
  
  # Build the sequence content
  var seqContent = DerEncoder()
  let mechOid = newAsn1ObjectIdentifier(oid)
  seqContent.encodeObjectIdentifier(mechOid.value)
  seqContent.buffer.add(innerToken)
  
  # Wrap with APPLICATION 0 tag (0x60)
  enc.buffer.add(0x60'u8)  # APPLICATION 0, constructed
  enc.writeLength(seqContent.buffer.len)
  enc.buffer.add(seqContent.buffer)
  
  result = enc.buffer

proc unwrapGssApiToken*(token: seq[uint8]): tuple[oid: string, innerToken: seq[uint8]] =
  ## Unwrap a GSS-API token and extract the mechanism OID and inner token
  if token.len < 2 or token[0] != 0x60:
    raise newAsn1Error("Invalid GSS-API token")
  
  var dec = DerDecoder(data: token, pos: 1)
  let length = dec.readLength()
  
  # Read the OID
  let oidComponents = dec.decodeObjectIdentifier()
  result.oid = oidComponents.mapIt($it).join(".")
  
  # The rest is the inner token
  result.innerToken = token[dec.pos..^1]

proc isSpnegoToken*(token: seq[uint8]): bool =
  ## Check if a token is a SPNEGO token
  try:
    let (oid, _) = unwrapGssApiToken(token)
    return oid == OID_SPNEGO
  except:
    return false

# SPNEGO Token Parsers
proc parseNegTokenInit*(data: seq[uint8]): SpnegoNegTokenInit =
  ## Parse a SPNEGO NegTokenInit token
  var dec = DerDecoder(data: data, pos: 0)
  
  # Should start with [0] CONTEXT tag
  let (tag, constructed, class) = dec.readTag()
  if tag != 0 or class != classContext or not constructed:
    raise newAsn1Error("Invalid NegTokenInit")
  
  let length = dec.readLength()
  let endPos = dec.pos + length
  
  # Now we should have a SEQUENCE
  let (seqTag, seqConstructed, seqClass) = dec.readTag()
  if seqTag != TAG_NUM_SEQUENCE or seqClass != classUniversal or not seqConstructed:
    raise newAsn1Error("Expected SEQUENCE in NegTokenInit")
  
  let seqLength = dec.readLength()
  let seqEndPos = dec.pos + seqLength
  
  # Parse optional fields within the SEQUENCE
  while dec.pos < seqEndPos:
    let (fieldTag, fieldConstructed, fieldClass) = dec.readTag()
    if fieldClass != classContext:
      raise newAsn1Error("Expected CONTEXT tag in NegTokenInit")
    
    let fieldLength = dec.readLength()
    let fieldEndPos = dec.pos + fieldLength
    
    case fieldTag:
    of 0:  # MechTypeList
      # Read SEQUENCE of OIDs
      let (mechSeqTag, mechSeqConstructed, mechSeqClass) = dec.readTag()
      if mechSeqTag != TAG_NUM_SEQUENCE:
        raise newAsn1Error("Expected SEQUENCE for MechTypeList")
      let mechSeqLength = dec.readLength()
      let mechSeqEndPos = dec.pos + mechSeqLength
      
      result.mechTypes = @[]
      while dec.pos < mechSeqEndPos:
        let oid = dec.decodeObjectIdentifier()
        result.mechTypes.add(oid.mapIt($it).join("."))
      
    of 1:  # ReqFlags
      # The content is a BIT STRING
      let (bitTag, _, bitClass) = dec.readTag()
      if bitTag != TAG_NUM_BIT_STRING:
        raise newAsn1Error("Expected BIT STRING for ReqFlags")
      let bitLength = dec.readLength()
      let unused = dec.readByte()
      let flagBytes = dec.readBytes(bitLength - 1)
      result.reqFlags = some(decodeContextFlags(flagBytes))
      
    of 2:  # MechToken
      let tokenBytes = dec.decodeOctetString()
      result.mechToken = some(tokenBytes)
      
    of 3:  # MechListMIC
      let micBytes = dec.decodeOctetString()
      result.mechListMIC = some(micBytes)
      
    else:
      # Skip unknown fields
      dec.pos = fieldEndPos

proc parseNegTokenResp*(data: seq[uint8]): SpnegoNegTokenResp =
  ## Parse a SPNEGO NegTokenResp token
  var dec = DerDecoder(data: data, pos: 0)
  
  # Should start with [1] CONTEXT tag
  let (tag, constructed, class) = dec.readTag()
  if tag != 1 or class != classContext or not constructed:
    raise newAsn1Error("Invalid NegTokenResp")
  
  let length = dec.readLength()
  let endPos = dec.pos + length
  
  # Now we should have a SEQUENCE
  let (seqTag, seqConstructed, seqClass) = dec.readTag()
  if seqTag != TAG_NUM_SEQUENCE or seqClass != classUniversal or not seqConstructed:
    raise newAsn1Error("Expected SEQUENCE in NegTokenResp")
  
  let seqLength = dec.readLength()
  let seqEndPos = dec.pos + seqLength
  
  # Parse optional fields within the SEQUENCE
  while dec.pos < seqEndPos:
    let (fieldTag, fieldConstructed, fieldClass) = dec.readTag()
    if fieldClass != classContext:
      raise newAsn1Error("Expected CONTEXT tag in NegTokenResp")
    
    let fieldLength = dec.readLength()
    let fieldEndPos = dec.pos + fieldLength
    
    case fieldTag:
    of 0:  # NegState
      let stateInt = dec.decodeInteger()
      let stateVal = stateInt.toInt64()
      if stateVal >= 0 and stateVal <= 3:
        result.negState = some(SpnegoNegState(stateVal))
      
    of 1:  # SupportedMech
      let oid = dec.decodeObjectIdentifier()
      result.supportedMech = some(oid.mapIt($it).join("."))
      
    of 2:  # ResponseToken
      let tokenBytes = dec.decodeOctetString()
      result.responseToken = some(tokenBytes)
      
    of 3:  # MechListMIC
      let micBytes = dec.decodeOctetString()
      result.mechListMIC = some(micBytes)
      
    else:
      # Skip unknown fields
      dec.pos = fieldEndPos

# High-level SPNEGO Context Management
proc newSpnegoContext*(isInitiator: bool, availableMechs: seq[string]): SpnegoContext =
  ## Create a new SPNEGO negotiation context
  new(result)
  result.isInitiator = isInitiator
  result.availableMechs = availableMechs
  result.state = acceptIncomplete
  result.gssContext = GssContext()
  result.gssContext.isInitiator = isInitiator
  result.gssContext.isEstablished = false
  result.sentTokens = @[]
  result.receivedTokens = @[]

proc createInitialToken*(ctx: SpnegoContext, mechToken: seq[uint8] = @[], 
                        flags: GssFlags = {}): seq[uint8] =
  ## Create the initial SPNEGO token for negotiation
  if not ctx.isInitiator:
    raise newAsn1Error("Only initiator can create initial token")
  
  var negToken = SpnegoNegTokenInit()
  negToken.mechTypes = ctx.availableMechs
  
  if flags != {}:
    negToken.reqFlags = some(flags)
    ctx.gssContext.flags = flags
  
  if mechToken.len > 0:
    negToken.mechToken = some(mechToken)
  
  let spnegoToken = buildNegTokenInit(negToken)
  let wrappedToken = wrapGssApiToken(OID_SPNEGO, spnegoToken)
  
  ctx.sentTokens.add(wrappedToken)
  result = wrappedToken

proc processToken*(ctx: SpnegoContext, token: seq[uint8]): tuple[
    responseToken: seq[uint8], isComplete: bool] =
  ## Process a received SPNEGO token and generate response if needed
  ctx.receivedTokens.add(token)
  
  # Unwrap the GSS-API token
  let (oid, innerToken) = unwrapGssApiToken(token)
  if oid != OID_SPNEGO:
    raise newAsn1Error("Not a SPNEGO token")
  
  # Determine token type by checking first byte after unwrapping
  var dec = DerDecoder(data: innerToken, pos: 0)
  let (tag, _, class) = dec.readTag()
  dec.pos = 0  # Reset
  
  if tag == 0 and class == classContext:
    # NegTokenInit
    let negTokenInit = parseNegTokenInit(innerToken)
    
    # NegTokenInit handling section
    if ctx.isInitiator:
      raise newAsn1Error("Initiator received NegTokenInit")
    
    # Select mechanism (prefer Kerberos if available)
    for mech in [OID_KERBEROS5, OID_MS_KRB5, OID_NTLMSSP]:
      if mech in negTokenInit.mechTypes and mech in ctx.availableMechs:
        ctx.selectedMech = mech
        ctx.gssContext.mechanism = mech
        break
    
    if ctx.selectedMech == "":
      # No common mechanism - REJECT
      ctx.state = reject
      var respToken = SpnegoNegTokenResp()
      respToken.negState = some(reject)
      let spnegoResp = buildNegTokenResp(respToken)
      result.responseToken = wrapGssApiToken(OID_SPNEGO, spnegoResp)
      result.isComplete = true
      return
    
    # Build response
    var respToken = SpnegoNegTokenResp()
    respToken.negState = some(acceptIncomplete)
    respToken.supportedMech = some(ctx.selectedMech)
    
    # Here you would generate the actual mechanism token
    # For now, we'll use a placeholder
    if negTokenInit.mechToken.isSome:
      # Process the mechanism token and generate response
      # This would involve calling the actual Kerberos/NTLM handler
      respToken.responseToken = some(@[0x01'u8, 0x02, 0x03])  # Placeholder
    
    let spnegoResp = buildNegTokenResp(respToken)
    result.responseToken = wrapGssApiToken(OID_SPNEGO, spnegoResp)
    result.isComplete = false
    
  elif tag == 1 and class == classContext:
    # NegTokenResp
    let negTokenResp = parseNegTokenResp(innerToken)
    
    if negTokenResp.negState.isSome:
      ctx.state = negTokenResp.negState.get()
    
    if negTokenResp.supportedMech.isSome:
      ctx.selectedMech = negTokenResp.supportedMech.get()
      ctx.gssContext.mechanism = ctx.selectedMech
    
    case ctx.state:
    of acceptCompleted:
      ctx.gssContext.isEstablished = true
      result.isComplete = true
      result.responseToken = @[]
      
    of acceptIncomplete:
      # Continue negotiation
      if negTokenResp.responseToken.isSome:
        # Process the mechanism token and generate response
        # This would involve calling the actual Kerberos/NTLM handler
        var respToken = SpnegoNegTokenResp()
        respToken.negState = some(acceptCompleted)
        respToken.responseToken = some(@[0x04'u8, 0x05, 0x06])  # Placeholder
        
        let spnegoResp = buildNegTokenResp(respToken)
        result.responseToken = wrapGssApiToken(OID_SPNEGO, spnegoResp)
        result.isComplete = false
      
    of reject:
      result.isComplete = true
      result.responseToken = @[]
      
    of requestMic:
      # Generate MIC if requested
      # This requires the actual mechanism to be implemented
      result.isComplete = false
      result.responseToken = @[]
  
  else:
    raise newAsn1Error("Unknown SPNEGO token type")

# Utility functions for common scenarios
proc createSpnegoKerberosInit*(kerberosToken: seq[uint8], 
                               includeNtlm: bool = false): seq[uint8] =
  ## Create a SPNEGO initial token with Kerberos (and optionally NTLM)
  var mechs = @[OID_KERBEROS5, OID_MS_KRB5]
  if includeNtlm:
    mechs.add(OID_NTLMSSP)
  
  var negToken = SpnegoNegTokenInit()
  negToken.mechTypes = mechs
  negToken.mechToken = some(kerberosToken)
  negToken.reqFlags = some({gssMutualFlag, gssReplayFlag, gssSequenceFlag})
  
  let spnegoToken = buildNegTokenInit(negToken)
  result = wrapGssApiToken(OID_SPNEGO, spnegoToken)

proc extractMechanismToken*(token: seq[uint8]): seq[uint8] =
  ## Extract the inner mechanism token from a SPNEGO token
  let (oid, innerToken) = unwrapGssApiToken(token)
  if oid != OID_SPNEGO:
    raise newAsn1Error("Not a SPNEGO token")
  
  var dec = DerDecoder(data: innerToken, pos: 0)
  let (tag, _, class) = dec.readTag()
  dec.pos = 0
  
  if tag == 0 and class == classContext:
    let negTokenInit = parseNegTokenInit(innerToken)
    if negTokenInit.mechToken.isSome:
      return negTokenInit.mechToken.get()
  elif tag == 1 and class == classContext:
    let negTokenResp = parseNegTokenResp(innerToken)
    if negTokenResp.responseToken.isSome:
      return negTokenResp.responseToken.get()
  
  return @[]

# Export all public symbols
export SpnegoMessageType, SpnegoNegState, GssTokenType, GssFlags, GssFlag
export SpnegoNegTokenInit, SpnegoNegTokenResp, GssApiToken, GssContext, SpnegoContext
export OID_SPNEGO, OID_KERBEROS5, OID_KERBEROS5_USER2USER, OID_NTLMSSP
export OID_NEGOEX, OID_GSSAPI_GENERIC, OID_GSSAPI_KRB5_WRAP
export OID_MS_KRB5, OID_MS_PKU2U
export encodeContextFlags, decodeContextFlags
export buildNegTokenInit, buildNegTokenResp
export wrapGssApiToken, unwrapGssApiToken, isSpnegoToken
export parseNegTokenInit, parseNegTokenResp
export newSpnegoContext, createInitialToken, processToken
export createSpnegoKerberosInit, extractMechanismToken