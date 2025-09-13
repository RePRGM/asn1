# SPNEGO/GSS-API Usage Examples
# Practical examples for Windows authentication protocols

import std/[strutils, sequtils, base64, options]  # Add options import
import ../asn1.nim
import ../gssapi/main

# Example 1: HTTP Negotiate Authentication
proc httpNegotiateAuth*() =
  echo "Example 1: HTTP Negotiate Authentication"
  echo "-".repeat(40)  # Fix: Use repeat instead of * 
  
  # Create SPNEGO context as client
  let ctx = newSpnegoContext(true, @[OID_KERBEROS5, OID_NTLMSSP])
  
  # Generate initial SPNEGO token (would include real Kerberos ticket)
  let fakeKrbTicket = @[0x6E'u8, 0x82, 0x01, 0x00]  # Fake AP-REQ
  let initToken = ctx.createInitialToken(fakeKrbTicket, {gssMutualFlag, gssReplayFlag})
  
  # Format for HTTP Authorization header
  let authHeader = "Negotiate " & encode(initToken)
  echo "  Authorization: " & authHeader[0..min(50, authHeader.high)] & "..."
  echo "  Token size: " & $initToken.len & " bytes"
  
  # Simulate server response
  echo "\n  Server would respond with:"
  echo "  WWW-Authenticate: Negotiate <base64-response-token>"
  
  # In real scenario, you'd parse the server's response and continue
  var serverResp = SpnegoNegTokenResp()
  serverResp.negState = some(acceptIncomplete)
  serverResp.supportedMech = some(OID_KERBEROS5)
  serverResp.responseToken = some(@[0xAB'u8, 0xCD, 0xEF])
  
  let serverToken = buildNegTokenResp(serverResp)
  let wrappedServerToken = wrapGssApiToken(OID_SPNEGO, serverToken)
  
  # Process server response
  let (clientResp, isDone) = ctx.processToken(wrappedServerToken)
  echo "  Negotiation complete: " & $isDone
  echo ""

# Example 2: SMB2 Session Setup
proc smb2SessionSetup*() =
  echo "Example 2: SMB2 Session Setup with SPNEGO"
  echo "-".repeat(40)
  
  # SMB2 uses SPNEGO for authentication
  let smbCtx = newSpnegoContext(true, @[OID_KERBEROS5, OID_NTLMSSP])
  
  # Create initial token for SMB2 SESSION_SETUP request
  let smbInitToken = smbCtx.createInitialToken(@[], {
    gssMutualFlag,
    gssReplayFlag,
    gssSequenceFlag,
    gssIntegFlag  # SMB requires integrity
  })
  
  echo "  SPNEGO token for SMB2 SESSION_SETUP:"
  echo "  Size: " & $smbInitToken.len & " bytes"
  echo "  Hex: " & smbInitToken[0..min(15, smbInitToken.high)].mapIt(it.toHex(2)).join(" ") & "..."
  
  # Extract mechanism list from token
  let (_, innerToken) = unwrapGssApiToken(smbInitToken)
  let negTokenInit = parseNegTokenInit(innerToken)
  echo "  Offered mechanisms:"
  for mech in negTokenInit.mechTypes:
    case mech:
    of OID_KERBEROS5: echo "    - Kerberos V5"
    of OID_NTLMSSP: echo "    - NTLMSSP"
    of OID_MS_KRB5: echo "    - Microsoft Kerberos"
    else: echo "    - " & mech
  echo ""

# Example 3: LDAP SASL Bind with GSS-SPNEGO
proc ldapSaslBind*() =
  echo "Example 3: LDAP SASL Bind with GSS-SPNEGO"
  echo "-".repeat(40)
  
  # LDAP uses SASL with GSS-SPNEGO mechanism
  const ldapSaslMech = "GSS-SPNEGO"
  
  # Create SPNEGO context
  let ldapCtx = newSpnegoContext(true, @[OID_KERBEROS5])
  
  # Generate SPNEGO token with Kerberos
  let krbServiceTicket = @[0x6E'u8, 0x82, 0x02, 0x00]  # Fake service ticket
  let spnegoToken = createSpnegoKerberosInit(krbServiceTicket, false)
  
  echo "  SASL Mechanism: " & ldapSaslMech
  echo "  Initial credential size: " & $spnegoToken.len & " bytes"
  
  # In LDAP bind request, this would go in the credentials field
  # Build a simplified LDAP BindRequest
  let bindRequest = newAsn1Sequence(
    newAsn1Integer(3),  # LDAP version 3
    newAsn1OctetString(""),  # Empty DN for SASL
    Asn1Type(newAsn1Sequence(  # SASL authentication
      newAsn1OctetString(ldapSaslMech),
      newAsn1OctetString(spnegoToken)
    ))
  )
  
  let encoded = encode(bindRequest)
  echo "  LDAP BindRequest size: " & $encoded.len & " bytes"
  echo ""

# Example 4: Extracting and Analyzing SPNEGO Tokens
proc analyzeSpnegoToken*(tokenBytes: seq[uint8]) =
  echo "Example 4: Analyzing SPNEGO Token"
  echo "-".repeat(40)
  
  if not isSpnegoToken(tokenBytes):
    echo "  Not a SPNEGO token!"
    return
  
  let (oid, innerToken) = unwrapGssApiToken(tokenBytes)
  echo "  GSS-API OID: " & oid
  
  # Determine token type
  var dec = DerDecoder(data: innerToken, pos: 0)
  let (tag, _, class) = dec.readTag()
  dec.pos = 0
  
  if tag == 0 and class == classContext:
    echo "  Token type: NegTokenInit"
    let negTokenInit = parseNegTokenInit(innerToken)
    
    echo "  Mechanism list:"
    for mech in negTokenInit.mechTypes:
      echo "    - " & mech
    
    if negTokenInit.reqFlags.isSome:
      echo "  Requested flags:"
      let flags = negTokenInit.reqFlags.get()
      if gssDelegFlag in flags: echo "    - Delegation"
      if gssMutualFlag in flags: echo "    - Mutual authentication"
      if gssReplayFlag in flags: echo "    - Replay detection"
      if gssSequenceFlag in flags: echo "    - Sequence detection"
      if gssConfFlag in flags: echo "    - Confidentiality"
      if gssIntegFlag in flags: echo "    - Integrity"
    
    if negTokenInit.mechToken.isSome:
      echo "  Contains mechanism token: " & $negTokenInit.mechToken.get().len & " bytes"
    
    if negTokenInit.mechListMIC.isSome:
      echo "  Contains MIC: " & $negTokenInit.mechListMIC.get().len & " bytes"
  
  elif tag == 1 and class == classContext:
    echo "  Token type: NegTokenResp"
    let negTokenResp = parseNegTokenResp(innerToken)
    
    if negTokenResp.negState.isSome:
      echo "  Negotiation state: " & $negTokenResp.negState.get()
    
    if negTokenResp.supportedMech.isSome:
      echo "  Selected mechanism: " & negTokenResp.supportedMech.get()
    
    if negTokenResp.responseToken.isSome:
      echo "  Contains response token: " & $negTokenResp.responseToken.get().len & " bytes"
  echo ""

# Example 5: Multi-round Negotiation
proc multiRoundNegotiation*() =
  echo "Example 5: Multi-round SPNEGO Negotiation"
  echo "-".repeat(40)
  
  # Initialize contexts
  let clientCtx = newSpnegoContext(true, @[OID_KERBEROS5, OID_NTLMSSP])
  let serverCtx = newSpnegoContext(false, @[OID_NTLMSSP, OID_KERBEROS5])
  
  echo "  Round 1: Client -> Server"
  let clientInit = clientCtx.createInitialToken(@[0x01'u8], {gssMutualFlag})
  echo "    Client sends NegTokenInit: " & $clientInit.len & " bytes"
  
  echo "  Round 2: Server -> Client"
  let (serverResp, serverDone) = serverCtx.processToken(clientInit)
  echo "    Server selects: " & serverCtx.selectedMech
  echo "    Server sends NegTokenResp: " & $serverResp.len & " bytes"
  echo "    Server complete: " & $serverDone
  
  echo "  Round 3: Client -> Server"
  let (clientResp, clientDone) = clientCtx.processToken(serverResp)
  echo "    Client sends response: " & $clientResp.len & " bytes"
  echo "    Client complete: " & $clientDone
  
  # In real scenario, rounds continue until both sides are done
  echo "  Negotiation would continue until both sides complete"
  echo ""

# Example 6: Error Handling
proc handleSpnegoErrors*() =
  echo "Example 6: SPNEGO Error Handling"
  echo "-".repeat(40)
  
  # Scenario 1: No common mechanism
  echo "  Scenario: No common mechanism"
  let clientCtx = newSpnegoContext(true, @[OID_KERBEROS5])
  let serverCtx = newSpnegoContext(false, @[OID_NTLMSSP])  # Only supports NTLM
  
  let initToken = clientCtx.createInitialToken()
  let (rejectToken, isDone) = serverCtx.processToken(initToken)
  
  echo "    Server state: " & $serverCtx.state
  echo "    Negotiation complete: " & $isDone
  echo "    Rejection token sent: " & $(rejectToken.len > 0)
  
  # Scenario 2: Invalid token handling
  echo "\n  Scenario: Invalid token"
  try:
    let invalidToken = @[0xFF'u8, 0xFF, 0xFF]
    discard clientCtx.processToken(invalidToken)
    echo "    ERROR: Should have thrown exception"
  except Asn1Error as e:
    echo "    Correctly caught error: " & e.msg
  
  echo ""

# Main demonstration
when isMainModule:
  echo "SPNEGO/GSS-API Usage Examples"
  echo "=".repeat(50)
  echo ""
  
  httpNegotiateAuth()
  smb2SessionSetup()
  ldapSaslBind()
  
  # Create and analyze a sample token
  let sampleCtx = newSpnegoContext(true, @[OID_KERBEROS5, OID_NTLMSSP])
  let sampleToken = sampleCtx.createInitialToken(@[], {gssMutualFlag, gssIntegFlag})
  analyzeSpnegoToken(sampleToken)
  
  multiRoundNegotiation()
  handleSpnegoErrors()
  
  echo "=".repeat(50)
  echo "Examples completed successfully!"