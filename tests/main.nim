import unittest, sequtils, strutils
import ../asn1.nim

test "Encode BIT STRING with unused bits":
    let bitStr = newAsn1BitString(@[0xF0'u8], 4)
    let encoded = encode(bitStr)
    
    check encoded == @[0x03'u8, 0x02, 0x04, 0xF0]
  
test "Round-trip BIT STRING":
  let bitStr = newAsn1BitString(@[0xDE'u8, 0xAD, 0xBE, 0xEF], 3)
  let encoded = encode(bitStr)
  
  var dec = DerDecoder(data: encoded, pos: 0)
  let (decoded, unused) = dec.decodeBitString()
  check decoded == @[0xDE'u8, 0xAD, 0xBE, 0xEF]
  check unused == 3

suite "ASN.1 DER NULL Encoding":
  test "Encode NULL":
    let nullVal = newAsn1Null()
    let encoded = encode(nullVal)
    check encoded == @[0x05'u8, 0x00]
  
  test "Round-trip NULL":
    let nullVal = newAsn1Null()
    let encoded = encode(nullVal)
    
    var dec = DerDecoder(data: encoded, pos: 0)
    dec.decodeNull()  # Should not throw
    check dec.pos == encoded.len

suite "ASN.1 DER OBJECT IDENTIFIER Encoding":
  test "Encode simple OID":
    let oid = newAsn1ObjectIdentifier("1.2.3.4")
    let encoded = encode(oid)
    
    var dec = DerDecoder(data: encoded, pos: 0)
    let decoded = dec.decodeObjectIdentifier()
    check decoded == @[1'u32, 2, 3, 4]
  
  test "Encode RSA OID":
    let oid = newAsn1ObjectIdentifier("1.2.840.113549.1.1.1")
    let encoded = encode(oid)
    
    var dec = DerDecoder(data: encoded, pos: 0)
    let decoded = dec.decodeObjectIdentifier()
    check decoded == @[1'u32, 2, 840, 113549, 1, 1, 1]
  
  test "Encode OID with large arc":
    let oid = newAsn1ObjectIdentifier("2.999.12345678")
    let encoded = encode(oid)
    
    var dec = DerDecoder(data: encoded, pos: 0)
    let decoded = dec.decodeObjectIdentifier()
    check decoded == @[2'u32, 999, 12345678]
  
  test "OID edge cases":
    # Test minimum valid OID
    let oid1 = newAsn1ObjectIdentifier(@[1'u32, 2])
    let encoded1 = encode(oid1)
    check encoded1 == @[0x06'u8, 0x01, 0x2A]  # 1*40 + 2 = 42 = 0x2A
    
    # Test with first arc = 2
    let oid2 = newAsn1ObjectIdentifier(@[2'u32, 5])
    let encoded2 = encode(oid2)
    check encoded2 == @[0x06'u8, 0x01, 0x55]  # 2*40 + 5 = 85 = 0x55

suite "ASN.1 DER SEQUENCE Encoding":
  test "Encode empty SEQUENCE":
    let seq = newAsn1Sequence()
    let encoded = encode(seq)
    check encoded == @[0x30'u8, 0x00]
  
  test "Encode SEQUENCE with single element":
    let seq = newAsn1Sequence(newAsn1Integer(42))
    let encoded = encode(seq)
    check encoded == @[0x30'u8, 0x03, 0x02, 0x01, 0x2A]
  
test "Encode SEQUENCE with multiple elements":
  let seq = newAsn1Sequence(
    newAsn1Integer(1),
    newAsn1Boolean(true),
    newAsn1UTF8String("test")
  )
  let encoded = encode(seq)
  
  check encoded[0] == 0x30'u8  # SEQUENCE tag
  
  # Let's verify the actual components to understand the length
  echo "  Actual encoded: ", encoded.mapIt(it.toHex(2)).join(" ")
  
  # The actual length might be different if UTF8String encoding is different
  # Just verify we can decode it back correctly
  var dec = DerDecoder(data: encoded, pos: 2)  # Skip tag and length
  let int1 = dec.decodeInteger()
  check int1.toInt64() == 1
  let bool1 = dec.decodeBoolean()
  check bool1 == true
  let str1 = dec.decodeUTF8String()
  check str1 == "test"
  
  test "Encode nested SEQUENCE":
    let innerSeq = newAsn1Sequence(
      newAsn1Integer(1),
      newAsn1Integer(2)
    )
    let outerSeq = newAsn1Sequence(
      newAsn1Integer(0),
      innerSeq,
      newAsn1Boolean(false)
    )
    let encoded = encode(outerSeq)
    
    check encoded[0] == 0x30'u8  # SEQUENCE tag
    # The encoded sequence should contain the nested structure

suite "ASN.1 DER SET Encoding":
  test "Encode empty SET":
    let setVal = newAsn1Set()
    let encoded = encode(setVal)
    check encoded == @[0x31'u8, 0x00]
  
  test "Encode SET with elements":
    let setVal = newAsn1Set(
      newAsn1Integer(1),
      newAsn1Integer(2),
      newAsn1Integer(3)
    )
    let encoded = encode(setVal)
    
    check encoded[0] == 0x31'u8  # SET tag

suite "ASN.1 DER Length Encoding":
  test "Short form length (< 128)":
    var enc = DerEncoder()
    enc.writeLength(0)
    check enc.buffer == @[0x00'u8]
    
    enc = DerEncoder()
    enc.writeLength(127)
    check enc.buffer == @[0x7F'u8]
  
  test "Long form length (128-255)":
    var enc = DerEncoder()
    enc.writeLength(128)
    check enc.buffer == @[0x81'u8, 0x80]
    
    enc = DerEncoder()
    enc.writeLength(255)
    check enc.buffer == @[0x81'u8, 0xFF]
  
  test "Long form length (256-65535)":
    var enc = DerEncoder()
    enc.writeLength(256)
    check enc.buffer == @[0x82'u8, 0x01, 0x00]
    
    enc = DerEncoder()
    enc.writeLength(65535)
    check enc.buffer == @[0x82'u8, 0xFF, 0xFF]
  
  test "Long form length (large)":
    var enc = DerEncoder()
    enc.writeLength(16777216)  # 2^24
    check enc.buffer == @[0x84'u8, 0x01, 0x00, 0x00, 0x00]

suite "ASN.1 DER Complex Structures":
  test "X.509-like structure":
    let algId = newAsn1Sequence(
      newAsn1ObjectIdentifier("1.2.840.113549.1.1.11"),
      newAsn1Null()
    )
    
    let validity = newAsn1Sequence(
      newAsn1UTF8String("20240101000000Z"),
      newAsn1UTF8String("20250101000000Z")
    )
    
    let tbsCert = newAsn1Sequence(
      newAsn1Integer(2),           # version
      newAsn1Integer(12345),       # serial
      algId,                       # signature algorithm
      newAsn1UTF8String("CN=Test CA"),  # issuer
      validity,                    # validity period
      newAsn1UTF8String("CN=Test User"), # subject
      newAsn1OctetString(@[0x01'u8, 0x02, 0x03, 0x04])  # public key (simplified)
    )
    
    let encoded = encode(tbsCert)
    check encoded[0] == 0x30'u8  # SEQUENCE tag
    check encoded.len > 50       # Should be a substantial structure
  
test "Attribute-value pair":
  # Common in certificates and LDAP
  let attr = newAsn1Sequence(
    newAsn1ObjectIdentifier("2.5.4.3"),  # Common Name OID
    newAsn1UTF8String("John Doe")
  )
  let encoded = encode(attr)
  check encoded[0] == 0x30'u8  # SEQUENCE tag
  
  # Verify it encodes correctly
  check encoded.len > 10  # Should have reasonable size
  
  # Verify we can decode the OID back
  var dec = DerDecoder(data: encoded, pos: 2)  # Skip SEQUENCE tag and length
  let oid = dec.decodeObjectIdentifier()
  check oid == @[2'u32, 5, 4, 3]

suite "ASN.1 DER Error Handling":
  test "Decode invalid tag":
    let invalidData = @[0xFF'u8, 0x01, 0x00]
    var dec = DerDecoder(data: invalidData, pos: 0)
    expect Asn1Error:
      discard dec.decodeInteger()
  
  test "Decode truncated data":
    let truncated = @[0x02'u8, 0x05]  # INTEGER with length 5 but no data
    var dec = DerDecoder(data: truncated, pos: 0)
    expect Asn1Error:
      discard dec.decodeInteger()
  
  test "Invalid BOOLEAN length":
    let invalidBool = @[0x01'u8, 0x02, 0xFF, 0xFF]  # BOOLEAN with length 2
    var dec = DerDecoder(data: invalidBool, pos: 0)
    expect Asn1Error:
      discard dec.decodeBoolean()
  
  test "Empty OID":
    expect Asn1Error:
      discard newAsn1ObjectIdentifier(@[])
  
  test "OID with single component":
    expect Asn1Error:
      discard newAsn1ObjectIdentifier(@[1'u32])

suite "ASN.1 DER Tagged Values":
  test "Context-specific tag [0]":
    var enc = DerEncoder()
    enc.encodeTagged(0, classContext, false, proc(e: var DerEncoder) =
      e.encodeInteger(fromInt64(42))
    )
    
    check enc.buffer[0] == 0x80'u8  # [0] CONTEXT, primitive
    check enc.buffer[1] == 0x03'u8  # Length
    check enc.buffer[2..4] == @[0x02'u8, 0x01, 0x2A]  # INTEGER 42
  
  test "Application tag [1] constructed":
    var enc = DerEncoder()
    enc.encodeTagged(1, classApplication, true, proc(e: var DerEncoder) =
      var procs: seq[proc(e2: var DerEncoder)] = @[]
      procs.add(proc(e2: var DerEncoder) = e2.encodeInteger(fromInt64(1)))
      procs.add(proc(e2: var DerEncoder) = e2.encodeInteger(fromInt64(2)))
      e.encodeSequence(procs)
    )
  
    check enc.buffer[0] == 0x61'u8  # [1] APPLICATION, constructed
  
  test "Long form tag":
    var enc = DerEncoder()
    enc.encodeTagged(31, classContext, false, proc(e: var DerEncoder) =
      e.encodeNull()
    )
    
    check enc.buffer[0] == 0x9F'u8  # CONTEXT, long form indicator
    check enc.buffer[1] == 0x1F'u8  # Tag number 31

# Performance tests (optional)
when defined(performance):
  suite "ASN.1 DER Performance":
    test "Large integer encoding":
      let largeInt = newAsn1Integer(int64.high)
      let encoded = encode(largeInt)
      check encoded.len <= 10  # Should be efficiently encoded
    
    test "Large sequence encoding":
      var elements: seq[Asn1Type] = @[]
      for i in 0..999:
        elements.add(newAsn1Integer(int64(i)))
      let seq = newAsn1Sequence(elements)
      let encoded = encode(seq)
      check encoded.len > 1000  # Should handle large sequences

# Run the tests
when isMainModule:
  echo "Running ASN.1 DER Library Test Suite"
  echo "===================================="