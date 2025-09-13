# ASN.1 DER Encoding/Decoding Library for Nim
# Designed for cross-platform use with Windows protocols (MSRPC, SMB, etc.)

import std/[strutils, sequtils, tables, options, endians]

type
  Asn1Tag* = enum
    tagBoolean = 0x01
    tagInteger = 0x02
    tagBitString = 0x03
    tagOctetString = 0x04
    tagNull = 0x05
    tagObjectIdentifier = 0x06
    tagUTF8String = 0x0C
    tagSequence = 0x30
    tagSet = 0x31
    tagPrintableString = 0x13
    tagIA5String = 0x16
    tagUTCTime = 0x17
    tagGeneralizedTime = 0x18
    tagUniversalString = 0x1C
    tagBMPString = 0x1E

  Asn1Class* = enum
    classUniversal = 0x00
    classApplication = 0x40
    classContext = 0x80
    classPrivate = 0xC0

  Asn1Type* = ref object of RootObj
    tag*: uint8
    class*: Asn1Class
    constructed*: bool

  Asn1Boolean* = ref object of Asn1Type
    value*: bool

  Asn1Integer* = ref object of Asn1Type
    value*: seq[uint8]  # Big-endian bytes

  Asn1BitString* = ref object of Asn1Type
    unused*: uint8
    value*: seq[uint8]

  Asn1OctetString* = ref object of Asn1Type
    value*: seq[uint8]

  Asn1Null* = ref object of Asn1Type

  Asn1ObjectIdentifier* = ref object of Asn1Type
    value*: seq[uint32]

  Asn1String* = ref object of Asn1Type
    value*: string

  Asn1Sequence* = ref object of Asn1Type
    elements*: seq[Asn1Type]

  Asn1Set* = ref object of Asn1Type
    elements*: seq[Asn1Type]

  Asn1Tagged* = ref object of Asn1Type
    tagNumber*: uint32
    implicit*: bool
    content*: Asn1Type

  DerEncoder* = object
    buffer*: seq[uint8]

  DerDecoder* = object
    data*: seq[uint8]
    pos*: int

  Asn1Error* = object of CatchableError

# Utility functions
proc newAsn1Error*(msg: string): ref Asn1Error =
  new(result)
  result.msg = msg

proc toInt64*(i: Asn1Integer): int64 =
  ## Convert ASN.1 INTEGER to int64
  if i.value.len == 0:
    return 0
  
  result = 0
  var negative = (i.value[0] and 0x80) != 0
  
  for b in i.value:
    result = (result shl 8) or int64(b)
  
  if negative and i.value.len < 8:
    # Sign extend
    for j in i.value.len..7:
      result = result or (int64(0xFF) shl (j * 8))

proc fromInt64*(value: int64): Asn1Integer =
  ## Create ASN.1 INTEGER from int64
  new(result)
  result.tag = uint8(tagInteger)
  result.class = classUniversal
  
  var v = value
  var bytes: seq[uint8] = @[]
  
  if v == 0:
    bytes = @[0'u8]
  else:
    var negative = v < 0
    if negative:
      v = not v  # Two's complement
    
    while v != 0:
      bytes.insert(uint8(v and 0xFF), 0)
      v = v shr 8
    
    if negative:
      # Add sign bit if needed
      if (bytes[0] and 0x80) == 0:
        bytes.insert(0xFF'u8, 0)
      # Two's complement
      var carry = 1'u8
      for i in countdown(bytes.high, 0):
        var sum = uint16(not bytes[i]) + uint16(carry)
        bytes[i] = uint8(sum and 0xFF)
        carry = uint8(sum shr 8)
    else:
      # Add padding if high bit is set
      if (bytes[0] and 0x80) != 0:
        bytes.insert(0'u8, 0)
  
  result.value = bytes

# DER Encoder
proc writeLength(enc: var DerEncoder, length: int) =
  if length < 128:
    enc.buffer.add(uint8(length))
  elif length < 256:
    enc.buffer.add(0x81'u8)
    enc.buffer.add(uint8(length))
  elif length < 65536:
    enc.buffer.add(0x82'u8)
    enc.buffer.add(uint8(length shr 8))
    enc.buffer.add(uint8(length and 0xFF))
  else:
    enc.buffer.add(0x84'u8)
    enc.buffer.add(uint8(length shr 24))
    enc.buffer.add(uint8((length shr 16) and 0xFF))
    enc.buffer.add(uint8((length shr 8) and 0xFF))
    enc.buffer.add(uint8(length and 0xFF))

proc writeTag(enc: var DerEncoder, tag: uint8, constructed: bool = false, class: Asn1Class = classUniversal) =
  var t = tag
  if constructed:
    t = t or 0x20
  t = t or uint8(class)
  enc.buffer.add(t)

proc encodeBoolean*(enc: var DerEncoder, value: bool) =
  enc.writeTag(uint8(tagBoolean))
  enc.writeLength(1)
  enc.buffer.add(if value: 0xFF'u8 else: 0x00'u8)

proc encodeInteger*(enc: var DerEncoder, value: Asn1Integer) =
  enc.writeTag(uint8(tagInteger))
  enc.writeLength(value.value.len)
  enc.buffer.add(value.value)

proc encodeOctetString*(enc: var DerEncoder, value: seq[uint8]) =
  enc.writeTag(uint8(tagOctetString))
  enc.writeLength(value.len)
  enc.buffer.add(value)

proc encodeBitString*(enc: var DerEncoder, value: seq[uint8], unused: uint8 = 0) =
  enc.writeTag(uint8(tagBitString))
  enc.writeLength(value.len + 1)
  enc.buffer.add(unused)
  enc.buffer.add(value)

proc encodeNull*(enc: var DerEncoder) =
  enc.writeTag(uint8(tagNull))
  enc.writeLength(0)

proc encodeObjectIdentifier*(enc: var DerEncoder, oid: seq[uint32]) =
  if oid.len < 2:
    raise newAsn1Error("OID must have at least 2 components")
  
  var encoded: seq[uint8] = @[]
  
  # Validation
  if oid[0] > 2:
    raise newAsn1Error("First OID component must be 0, 1, or 2")
  if oid[0] < 2 and oid[1] >= 40:
    raise newAsn1Error("Second OID component must be less than 40 when first is 0 or 1")
  
  # Encode first two components as: first * 40 + second
  let firstValue = oid[0] * 40 + oid[1]
  
  # Encode firstValue in base 128
  if firstValue < 128:
    encoded.add(uint8(firstValue))
  else:
    # Multi-byte encoding for first value
    var value = firstValue
    var bytes: seq[uint8] = @[]
    
    # Build bytes from least significant to most
    bytes.add(uint8(value and 0x7F))
    value = value shr 7
    
    while value > 0:
      bytes.insert(uint8((value and 0x7F) or 0x80), 0)
      value = value shr 7
    
    encoded.add(bytes)
  
  # Encode remaining components
  for i in 2..<oid.len:
    var value = oid[i]
    
    if value < 128:
      encoded.add(uint8(value))
    else:
      var bytes: seq[uint8] = @[]
      
      bytes.add(uint8(value and 0x7F))
      value = value shr 7
      
      while value > 0:
        bytes.insert(uint8((value and 0x7F) or 0x80), 0)
        value = value shr 7
      
      encoded.add(bytes)
  
  enc.writeTag(uint8(tagObjectIdentifier))
  enc.writeLength(encoded.len)
  enc.buffer.add(encoded)

proc encodeUTF8String*(enc: var DerEncoder, value: string) =
  enc.writeTag(uint8(tagUTF8String))
  enc.writeLength(value.len)
  for c in value:
    enc.buffer.add(uint8(c))

proc encodePrintableString*(enc: var DerEncoder, value: string) =
  enc.writeTag(uint8(tagPrintableString))
  enc.writeLength(value.len)
  for c in value:
    enc.buffer.add(uint8(c))

proc encodeIA5String*(enc: var DerEncoder, value: string) =
  enc.writeTag(uint8(tagIA5String))
  enc.writeLength(value.len)
  for c in value:
    enc.buffer.add(uint8(c))

proc encodeSequence*(enc: var DerEncoder, elements: seq[proc(e: var DerEncoder)]) =
  var temp = DerEncoder()
  for element in elements:
    element(temp)
  
  enc.writeTag(uint8(tagSequence), true)
  enc.writeLength(temp.buffer.len)
  enc.buffer.add(temp.buffer)

proc encodeSet*(enc: var DerEncoder, elements: seq[proc(e: var DerEncoder)]) =
  var temp = DerEncoder()
  for element in elements:
    element(temp)
  
  enc.writeTag(uint8(tagSet), true)
  enc.writeLength(temp.buffer.len)
  enc.buffer.add(temp.buffer)

proc encodeTagged*(enc: var DerEncoder, tagNumber: uint32, class: Asn1Class, 
                   constructed: bool, content: proc(e: var DerEncoder)) =
  var temp = DerEncoder()
  content(temp)
  
  if tagNumber < 31:
    enc.writeTag(uint8(tagNumber), constructed, class)
  else:
    # Long form tag
    enc.buffer.add(uint8(class) or (if constructed: 0x20'u8 else: 0'u8) or 0x1F'u8)
    var t = tagNumber
    var bytes: seq[uint8] = @[]
    bytes.add(uint8(t and 0x7F))
    t = t shr 7
    while t > 0:
      bytes.insert(uint8((t and 0x7F) or 0x80), 0)
      t = t shr 7
    enc.buffer.add(bytes)
  
  enc.writeLength(temp.buffer.len)
  enc.buffer.add(temp.buffer)

# DER Decoder
proc readByte*(dec: var DerDecoder): uint8 =
  if dec.pos >= dec.data.len:
    raise newAsn1Error("Unexpected end of data")
  result = dec.data[dec.pos]
  inc dec.pos

proc peekByte(dec: DerDecoder): uint8 =
  if dec.pos >= dec.data.len:
    raise newAsn1Error("Unexpected end of data")
  result = dec.data[dec.pos]

proc readTag(dec: var DerDecoder): tuple[tag: uint32, constructed: bool, class: Asn1Class] =
  let b = dec.readByte()
  result.class = Asn1Class(b and 0xC0)
  result.constructed = (b and 0x20) != 0
  
  if (b and 0x1F) == 0x1F:
    # Long form
    result.tag = 0
    var b2 = dec.readByte()
    while (b2 and 0x80) != 0:
      result.tag = (result.tag shl 7) or uint32(b2 and 0x7F)
      b2 = dec.readByte()
    result.tag = (result.tag shl 7) or uint32(b2)
  else:
    result.tag = uint32(b and 0x1F)

proc readLength(dec: var DerDecoder): int =
  let b = dec.readByte()
  if b == 0x80:
    raise newAsn1Error("Indefinite length not supported in DER")
  elif (b and 0x80) == 0:
    result = int(b)
  else:
    let numBytes = int(b and 0x7F)
    if numBytes > 4:
      raise newAsn1Error("Length too large")
    result = 0
    for i in 0..<numBytes:
      result = (result shl 8) or int(dec.readByte())

proc readBytes*(dec: var DerDecoder, length: int): seq[uint8] =
  if dec.pos + length > dec.data.len:
    raise newAsn1Error("Unexpected end of data")
  result = dec.data[dec.pos..<dec.pos + length]
  dec.pos += length

proc decodeBoolean*(dec: var DerDecoder): bool =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagBoolean) or class != classUniversal or constructed:
    raise newAsn1Error("Expected BOOLEAN")
  let length = dec.readLength()
  if length != 1:
    raise newAsn1Error("Invalid BOOLEAN length")
  result = dec.readByte() != 0

proc decodeInteger*(dec: var DerDecoder): Asn1Integer =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagInteger) or class != classUniversal or constructed:
    raise newAsn1Error("Expected INTEGER")
  let length = dec.readLength()
  new(result)
  result.tag = uint8(tagInteger)
  result.class = classUniversal
  result.value = dec.readBytes(length)

proc decodeOctetString*(dec: var DerDecoder): seq[uint8] =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagOctetString) or class != classUniversal:
    raise newAsn1Error("Expected OCTET STRING")
  let length = dec.readLength()
  result = dec.readBytes(length)

proc decodeBitString*(dec: var DerDecoder): tuple[value: seq[uint8], unused: uint8] =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagBitString) or class != classUniversal:
    raise newAsn1Error("Expected BIT STRING")
  let length = dec.readLength()
  if length < 1:
    raise newAsn1Error("Invalid BIT STRING length")
  result.unused = dec.readByte()
  result.value = dec.readBytes(length - 1)

proc decodeNull*(dec: var DerDecoder) =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagNull) or class != classUniversal or constructed:
    raise newAsn1Error("Expected NULL")
  let length = dec.readLength()
  if length != 0:
    raise newAsn1Error("Invalid NULL length")

proc decodeObjectIdentifier*(dec: var DerDecoder): seq[uint32] =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagObjectIdentifier) or class != classUniversal or constructed:
    raise newAsn1Error("Expected OBJECT IDENTIFIER")
  let length = dec.readLength()
  let bytes = dec.readBytes(length)
  
  if bytes.len == 0:
    raise newAsn1Error("Empty OID")
  
  # Decode first value (which encodes first two components)
  var i = 0
  var firstValue: uint32 = 0
  var b = bytes[i]
  
  while (b and 0x80) != 0:
    firstValue = (firstValue shl 7) or uint32(b and 0x7F)
    inc i
    if i >= bytes.len:
      raise newAsn1Error("Invalid OID encoding")
    b = bytes[i]
  firstValue = (firstValue shl 7) or uint32(b)
  inc i
  
  # Extract first two components from firstValue
  # The standard says if firstValue < 40, first arc is 0
  # if firstValue < 80, first arc is 1
  # otherwise first arc is 2
  if firstValue < 40:
    result = @[0'u32, firstValue]
  elif firstValue < 80:
    result = @[1'u32, firstValue - 40]
  else:
    # When first arc is 2, the second arc is (firstValue - 80)
    result = @[2'u32, firstValue - 80]
  
  # Decode remaining components
  while i < bytes.len:
    var value: uint32 = 0
    b = bytes[i]
    while (b and 0x80) != 0:
      value = (value shl 7) or uint32(b and 0x7F)
      inc i
      if i >= bytes.len:
        raise newAsn1Error("Invalid OID encoding")
      b = bytes[i]
    value = (value shl 7) or uint32(b)
    result.add(value)
    inc i

proc decodeUTF8String*(dec: var DerDecoder): string =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagUTF8String) or class != classUniversal:
    raise newAsn1Error("Expected UTF8String")
  let length = dec.readLength()
  let bytes = dec.readBytes(length)
  result = ""
  for b in bytes:
    result.add(char(b))

proc decodePrintableString*(dec: var DerDecoder): string =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagPrintableString) or class != classUniversal:
    raise newAsn1Error("Expected PrintableString")
  let length = dec.readLength()
  let bytes = dec.readBytes(length)
  result = ""
  for b in bytes:
    result.add(char(b))

proc decodeIA5String*(dec: var DerDecoder): string =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagIA5String) or class != classUniversal:
    raise newAsn1Error("Expected IA5String")
  let length = dec.readLength()
  let bytes = dec.readBytes(length)
  result = ""
  for b in bytes:
    result.add(char(b))

proc decodeSequence*(dec: var DerDecoder): seq[seq[uint8]] =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagSequence) or class != classUniversal or not constructed:
    raise newAsn1Error("Expected SEQUENCE")
  let length = dec.readLength()
  let endPos = dec.pos + length
  
  result = @[]
  while dec.pos < endPos:
    let elemStart = dec.pos
    let (elemTag, elemConstructed, elemClass) = dec.readTag()
    let elemLength = dec.readLength()
    dec.pos = elemStart  # Reset to start of element
    let elemBytes = dec.readBytes(elemLength + (dec.pos - elemStart))
    result.add(elemBytes)

proc decodeSet*(dec: var DerDecoder): seq[seq[uint8]] =
  let (tag, constructed, class) = dec.readTag()
  if tag != uint32(tagSet) or class != classUniversal or not constructed:
    raise newAsn1Error("Expected SET")
  let length = dec.readLength()
  let endPos = dec.pos + length
  
  result = @[]
  while dec.pos < endPos:
    let elemStart = dec.pos
    let (elemTag, elemConstructed, elemClass) = dec.readTag()
    let elemLength = dec.readLength()
    dec.pos = elemStart  # Reset to start of element
    let elemBytes = dec.readBytes(elemLength + (dec.pos - elemStart))
    result.add(elemBytes)

# High-level encoding functions
proc encode*(value: Asn1Type): seq[uint8] =
  var enc = DerEncoder()
  
  if value of Asn1Boolean:
    let b = Asn1Boolean(value)
    enc.encodeBoolean(b.value)
  elif value of Asn1Integer:
    let i = Asn1Integer(value)
    enc.encodeInteger(i)
  elif value of Asn1OctetString:
    let o = Asn1OctetString(value)
    enc.encodeOctetString(o.value)
  elif value of Asn1BitString:
    let b = Asn1BitString(value)
    enc.encodeBitString(b.value, b.unused)
  elif value of Asn1Null:
    enc.encodeNull()
  elif value of Asn1ObjectIdentifier:
    let o = Asn1ObjectIdentifier(value)
    enc.encodeObjectIdentifier(o.value)
  elif value of Asn1String:
    let s = Asn1String(value)
    case s.tag:
    of uint8(tagUTF8String):
      enc.encodeUTF8String(s.value)
    of uint8(tagPrintableString):
      enc.encodePrintableString(s.value)
    of uint8(tagIA5String):
      enc.encodeIA5String(s.value)
    else:
      raise newAsn1Error("Unsupported string type")
  elif value of Asn1Sequence:
    let s = Asn1Sequence(value)
    var tempEnc = DerEncoder()
    for elem in s.elements:
      tempEnc.buffer.add(encode(elem))
    enc.writeTag(uint8(tagSequence), true)
    enc.writeLength(tempEnc.buffer.len)
    enc.buffer.add(tempEnc.buffer)
  elif value of Asn1Set:
    let s = Asn1Set(value)
    var tempEnc = DerEncoder()
    for elem in s.elements:
      let encodedElem = encode(elem)
      tempEnc.buffer.add(encodedElem)
    enc.writeTag(uint8(tagSet), true)
    enc.writeLength(tempEnc.buffer.len)
    enc.buffer.add(tempEnc.buffer)
  else:
    raise newAsn1Error("Unsupported ASN.1 type")
  
  result = enc.buffer

# Convenience constructors
proc newAsn1Boolean*(value: bool): Asn1Boolean =
  new(result)
  result.tag = uint8(tagBoolean)
  result.class = classUniversal
  result.value = value

proc newAsn1Integer*(value: int64): Asn1Integer =
  fromInt64(value)

proc newAsn1OctetString*(value: seq[uint8]): Asn1OctetString =
  new(result)
  result.tag = uint8(tagOctetString)
  result.class = classUniversal
  result.value = value

proc newAsn1OctetString*(value: string): Asn1OctetString =
  new(result)
  result.tag = uint8(tagOctetString)
  result.class = classUniversal
  result.value = @[]
  for c in value:
    result.value.add(uint8(ord(c)))

proc newAsn1BitString*(value: seq[uint8], unused: uint8 = 0): Asn1BitString =
  new(result)
  result.tag = uint8(tagBitString)
  result.class = classUniversal
  result.value = value
  result.unused = unused

proc newAsn1Null*(): Asn1Null =
  new(result)
  result.tag = uint8(tagNull)
  result.class = classUniversal

proc newAsn1ObjectIdentifier*(oid: seq[uint32]): Asn1ObjectIdentifier =
  if oid.len < 2:
    raise newAsn1Error("OID must have at least 2 components")
  if oid[0] > 2:
    raise newAsn1Error("First OID component must be 0, 1, or 2")
  if oid[0] < 2 and oid[1] >= 40:
    raise newAsn1Error("Second OID component must be less than 40 when first is 0 or 1")
  
  new(result)
  result.tag = uint8(tagObjectIdentifier)
  result.class = classUniversal
  result.value = oid

proc newAsn1ObjectIdentifier*(oid: string): Asn1ObjectIdentifier =
  ## Create OID from dot notation (e.g., "1.2.840.113549")
  let parts = oid.split('.')
  if parts.len < 2:
    raise newAsn1Error("OID must have at least 2 components")
  
  var values: seq[uint32] = @[]
  for part in parts:
    try:
      values.add(uint32(parseInt(part)))
    except ValueError:
      raise newAsn1Error("Invalid OID component: " & part)
  
  newAsn1ObjectIdentifier(values)

proc newAsn1UTF8String*(value: string): Asn1String =
  new(result)
  result.tag = uint8(tagUTF8String)
  result.class = classUniversal
  result.value = value

proc newAsn1PrintableString*(value: string): Asn1String =
  new(result)
  result.tag = uint8(tagPrintableString)
  result.class = classUniversal
  result.value = value

proc newAsn1IA5String*(value: string): Asn1String =
  new(result)
  result.tag = uint8(tagIA5String)
  result.class = classUniversal
  result.value = value

proc newAsn1Sequence*(elements: varargs[Asn1Type]): Asn1Sequence =
  new(result)
  result.tag = uint8(tagSequence)
  result.class = classUniversal
  result.constructed = true
  result.elements = @elements

proc newAsn1Set*(elements: varargs[Asn1Type]): Asn1Set =
  new(result)
  result.tag = uint8(tagSet)
  result.class = classUniversal
  result.constructed = true
  result.elements = @elements

proc newAsn1SequenceFromSeq*(elements: seq[Asn1Type]): Asn1Sequence =
  ## Create a SEQUENCE from a seq of elements (useful for dynamic construction)
  new(result)
  result.tag = uint8(tagSequence)
  result.class = classUniversal
  result.constructed = true
  result.elements = elements

proc newAsn1SetFromSeq*(elements: seq[Asn1Type]): Asn1Set =
  ## Create a SET from a seq of elements (useful for dynamic construction)
  new(result)
  result.tag = uint8(tagSet)
  result.class = classUniversal
  result.constructed = true
  result.elements = elements

# Example exports for library users
export Asn1Tag, Asn1Class, Asn1Type, Asn1Boolean, Asn1Integer, Asn1BitString
export Asn1OctetString, Asn1Null, Asn1ObjectIdentifier, Asn1String
export Asn1Sequence, Asn1Set, Asn1Tagged, Asn1Error
export DerEncoder, DerDecoder
export newAsn1Error, toInt64, fromInt64
export encode, newAsn1Boolean, newAsn1Integer, newAsn1OctetString
export newAsn1BitString, newAsn1Null, newAsn1ObjectIdentifier
export newAsn1UTF8String, newAsn1PrintableString, newAsn1IA5String
export newAsn1Sequence, newAsn1Set
export newAsn1SequenceFromSeq, newAsn1SetFromSeq  # Add these exports
export encodeBoolean, encodeInteger, encodeOctetString, encodeBitString
export encodeNull, encodeObjectIdentifier, encodeUTF8String
export encodePrintableString, encodeIA5String, encodeSequence, encodeSet
export encodeTagged, writeLength, writeTag
export decodeBoolean, decodeInteger, decodeOctetString, decodeBitString
export decodeNull, decodeObjectIdentifier, decodeUTF8String
export decodePrintableString, decodeIA5String, decodeSequence, decodeSet
export readTag, readLength