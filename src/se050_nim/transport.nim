# =============================================================================
# SE050 T=1 over I2C transport
# =============================================================================
#
# Minimal transport layer for NXP SE050 / SE05x.
#
# Layering:
#
#   i2c.nim
#     ↓
#   se050_transport.nim
#     ↓
#   se050_uid.nim / se050_apdu.nim
#
# This module intentionally does not depend on NXP Plug & Trust Middleware.

import std/strformat
import std/strutils
import std/os

import ./errors
import ./i2c

# =============================================================================
# Types
# =============================================================================

type
  Se050Transport* = ref object
    i2c*: I2cdev
    debug*: bool
    txSeq: uint8
    rxSeq: uint8
    ifsc*: int
    maxReadLen*: int
    maxRetries*: int
    maxReadPolls*: int
    maxReadBackoffMs*: int

  T1FrameKind = enum
    fkIBlock,
    fkRBlock,
    fkSBlock

  T1Frame = object
    nad: uint8
    pcb: uint8
    inf: seq[uint8]
    kind: T1FrameKind

# =============================================================================
# Constants
# =============================================================================

const
  DefaultSe050I2cAddress* = 0x48'u8

  NadHostToSe = 0x5A'u8
  NadSeToHost = 0xA5'u8

  PcbISeqMask = 0x40'u8
  PcbIMore = 0x20'u8

  PcbRBlock = 0x80'u8
  PcbRSeqMask = 0x10'u8
  PcbRErrorMask = 0x0F'u8

  PcbSBlockReq = 0xC0'u8
  PcbSBlockRsp = 0xE0'u8
  PcbSTypeMask = 0x1F'u8

  STypeWtx = 0x03'u8
  STypeGetAtr = 0x0F'u8

  HeaderLen = 3
  CrcLen = 2

  # A cryptographic command such as ReadObject-with-Attestation may keep the
  # SE050 busy longer than ordinary management/read commands. During that
  # period the device NACKs I2C reads. Poll with an increasing delay, following
  # the behaviour of NXP's T=1-over-I2C PAL.
  DefaultMaxReadPolls* = 100
  DefaultMaxReadBackoffMs* = 20

# =============================================================================
# Byte helpers
# =============================================================================

proc toBytes(s: openArray[char]): seq[uint8] =
  result = newSeq[uint8](s.len)
  for i, c in s:
    result[i] = uint8(c)

proc hexByte(b: uint8): string =
  result = &"{b:02X}"

proc hexDump*(data: openArray[uint8]): string =
  for i, b in data:
    if i > 0:
      result.add(" ")
    result.add(hexByte(b))

# =============================================================================
# CRC
# =============================================================================

proc computeCrc(data: openArray[uint8], offset: int = 0, length: int = -1): uint16 =
  ## CRC implementation matching NXP phNxpEseProto7816_ComputeCRC()
  ## for T1oI2C_UM11225.
  var stop = length
  if stop < 0:
    stop = data.len

  var cal = 0xFFFF'u16

  for i in offset ..< stop:
    cal = cal xor uint16(data[i])
    for _ in 0 ..< 8:
      if (cal and 0x0001'u16) == 0x0001'u16:
        cal = (cal shr 1) xor 0x8408'u16
      else:
        cal = cal shr 1

  cal = cal xor 0xFFFF'u16
  result = ((cal and 0x00FF'u16) shl 8) or ((cal shr 8) and 0x00FF'u16)

proc appendCrc(frame: var seq[uint8]) =
  let crc = computeCrc(frame)
  frame.add(uint8((crc shr 8) and 0xFF))
  frame.add(uint8(crc and 0xFF))

proc checkCrc(frame: openArray[uint8]): bool =
  if frame.len < CrcLen:
    return false

  let got = (uint16(frame[frame.len - 2]) shl 8) or uint16(frame[frame.len - 1])
  let calc = computeCrc(frame, 0, frame.len - CrcLen)
  result = got == calc

# =============================================================================
# Frame construction
# =============================================================================

proc makeFrame(pcb: uint8, inf: openArray[uint8] = []): seq[uint8] =
  doAssert inf.len <= 255

  result = newSeq[uint8](0)
  result.add(NadHostToSe)
  result.add(pcb)
  result.add(uint8(inf.len))
  for b in inf:
    result.add(b)
  result.appendCrc()

proc makeIBlock(self: Se050Transport, data: openArray[uint8], more: bool): seq[uint8] =
  var pcb = uint8((self.txSeq and 0x01'u8) shl 6)
  if more:
    pcb = pcb or PcbIMore
  result = makeFrame(pcb, data)

proc makeRBlock(self: Se050Transport, errorCode: uint8 = 0): seq[uint8] =
  var pcb = PcbRBlock or uint8((self.rxSeq and 0x01'u8) shl 4)
  pcb = pcb or (errorCode and PcbRErrorMask)
  result = makeFrame(pcb)

proc makeSBlockRequest(stype: uint8, inf: openArray[uint8] = []): seq[uint8] =
  result = makeFrame(PcbSBlockReq or (stype and PcbSTypeMask), inf)

proc makeSBlockResponse(stype: uint8, inf: openArray[uint8] = []): seq[uint8] =
  result = makeFrame(PcbSBlockRsp or (stype and PcbSTypeMask), inf)

# =============================================================================
# Raw I2C access
# =============================================================================

proc writeRaw(self: Se050Transport, frame: openArray[uint8]): SE[void] =
  if self.debug:
    echo "T1 TX: ", hexDump(frame)

  if not self.i2c.write(frame):
    return fail[void](seI2cWriteFailed, "I2C write failed")

  result = ok()

proc readRaw(self: Se050Transport, readLen: int): SE[seq[uint8]] =
  ## Polls until the SE050 has a T=1 frame ready.
  ##
  ## SE050 signals a busy state by NACKing I2C reads. Commands involving
  ## internal asymmetric cryptography can remain busy long enough that the
  ## previous fixed 8 x 5 ms window expired before the first WTX/I-block was
  ## available. Use a bounded incremental backoff instead.
  for attempt in 0 ..< self.maxReadPolls:
    let rxChars = self.i2c.read(readLen)
    if rxChars.len > 0:
      let rx = toBytes(rxChars)
      if self.debug:
        echo "T1 RX: ", hexDump(rx)
      return ok(rx)

    if attempt + 1 < self.maxReadPolls:
      let delayMs = min(attempt + 1, self.maxReadBackoffMs)
      if self.debug:
        echo &"T1 RX busy: poll {attempt + 1}/{self.maxReadPolls}, retry in {delayMs} ms"
      sleep(delayMs)

  result = fail[seq[uint8]](
    seI2cReadFailed,
    &"I2C read returned no data after {self.maxReadPolls} polls"
  )

proc readRaw(self: Se050Transport): SE[seq[uint8]] =
  result = self.readRaw(self.maxReadLen)

# =============================================================================
# Frame parsing
# =============================================================================

proc parseFrame(raw: openArray[uint8]): SE[T1Frame] =
  if raw.len < HeaderLen + CrcLen:
    return fail[T1Frame](seFrameTooShort, &"frame too short: {raw.len}")

  let nad = raw[0]
  if nad != NadSeToHost:
    return fail[T1Frame](seInvalidNad, &"unexpected NAD: 0x{nad:02X}")

  let pcb = raw[1]
  let payloadLen = int(raw[2])
  let totalLen = int(HeaderLen) + payloadLen + int(CrcLen)

  if raw.len < totalLen:
    return fail[T1Frame](seInvalidLen, &"incomplete frame: got {raw.len}, need {totalLen}")

  var frameBytes = newSeq[uint8](totalLen)
  for i in 0 ..< totalLen:
    frameBytes[i] = raw[i]

  if not checkCrc(frameBytes):
    return fail[T1Frame](seInvalidCrc, "CRC mismatch")

  var f: T1Frame
  f.nad = nad
  f.pcb = pcb
  f.inf = newSeq[uint8](payloadLen)
  for i in 0 ..< payloadLen:
    f.inf[i] = frameBytes[HeaderLen + i]

  if (pcb and 0x80'u8) == 0x00'u8:
    f.kind = fkIBlock
  elif (pcb and 0xC0'u8) == 0x80'u8:
    f.kind = fkRBlock
  elif (pcb and 0xC0'u8) == 0xC0'u8:
    f.kind = fkSBlock
  else:
    return fail[T1Frame](seUnexpectedFrame, &"unknown PCB: 0x{pcb:02X}")

  result = ok(f)

proc readFrame(self: Se050Transport): SE[T1Frame] =
  let rawRes = self.readRaw()
  if not rawRes.ok:
    return fail[T1Frame](rawRes.error.kind, rawRes.error.message)

  result = parseFrame(rawRes.value)


proc rBlockErrorMessage(pcb: uint8): string =
  let code = pcb and PcbRErrorMask
  case code
  of 0x00'u8:
    result = "R-ACK"
  of 0x01'u8:
    result = "R-NACK: EDC/CRC error"
  of 0x02'u8:
    result = "R-NACK: sequence error"
  of 0x03'u8:
    result = "R-NACK: other error"
  else:
    result = &"R-NACK: unknown error code 0x{code:02X}"

# =============================================================================
# Transport API
# =============================================================================

proc newSe050Transport*(i2c: I2cdev, debug: bool = false): Se050Transport =
  result = new Se050Transport
  result.i2c = i2c
  result.debug = debug
  result.txSeq = 0
  result.rxSeq = 0
  result.ifsc = 254
  result.maxReadLen = 260
  result.maxRetries = 8
  result.maxReadPolls = DefaultMaxReadPolls
  result.maxReadBackoffMs = DefaultMaxReadBackoffMs

# --------------------------------------------------------------------------------
# API:
# --------------------------------------------------------------------------------

proc openSe050*(bus: int, address: uint8 = DefaultSe050I2cAddress, debug: bool = false): Se050Transport =
  ## Opens SE050 on a Linux I2C bus.
  ##
  ## The lower-level i2c.nim module is intentionally hidden from users.
  let i2cdev = newI2c(bus, address, debug = debug)
  result = newSe050Transport(i2cdev, debug = debug)

proc requestAtrOnce(self: Se050Transport): SE[seq[uint8]] =
  let req = makeSBlockRequest(STypeGetAtr)
  let w = self.writeRaw(req)
  if not w.ok:
    return fail[seq[uint8]](w.error.kind, w.error.message)

  let raw = self.readRaw(40)
  if not raw.ok:
    return fail[seq[uint8]](raw.error.kind, raw.error.message)

  let f = parseFrame(raw.value)
  if not f.ok:
    return fail[seq[uint8]](f.error.kind, f.error.message)

  if f.value.kind != fkSBlock:
    if f.value.kind == fkRBlock:
      return fail[seq[uint8]](seUnexpectedFrame, rBlockErrorMessage(f.value.pcb))
    return fail[seq[uint8]](seUnexpectedFrame, "ATR response was not an S-block")

  self.txSeq = 0
  self.rxSeq = 0
  result = ok(f.value.inf)

proc requestAtr*(self: Se050Transport): SE[seq[uint8]] =
  ## Sends S(GET_ATR) request.
  ##
  ## The raw frame should be:
  ##
  ##   5A CF 00 37 7F
  ##
  ## SE050 commonly returns an S(GET_ATR) response with LEN=0x23,
  ## so the complete T=1oI2C frame is 3 + 35 + 2 = 40 bytes.
  ##
  ## If a previous short/incomplete read left the SE050 T=1 sequence state
  ## misaligned, the first request may return R-NACK sequence error. In that
  ## case, retry GET_ATR once after resetting local sequence counters.
  let first = self.requestAtrOnce()
  if first.ok:
    return first

  if first.error.kind == seUnexpectedFrame and
      first.error.message.contains("sequence error"):
    self.txSeq = 0
    self.rxSeq = 0

    let second = self.requestAtrOnce()
    if second.ok:
      return second

    return fail[seq[uint8]](
      second.error.kind,
      second.error.message,
      second.error.sw
    )

  result = first

proc sendWtxResponse(self: Se050Transport, wtxm: uint8): SE[void] =
  let rsp = makeSBlockResponse(STypeWtx, @[wtxm])
  result = self.writeRaw(rsp)

proc sendRACK(self: Se050Transport): SE[void] =
  let ack = self.makeRBlock(0)
  result = self.writeRaw(ack)

proc transceiveApdu*(self: Se050Transport, apdu: openArray[uint8]): SE[seq[uint8]] =
  ## Sends one APDU and returns the APDU response bytes.
  ##
  ## The returned bytes are the INF payload reassembled from I-block responses.
  ## For SE050 APDUs, this usually ends with SW1 SW2, e.g. 90 00.
  if apdu.len == 0:
    return fail[seq[uint8]](seApduTooLarge, "empty APDU is not allowed")

  var offset = 0
  var retries = 0

  while offset < apdu.len:
    let chunkLen = min(self.ifsc, apdu.len - offset)
    let more = (offset + chunkLen) < apdu.len

    var chunk = newSeq[uint8](chunkLen)
    for i in 0 ..< chunkLen:
      chunk[i] = apdu[offset + i]

    let tx = self.makeIBlock(chunk, more)
    let w = self.writeRaw(tx)
    if not w.ok:
      return fail[seq[uint8]](w.error.kind, w.error.message)

    if more:
      while true:
        let rf = self.readFrame()
        if not rf.ok:
          return fail[seq[uint8]](rf.error.kind, rf.error.message)

        case rf.value.kind
        of fkRBlock:
          let errorCode = rf.value.pcb and PcbRErrorMask
          if errorCode != 0:
            retries += 1
            if retries > self.maxRetries:
              return fail[seq[uint8]](seTooManyRetries, "too many R-NACK retries")
            continue

          self.txSeq = self.txSeq xor 1
          offset += chunkLen
          break

        of fkSBlock:
          let stype = rf.value.pcb and PcbSTypeMask
          if stype == STypeWtx:
            let wtxm = if rf.value.inf.len > 0: rf.value.inf[0] else: 1'u8
            let wr = self.sendWtxResponse(wtxm)
            if not wr.ok:
              return fail[seq[uint8]](wr.error.kind, wr.error.message)
          else:
            return fail[seq[uint8]](
              seUnexpectedFrame,
              &"unexpected S-block during command chaining: 0x{rf.value.pcb:02X}"
            )

        of fkIBlock:
          return fail[seq[uint8]](
            seUnexpectedFrame,
            "unexpected I-block before final command block"
          )
    else:
      self.txSeq = self.txSeq xor 1
      offset += chunkLen

  var response: seq[uint8] = @[]

  while true:
    let rf = self.readFrame()
    if not rf.ok:
      return fail[seq[uint8]](rf.error.kind, rf.error.message)

    case rf.value.kind
    of fkIBlock:
      let seqNo = uint8((rf.value.pcb and PcbISeqMask) shr 6)
      if seqNo != self.rxSeq:
        let nack = self.makeRBlock(0x02)
        discard self.writeRaw(nack)
        return fail[seq[uint8]](
          seUnexpectedFrame,
          &"unexpected I-block seq: got {seqNo}, expected {self.rxSeq}"
        )

      response.add(rf.value.inf)
      self.rxSeq = self.rxSeq xor 1

      let more = (rf.value.pcb and PcbIMore) != 0
      if more:
        let ack = self.sendRACK()
        if not ack.ok:
          return fail[seq[uint8]](ack.error.kind, ack.error.message)
      else:
        return ok(response)

    of fkSBlock:
      let stype = rf.value.pcb and PcbSTypeMask
      if stype == STypeWtx:
        let wtxm = if rf.value.inf.len > 0: rf.value.inf[0] else: 1'u8
        let wr = self.sendWtxResponse(wtxm)
        if not wr.ok:
          return fail[seq[uint8]](wr.error.kind, wr.error.message)
      else:
        return fail[seq[uint8]](
          seUnexpectedFrame,
          &"unexpected S-block while waiting APDU response: 0x{rf.value.pcb:02X}"
        )

    of fkRBlock:
      let errorCode = rf.value.pcb and PcbRErrorMask
      if errorCode != 0:
        return fail[seq[uint8]](seDeviceRnaK, &"device returned R-NACK: 0x{errorCode:02X}")
      return fail[seq[uint8]](seUnexpectedFrame, "unexpected R-ACK while waiting APDU response")
