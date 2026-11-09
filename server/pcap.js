const ipv4 = (buffer, offset) => `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`

export function parsePcap(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 24) throw new Error('PCAP payload is too small')
  const magic = buffer.readUInt32LE(0)
  const littleEndian = magic === 0xa1b2c3d4 || magic === 0xa1b23c4d
  const bigEndian = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1
  if (!littleEndian && !bigEndian) throw new Error('Unsupported PCAP format; expected classic libpcap')
  const read32 = (offset) => littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset)
  const events = []
  let offset = 24
  while (offset + 16 <= buffer.length) {
    const seconds = read32(offset); const fraction = read32(offset + 4); const capturedLength = read32(offset + 8)
    const packetStart = offset + 16; const packetEnd = packetStart + capturedLength
    if (packetEnd > buffer.length) break
    const packet = buffer.subarray(packetStart, packetEnd)
    const event = { timestamp: new Date(seconds * 1000 + Math.floor(fraction / 1000)).toISOString(), event_type: 'pcap_packet', bytes: capturedLength, link_type: 'ethernet' }
    if (packet.length >= 14 && packet.readUInt16BE(12) === 0x0800 && packet.length >= 34) {
      const ipStart = 14; const ihl = (packet[ipStart] & 0x0f) * 4; const protocol = packet[ipStart + 9]
      event.src_ip = ipv4(packet, ipStart + 12); event.dest_ip = ipv4(packet, ipStart + 16); event.proto = protocol === 6 ? 'tcp' : protocol === 17 ? 'udp' : String(protocol)
      const transport = ipStart + ihl
      if ((protocol === 6 || protocol === 17) && transport + 4 <= packet.length) { event.src_port = packet.readUInt16BE(transport); event.dest_port = packet.readUInt16BE(transport + 2) }
    }
    events.push(event); offset = packetEnd
  }
  return events
}
