using System.Net;

namespace Proxify.Common;

/// <summary>
/// Построение и разбор «сырых» IPv4/UDP-пакетов.
/// Используется прокси-клиентом для подмены исходного IP-адреса.
/// </summary>
public static class Packets
{
    public const byte ProtoUdp = 17;

    private const int IpHeaderLength = 20;
    private const int UdpHeaderLength = 8;

    /// <summary>
    /// Собирает полный IPv4 + UDP датаграмму с заданным (в том числе чужим) исходным адресом.
    /// </summary>
    public static byte[] BuildIpv4Udp(
        IPAddress sourceIp, IPAddress destinationIp,
        ushort sourcePort, ushort destinationPort,
        ReadOnlySpan<byte> payload, ushort ipId)
    {
        var udpLength = UdpHeaderLength + payload.Length;
        var totalLength = IpHeaderLength + udpLength;

        var packet = new byte[totalLength];

        // --- IPv4 header ---
        packet[0] = 0x45;                              // version 4, IHL 5
        packet[1] = 0x00;                              // DSCP/ECN
        packet[2] = (byte)(totalLength >> 8);          // total length
        packet[3] = (byte)totalLength;
        packet[4] = (byte)(ipId >> 8);                 // identification
        packet[5] = (byte)ipId;
        packet[6] = 0x40;                              // DF flag
        packet[7] = 0x00;
        packet[8] = 64;                                // TTL
        packet[9] = ProtoUdp;                          // protocol = UDP
        packet[10] = 0x00;                             // header checksum (заполним ниже)
        packet[11] = 0x00;

        var s = sourceIp.GetAddressBytes();
        var d = destinationIp.GetAddressBytes();
        Array.Copy(s, 0, packet, 12, 4);               // source IP
        Array.Copy(d, 0, packet, 16, 4);               // destination IP

        // --- UDP header ---
        var u = IpHeaderLength;
        packet[u + 0] = (byte)(sourcePort >> 8);       // source port
        packet[u + 1] = (byte)sourcePort;
        packet[u + 2] = (byte)(destinationPort >> 8);  // destination port
        packet[u + 3] = (byte)destinationPort;
        packet[u + 4] = (byte)(udpLength >> 8);        // UDP length
        packet[u + 5] = (byte)udpLength;
        packet[u + 6] = 0x00;                          // UDP checksum (заполним ниже)
        packet[u + 7] = 0x00;

        payload.CopyTo(packet.AsSpan(u + UdpHeaderLength));

        var ipChecksum = Checksum.Ip(packet.AsSpan(0, IpHeaderLength));
        packet[10] = (byte)(ipChecksum >> 8);
        packet[11] = (byte)ipChecksum;

        var udpChecksum = Checksum.Udp(sourceIp, destinationIp, (ushort)udpLength, packet.AsSpan(u, udpLength));
        packet[u + 6] = (byte)(udpChecksum >> 8);
        packet[u + 7] = (byte)udpChecksum;

        return packet;
    }

    /// <summary>
    /// Разбирает «сырой» IPv4-пакет, содержащий UDP-датаграмму.
    /// </summary>
    public static bool TryParseUdp(
        byte[] buffer, int length,
        out IPAddress sourceIp, out IPAddress destinationIp,
        out ushort sourcePort, out ushort destinationPort,
        out byte[] payload)
    {
        sourceIp = IPAddress.Any;
        destinationIp = IPAddress.Any;
        sourcePort = 0;
        destinationPort = 0;
        payload = Array.Empty<byte>();

        if (buffer == null || length < IpHeaderLength + UdpHeaderLength)
            return false;

        if ((buffer[0] >> 4) != 4)
            return false;

        var ipHeaderLength = (buffer[0] & 0x0F) * 4;
        if (ipHeaderLength < IpHeaderLength || length < ipHeaderLength + UdpHeaderLength)
            return false;

        if (buffer[9] != ProtoUdp)
            return false;

        var s = new byte[4];
        var d = new byte[4];
        Array.Copy(buffer, 12, s, 0, 4);
        Array.Copy(buffer, 16, d, 0, 4);
        sourceIp = new IPAddress(s);
        destinationIp = new IPAddress(d);

        var u = ipHeaderLength;
        sourcePort = (ushort)((buffer[u] << 8) | buffer[u + 1]);
        destinationPort = (ushort)((buffer[u + 2] << 8) | buffer[u + 3]);
        var udpLength = (buffer[u + 4] << 8) | buffer[u + 5];

        var available = length - (u + UdpHeaderLength);
        if (udpLength - UdpHeaderLength > available || udpLength < UdpHeaderLength)
            return false;

        payload = new byte[udpLength - UdpHeaderLength];
        Array.Copy(buffer, u + UdpHeaderLength, payload, 0, payload.Length);
        return true;
    }
}
