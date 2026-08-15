using System.Net;

namespace Proxify.Common;

/// <summary>
/// Расчёт контрольных сумм IPv4 и UDP (RFC 1071, дополнение до единицы).
/// </summary>
public static class Checksum
{
    public static ushort Ip(ReadOnlySpan<byte> header)
    {
        uint sum = 0;
        for (int i = 0; i + 1 < header.Length; i += 2)
            sum += (uint)((header[i] << 8) | header[i + 1]);

        sum = Fold(sum);
        return (ushort)(~sum & 0xFFFF);
    }

    public static ushort Udp(IPAddress sourceIp, IPAddress destinationIp, ushort udpLength, ReadOnlySpan<byte> udp)
    {
        var s = sourceIp.GetAddressBytes();
        var d = destinationIp.GetAddressBytes();

        uint sum = 0;
        sum += (uint)((s[0] << 8) | s[1]);
        sum += (uint)((s[2] << 8) | s[3]);
        sum += (uint)((d[0] << 8) | d[1]);
        sum += (uint)((d[2] << 8) | d[3]);
        sum += Packets.ProtoUdp;
        sum += udpLength;

        int i = 0;
        for (; i + 1 < udp.Length; i += 2)
            sum += (uint)((udp[i] << 8) | udp[i + 1]);

        if ((udp.Length & 1) != 0)
            sum += (uint)(udp[^1] << 8);

        sum = Fold(sum);
        return (ushort)(~sum & 0xFFFF);
    }

    private static uint Fold(uint sum)
    {
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return sum;
    }
}
