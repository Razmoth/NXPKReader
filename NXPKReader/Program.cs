using K4os.Compression.LZ4;
using NXPKReader;
using System.IO.Compression;

if (args.Length != 2)
{
    Console.WriteLine("NXPXReader <folder> <key>");
    return;
}

if (!Directory.Exists(args[0]))
{
    Console.WriteLine("Folder does not exist !!");
    return;
}

var files = Directory.GetFiles(args[0], "*.npk", SearchOption.AllDirectories);

if (!byte.TryParse(args[1], out var key))
{
    Console.WriteLine("Key must be byte only !!");
    return;
}

byte[] KEY = Enumerable.Range(0, 0x100).Select(x => (byte)(x - key)).ToArray();

foreach(var file in files)
{
    Decrypt(file);
}

void Decrypt(string file)
{
    using var fs = File.OpenRead(file);
    using var reader = new BinaryReader(fs);
    var signature = reader.ReadStringToNull(4);
    if (signature != "NXPK")
        throw new Exception("Invalid signautre !!");

    var fileSize = (int)reader.BaseStream.Length;

    var count = reader.ReadInt32();
    var ver1 = reader.ReadInt32();
    var ver2 = reader.ReadInt32();
    var ver3 = reader.ReadInt32();
    var offset = reader.ReadInt32();

    var mode = 0;
    if (ver1 > 1 && ver2 > 1)
        mode = 1;

    var infoSize = 0x1C;
    if (mode != 0)
        infoSize = 0x28;

    if (offset > fileSize)
        offset = fileSize - (count * infoSize);

    reader.BaseStream.Position = offset;
    for (int i = 0; i < count; i++)
    {
        var entry = new Entry()
        {
            NameCRC = reader.ReadInt32(),
            Offset = reader.ReadInt32(),
            ZSize = reader.ReadInt32(),
            Size = reader.ReadInt32(),
            ZCRC = reader.ReadInt32(),
            CRC = reader.ReadInt32(),
        };

        if (mode != 0)
        {
            reader.ReadInt32();
            reader.ReadInt32();
            entry.Flags = reader.ReadInt32();
            reader.ReadInt32();
        }
        else
        {
            entry.Flags = reader.ReadInt32();
        }

        var pos = reader.BaseStream.Position;
        var zflags = entry.Flags & 0xFFFF;
        var flags = entry.Flags >> 16;
        if (zflags == 2)
            entry.CompresstionType = CompresstionType.LZ4;
        else
            entry.CompresstionType = CompresstionType.ZLib;

        reader.BaseStream.Position = entry.Offset;
        var bytes = reader.ReadBytes(entry.ZSize);
        if (flags == 1)
        {
            var tmp = 0x80;
            if (tmp > entry.ZSize)
                tmp = entry.ZSize;
            for (int j = 0; j < tmp; j++)
            {
                bytes[j] ^= KEY[j % KEY.Length];
            }
        }
        else if (flags == 3)
        {
            var b = (byte)(entry.CRC ^ entry.Size);

            uint start = 0;
            uint size = (uint)entry.ZSize;
            if (size > 0x80)
            {
                start = (uint)(((uint)entry.CRC >> 1) % (entry.ZSize - 0x80));
                size = 2 * (uint)entry.Size % 0x60 + 0x20;
            }

            var key = Enumerable.Range(0, 0x100).Select(x => (byte)(x + b)).ToArray();
            for (int j = 0; j < size; j++)
            {
                bytes[start + j] ^= key[j % key.Length];
            }
        }
        var outBytes = new byte[entry.Size];
        if (entry.Size == entry.ZSize)
        {
            bytes.CopyTo(outBytes, 0);
        }
        else
        {
            switch (entry.CompresstionType)
            {
                case CompresstionType.LZ4:
                    var readNum = LZ4Codec.Decode(bytes, outBytes);
                    if (readNum == -1)
                        throw new Exception("Invalid Decompression !!");
                    break;
                case CompresstionType.ZLib:
                    var inputMS = new MemoryStream(bytes);
                    var stream = new ZLibStream(inputMS, CompressionMode.Decompress);
                    var outMS = new MemoryStream();
                    stream.CopyTo(outMS);
                    outMS.ToArray().CopyTo(outBytes, 0);
                    break;
            }
        }
        var fileName = $"{(uint)entry.NameCRC:X8}.dat";
        var folderName = Path.GetFileNameWithoutExtension(file);
        Directory.CreateDirectory($"output/{folderName}");
        Console.WriteLine($"Writing {fileName}");
        File.WriteAllBytes($"output/{folderName}/{fileName}", outBytes);
        reader.BaseStream.Position = pos;
    }
}


public enum CompresstionType
{
    LZ4,
    ZLib
}

public record Entry
{
    public int NameCRC;
    public int Offset;
    public int ZSize;
    public int Size;
    public int ZCRC;
    public int CRC;
    public int Flags;
    public CompresstionType CompresstionType;
}