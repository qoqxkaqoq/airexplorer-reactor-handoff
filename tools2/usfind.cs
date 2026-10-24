using System;
using System.Text;
using dnlib.DotNet;

// usfind <exe> <keyword> — 在 #US 流中找包含关键词的字符串及其 US offset
class UsFind {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var kw = a[1].ToLowerInvariant();
        var us = mod.USStream;
        // 遍历 US 流: offset 1 起, [compressed len][flags][utf16]
        byte[] data = us.CreateReader().ToArray();
        int off = 1;
        while (off < data.Length) {
            int start = off;
            // CompressedUInt32 长度
            uint len;
            byte b0 = data[off];
            if ((b0 & 0x80) == 0) { len = b0; off += 1; }
            else if ((b0 & 0xC0) == 0x80) { len = (uint)(((b0 & 0x3F) << 8) | data[off + 1]); off += 2; }
            else { len = (uint)(((b0 & 0x1F) << 24) | (data[off+1] << 16) | (data[off+2] << 8) | data[off+3]); off += 4; }
            if (len == 0) { continue; }
            int strStart = off + 1; // 跳过 flags 字节
            int strLen = (int)len - 1;
            if (strStart + strLen > data.Length) break;
            string s = Encoding.Unicode.GetString(data, strStart, strLen);
            if (s.Length > 0 && s.ToLowerInvariant().Contains(kw))
                Console.WriteLine("US=0x" + start.ToString("X") + " (" + start + ")  " + (s.Length > 120 ? s.Substring(0, 120) + "..." : s));
            off = strStart + strLen;
        }
    }
}
