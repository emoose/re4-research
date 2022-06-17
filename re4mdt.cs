// RE4MDT v1 by emoose
// Kinda-hacky tool for converting MDT files to INI, and applying changed INI files back onto MDTs
// More info can be found in PrintUsage section
// Should support both multi-lang and single-lang MDT files
// (though this probably only works well with files from 1.1.0, which added two chinese langs without updating language count in file header...)
// All langs besides Japanese/Chinese should be supported for read/write, but batch-mode currently only supports english right now

using System.Text;

namespace RE4MDT
{
    class EncDec
    {
        // from zatarita:
        /* 0x0200 : insert *
0x0300 : newline
0x0400 : new page
0x0500 : something to do with chapters
0x0600 : font color *
0x0700 : menu option
0x0800 : wait for button press
0x0900 : pause *
0x0A00 : item stack quantity
0x0B00 : offset from left of screen*
0x0C00: offset from top of screen*
0x1000 : name of file being read
0x1100 : item *
0x1200 : character name * */
        enum MessageCode
        {
            /* 0args */ Unk0 = 0, // new msg?
            /* 0args */ EndOfLine = 1,
            /* 1args */ CommonPhrase = 2, // 
            /* 0args */ NewLine = 3,
            /* 0args */ NewPage = 4,
            /* 1args */ DisplaySpeed = 5,
            /* 1args */ SetColor = 6,
            /* 0args */ MenuOption = 7,
            /* 0args */ BtnCheck = 8,
            /* 1args */ Sleep = 9,
            /* 0args */ ItemStackQuantity = 0xA,
            /* 1args */ SetPositionX = 0xB,
            /* 1args */ SetPositionY = 0xC,
            /* 1args */ UnkD = 0xD,
            /* 0args */ UnkE = 0xE,
            /* 1args */ UnkF = 0xF,
            /* 0args */ NameOfFile = 0x10,
            /* 1args */ ItemId = 0x11,
            /* 1args */ CharaName = 0x12,
            /* 0args */ Unk13 = 0x13,
            Count = 0x14
        }
        static bool[] HasArgs = {
            false,
            false,
            true,
            false,
            false,
            true,
            true,
            false,
            false,
            true,
            false,
            true,
            true,
            true,
            false,
            true,
            false,
            true,
            true,
            false
        };
        static bool MsgIsCode(ushort msg) { return msg < 0x14; }

        public static string[] encoding = new string[0x10000];
        static bool inited = false;
        public static void Init()
        {
            if (inited)
                return;

            inited = true;

            for (int i = 0; i < encoding.Length; i++)
                if (i < (int)MessageCode.Count)
                    encoding[i] = $"[Code:{i}]";
                else
                    encoding[i] = $"[Unk:0x{i:X4}]";

            encoding[0x3] = "\\n";
            encoding[0x80] = " ";
            encoding[0x81] = "►"; // shaded arrow right
            encoding[0x82] = "▼"; // shaded arrow down
            encoding[0x83] = "0";
            encoding[0x84] = "1";
            encoding[0x85] = "2";
            encoding[0x86] = "3";
            encoding[0x87] = "4";
            encoding[0x88] = "5";
            encoding[0x89] = "6";
            encoding[0x8A] = "7";
            encoding[0x8B] = "8";
            encoding[0x8C] = "9";

            encoding[0x8D] = ":";
            encoding[0x8E] = "%";
            encoding[0x8F] = "&";
            encoding[0x90] = "+";
            encoding[0x91] = "-";
            encoding[0x92] = "/";
            encoding[0x93] = "=";
            encoding[0x94] = ",";
            encoding[0x95] = ".";
            // encoding[0x96] = "*"; // shaded superscript circle
            encoding[0x97] = "…"; // ellipsis
            encoding[0x98] = "(";
            encoding[0x99] = ")";
            encoding[0x9A] = "!";
            encoding[0x9B] = "?";
            encoding[0x9C] = "“"; // open quote
            encoding[0x9D] = "”"; // close quote
            encoding[0x9E] = "~";
            encoding[0x9F] = "★"; // star
            //encoding[0xA0] = "-"; // another dash? maybe em dash?
            encoding[0xA1] = "<";
            encoding[0xA2] = ">";
            encoding[0xA3] = "[";
            encoding[0xA4] = "]";
            encoding[0xA5] = "①"; // circled 1
            encoding[0xA6] = "②"; // circled 2

            /* 0xA7 - 0xDA */
            encoding[0xA7] = "A";
            encoding[0xA8] = "B";
            encoding[0xA9] = "C";
            encoding[0xAA] = "D";
            encoding[0xAB] = "E";
            encoding[0xAC] = "F";
            encoding[0xAD] = "G";
            encoding[0xAE] = "H";
            encoding[0xAF] = "I";
            encoding[0xB0] = "J";
            encoding[0xB1] = "K";
            encoding[0xB2] = "L";
            encoding[0xB3] = "M";
            encoding[0xB4] = "N";
            encoding[0xB5] = "O";
            encoding[0xB6] = "P";
            encoding[0xB7] = "Q";
            encoding[0xB8] = "R";
            encoding[0xB9] = "S";
            encoding[0xBA] = "T";
            encoding[0xBB] = "U";
            encoding[0xBC] = "V";
            encoding[0xBD] = "W";
            encoding[0xBE] = "X";
            encoding[0xBF] = "Y";
            encoding[0xC0] = "Z";
            encoding[0xC1] = "a";
            encoding[0xC2] = "b";
            encoding[0xC3] = "c";
            encoding[0xC4] = "d";
            encoding[0xC5] = "e";
            encoding[0xC6] = "f";
            encoding[0xC7] = "g";
            encoding[0xC8] = "h";
            encoding[0xC9] = "i";
            encoding[0xCA] = "j";
            encoding[0xCB] = "k";
            encoding[0xCC] = "l";
            encoding[0xCD] = "m";
            encoding[0xCE] = "n";
            encoding[0xCF] = "o";
            encoding[0xD0] = "p";
            encoding[0xD1] = "q";
            encoding[0xD2] = "r";
            encoding[0xD3] = "s";
            encoding[0xD4] = "t";
            encoding[0xD5] = "u";
            encoding[0xD6] = "v";
            encoding[0xD7] = "w";
            encoding[0xD8] = "x";
            encoding[0xD9] = "y";
            encoding[0xDA] = "z";

            /* 0xDB - 0xFF */
            encoding[0xDB] = "â";
            encoding[0xDC] = "ê";
            encoding[0xDD] = "î";
            encoding[0xDE] = "ô";
            encoding[0xDF] = "û";
            encoding[0xE0] = "Â";
            encoding[0xE1] = "Ê";
            encoding[0xE2] = "Î";
            encoding[0xE3] = "Ô";
            encoding[0xE4] = "Û";
            encoding[0xE5] = "à";
            encoding[0xE6] = "è";
            encoding[0xE7] = "ì";
            encoding[0xE8] = "ò";
            encoding[0xE9] = "ù";
            encoding[0xEA] = "À";
            encoding[0xEB] = "È";
            encoding[0xEC] = "Ì";
            encoding[0xED] = "Ò";
            encoding[0xEE] = "Ù";
            encoding[0xEF] = "á";
            encoding[0xF0] = "é";
            encoding[0xF1] = "í";
            encoding[0xF2] = "ó";
            encoding[0xF3] = "ú";
            encoding[0xF4] = "ý";
            encoding[0xF5] = "Á";
            encoding[0xF6] = "É";
            encoding[0xF7] = "Í";
            encoding[0xF8] = "Ó";
            encoding[0xF9] = "Ú";
            encoding[0xFA] = "Ý";
            encoding[0xFB] = "ä";
            encoding[0xFC] = "ë";
            encoding[0xFD] = "ï";
            encoding[0xFE] = "ö";
            encoding[0xFF] = "ü";

            encoding[0x101] = "Ä";
            encoding[0x102] = "Ë";
            encoding[0x103] = "Ï";
            encoding[0x104] = "Ö";
            encoding[0x105] = "Ü";
            encoding[0x106] = "Ÿ";
            encoding[0x107] = "ã";
            encoding[0x108] = "õ";
            encoding[0x109] = "Ã";
            encoding[0x10A] = "Õ";
            encoding[0x10B] = "ñ";
            encoding[0x10C] = "Ñ";
            encoding[0x10D] = "å";
            encoding[0x10E] = "Å";
            encoding[0x10F] = "ç";

            encoding[0x110] = "Ç";

            encoding[0x111] = "ø";
            encoding[0x112] = "Ø";
            encoding[0x113] = "ϸ"; // alt: Ϸ þ
            encoding[0x114] = "Ϸ"; // alt: Ϸ Þ
            encoding[0x115] = "š";
            encoding[0x116] = "Š";
            encoding[0x117] = "ß";
            encoding[0x118] = "Đ";
            encoding[0x119] = "ƒ";
            encoding[0x11A] = "μ";

            encoding[0x121] = "¡";
            encoding[0x122] = "¿";
            encoding[0x123] = "'";

            encoding[0x124] = "™";
            encoding[0x125] = ";";
            encoding[0x126] = "#";
            encoding[0x127] = "@";

            encoding[0x12D] = "\"";
            encoding[0x12F] = "®";
        }

        public static string Decode(BinaryReader reader, long endOffset)
        {
            string s = "";
            int j = 0;

            while (endOffset > reader.BaseStream.Position)
            {
                ushort ch = reader.ReadUInt16();

                string decoded = encoding[ch];
                //if (j < 2 && decoded == " ")
                //    decoded = "[Unk:0x80]";

                bool endOfLine = false;
                if (MsgIsCode(ch))
                {
                    if (ch == 0 && j == 0)
                    {
                        j++;
                        continue;
                    }

                    ushort param = 0;
                    if (HasArgs[ch])
                        param = reader.ReadUInt16();

                    switch ((MessageCode)ch)
                    {
                        case MessageCode.EndOfLine:
                            endOfLine = true;
                            break;
                        /*case MessageCode.CommonPhrase: // documented by mariokart64n
                            decoded = $"[CommonPhrase:{param}";
                            break;*/
                        case MessageCode.NewLine:
                            decoded = "\\n";
                            break;
                        /*case MessageCode.NewPage:
                            decoded = "[NewPage]";
                            break;
                        case MessageCode.DisplaySpeed:
                            decoded = $"[DisplaySpeed:{param}]";
                            break;
                        case MessageCode.SetColor:
                            decoded = $"[SetColor:{param}]";
                            break;
                        case MessageCode.MenuOption:
                            decoded = $"[MenuOption]";
                            break;
                        case MessageCode.BtnCheck:
                            decoded = "[BtnCheck]";
                            break;*/
                        case MessageCode.Sleep:
                            // check if this is sleeping based on something in SEQ
                            // aka Sleep(0xFFFF) && Code8 && Code4
                            bool isWaitSeq = false;
                            long pos = reader.BaseStream.Position;
                            if (param == 0xFFFF)
                            {
                                ushort next0 = reader.ReadUInt16();
                                isWaitSeq = false;
                                if ((MessageCode)next0 == MessageCode.BtnCheck)
                                {
                                    ushort next1 = reader.ReadUInt16();
                                    if ((MessageCode)next1 == MessageCode.NewPage)
                                    {
                                        isWaitSeq = true;
                                    }
                                }
                            }

                            if (isWaitSeq)
                            {
                                decoded = "[WaitForSeq]";
                                break;
                            }
                            else
                            {
                                decoded = $"[Sleep:{param}]";
                                reader.BaseStream.Position = pos;
                                break;
                            }
                        /*case MessageCode.ItemStackQuantity:
                            decoded = "[ItemStackQuantity]";
                            break;*/
                        case MessageCode.SetPositionX:
                            decoded = $"[SetPosX:{param}]";
                            break;
                        case MessageCode.SetPositionY:
                            decoded = $"[SetPosY:{param}]";
                            break;
                        /*case MessageCode.NameOfFile:
                            decoded = "[NameOfFile]";
                            break;
                        case MessageCode.ItemId:
                            decoded = $"[ItemId:{param}]";
                            break;
                        case MessageCode.CharaName:
                            decoded = $"[CharaName:{param}]";
                            break;*/
                        default:
                            decoded = $"[Code:0x{ch:X}";
                            if (HasArgs[ch])
                                decoded += $":0x{param:X}";
                            decoded += "]";
                            break;
                    }

                    if (endOfLine)
                        break;
                }

                s += decoded;
                j++;
            }

            return s;
        }

        static string SafeSubStr(string s, int offset, int count)
        {
            if (offset + count > s.Length)
                return "";
            return s.Substring(offset, count);
        }

        public static ushort[] Encode(string s)
        {
            var ret = new List<ushort>();
            ret.Add(0);

            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c == '[')
                {
                    if (SafeSubStr(s, i+1, 7).ToLower() == "setposx")
                    {
                        int idx = s.IndexOf(']', i + 8);
                        string pos = SafeSubStr(s, i + 9, idx - (i + 9));
                        ret.Add((ushort)MessageCode.SetPositionX);
                        ret.Add(pos.Contains("0x") ? Convert.ToUInt16(pos, 16) : Convert.ToUInt16(pos));
                        i = idx;
                        continue;
                    }
                    else if (SafeSubStr(s, i + 1, 7).ToLower() == "setposy")
                    {
                        int idx = s.IndexOf(']', i + 8);
                        string pos = SafeSubStr(s, i + 9, idx - (i + 9));
                        ret.Add((ushort)MessageCode.SetPositionY);
                        ret.Add(pos.Contains("0x") ? Convert.ToUInt16(pos, 16) : Convert.ToUInt16(pos));
                        i = idx;
                        continue;
                    }
                    else if (SafeSubStr(s, i + 1, 10).ToLower() == "waitforseq")
                    {
                        int idx = s.IndexOf(']', i + 11);
                        ret.Add((ushort)MessageCode.Sleep);
                        ret.Add(0xFFFF);
                        ret.Add((ushort)MessageCode.BtnCheck);
                        ret.Add((ushort)MessageCode.NewPage);
                        i = idx;
                        continue;
                    }
                    else if (SafeSubStr(s, i + 1, 5).ToLower() == "sleep")
                    {
                        int idx = s.IndexOf(']', i + 6);
                        string pos = SafeSubStr(s, i + 7, idx - (i + 7));
                        ret.Add((ushort)MessageCode.Sleep);
                        ret.Add(pos.Contains("0x") ? Convert.ToUInt16(pos, 16) : Convert.ToUInt16(pos));
                        i = idx;
                        continue;
                    }
                    else if (SafeSubStr(s, i + 1, 3).ToLower() == "unk")
                    {
                        int idx = s.IndexOf(']', i + 5);
                        string codepoint = SafeSubStr(s, i + 5, idx - (i + 5));
                        ret.Add(codepoint.Contains("0x") ? Convert.ToUInt16(codepoint, 16) : Convert.ToUInt16(codepoint));
                        i = idx;
                        continue;
                    }
                    else if (SafeSubStr(s, i+1, 4).ToLower() == "code")
                    {
                        int idx = s.IndexOf(']', i + 6);
                        string codepoint = SafeSubStr(s, i + 6, idx - (i + 6));
                        string param = "";
                        if (codepoint.Contains(":"))
                        {
                            int paramidx = codepoint.IndexOf(':');
                            param = codepoint.Substring(paramidx + 1);
                            codepoint = codepoint.Substring(0, paramidx);
                        }
                        ret.Add(codepoint.Contains("0x") ? Convert.ToUInt16(codepoint, 16) : Convert.ToUInt16(codepoint));
                        if (!string.IsNullOrEmpty(param))
                            ret.Add(param.Contains("0x") ? Convert.ToUInt16(param, 16) : Convert.ToUInt16(param));

                        i = idx;
                        continue;
                    }
                }

                if (c == '\\' && SafeSubStr(s, i, 2) == "\\n")
                {
                    ret.Add(3);
                    i++;
                    continue;
                }

                for (ushort j = 0; j < encoding.Length; j++)
                    if (encoding[j] == c.ToString())
                    {
                        ret.Add(j);
                        break;
                    }
            }

            // end of line
            ret.Add(1);
            //ret.Add(0x800);
            //ret.Add(0x100);

            return ret.ToArray();
        }
    }
    struct MdtHeader
    {
        /* 0x00 */ public uint Unk0; // maybe meant to be count of languages, in 1.1.0 they added two chinese langs without updating this though
        /* 0x04 */ public uint[] LanguageOffsets;

        public void Read(BinaryReader reader)
        {
            Unk0 = reader.ReadUInt32();

            LanguageOffsets = new uint[(int)Mdt.MesData_LanguageId.Count];
            for (int i = 0; i < (int)Mdt.MesData_LanguageId.Count; i++)
                LanguageOffsets[i] = reader.ReadUInt32();
        }

        public void Write(BinaryWriter writer)
        {
            writer.Write(Unk0);
            for (int i = 0; i < (int)Mdt.MesData_LanguageId.Count; i++)
                writer.Write(LanguageOffsets[i]);
        }
    }

    struct MdtLanguageHeader
    {
        /* 0x00 */ public uint Unk0; // per-language magic? checksum?
        /* 0x04 */ public int NumMessages;
        /* 0x08 */ public uint[] MessageOffsets;

        public void Read(BinaryReader reader)
        {
            Unk0 = reader.ReadUInt32();
            NumMessages = reader.ReadInt32();

            MessageOffsets = new uint[NumMessages];
            for (int i = 0; i < NumMessages; i++)
                MessageOffsets[i] = reader.ReadUInt32();
        }

        public void Write(BinaryWriter writer)
        {
            NumMessages = MessageOffsets.Length;
            writer.Write(Unk0);
            writer.Write(NumMessages);
            for (int i = 0; i < NumMessages; i++)
                writer.Write(MessageOffsets[i]);
        }
    }

    class MdtLanguage
    {
        public long LangPos;

        public MdtLanguageHeader Header;
        public List<string> Messages = new List<string>();
        public List<byte[]> MessageRaw = new List<byte[]>();

        public void Read(BinaryReader reader, long endOffset)
        {
            LangPos = reader.BaseStream.Position;

            Header = new MdtLanguageHeader();
            Header.Read(reader);

            Messages = new List<string>();
            for (int i = 0; i < Header.NumMessages; i++)
            {
                long msgEndOffset = endOffset;
                if (i + 1 < Header.NumMessages)
                    msgEndOffset = LangPos + Header.MessageOffsets[i+1];

                reader.BaseStream.Position = LangPos + Header.MessageOffsets[i];
                long size = msgEndOffset - reader.BaseStream.Position;
                MessageRaw.Add(reader.ReadBytes((int)size));

                reader.BaseStream.Position = LangPos + Header.MessageOffsets[i];
                string res = EncDec.Decode(reader, msgEndOffset);
                // var test = EncDec.Encode(res);
                Messages.Add(res);
            }
        }

        public void Write(BinaryWriter writer)
        {
            long pos = writer.BaseStream.Position;

            Header.NumMessages = Messages.Count;
            Header.MessageOffsets = new uint[Header.NumMessages];
            Header.Write(writer);

            for (int i = 0; i < Messages.Count; i++)
            {
                long messagePos = writer.BaseStream.Position;
                var encoded = EncDec.Encode(Messages[i]);
                var original = MessageRaw[i];

                byte[] encBytes = null;
                using (var stream = new MemoryStream())
                using (var writer2 = new BinaryWriter(stream))
                {
                    for (int j = 0; j < encoded.Length; j++)
                        writer2.Write(encoded[j]);
                    encBytes = stream.ToArray();
                }
                if (encBytes.Length != original.Length)
                {
                    //File.WriteAllBytes("raw.bin", original);
                    //File.WriteAllBytes("new.bin", encBytes);
                }
                for (int j = 0; j < encoded.Length; j++)
                    writer.Write(encoded[j]);
                Header.MessageOffsets[i] = (uint)(messagePos - pos);
            }
            long endPos = writer.BaseStream.Position;

            writer.BaseStream.Position = pos;
            Header.Write(writer);
            writer.BaseStream.Position = endPos;
        }
    }

    class Mdt
    {
        public enum MesData_LanguageId // seems to be different than pSys->language ?
        {
            Japanese = 0,
            English = 1,
            French = 2,
            German = 3,
            Italian = 4,
            Spanish = 5,
            TradChinese = 6,
            SimpChinese = 7,

            Count = 8
        }

        private long streamPos = 0;

        public MdtHeader Header;
        public List<MdtLanguage> Languages = new List<MdtLanguage>();

        public MdtLanguage GetLanguage(MesData_LanguageId language)
        {
            if (Languages.Count() > (int)language)
                return Languages[(int)language];
            return Languages[0];
        }

        public void Read(BinaryReader reader)
        {
            EncDec.Init();

            streamPos = reader.BaseStream.Position;

            Header = new MdtHeader();
            Header.Read(reader);
            if (Header.Unk0 != 6)
            {
                // All multi-lang MDTs seem to start with 6, this must be single lang
                reader.BaseStream.Position = streamPos;
                MdtLanguage language = new MdtLanguage();
                language.Read(reader, reader.BaseStream.Length);
                Languages.Add(language);
                return;
            }

            for (int i = 0; i < (int)MesData_LanguageId.Count; i++)
            {
                long endOffset = reader.BaseStream.Length;
                if (i + 1 < (int)MesData_LanguageId.Count)
                    endOffset = streamPos + Header.LanguageOffsets[i + 1];
                reader.BaseStream.Position = streamPos + Header.LanguageOffsets[i];
                MdtLanguage language = new MdtLanguage();
                language.Read(reader, endOffset);
                Languages.Add(language);
            }
        }

        public void Write(BinaryWriter writer, BinaryReader reader)
        {
            if (Languages.Count() < 2)
            {
                // single lang
                writer.BaseStream.SetLength(0);
                writer.BaseStream.Position = 0;
                Languages[0].Write(writer);
                return;
            }

            // copy unsupported langs as byte arrays, we can serialize the others
            List<Tuple<int, int>> langBlocks = new List<Tuple<int, int>>();
            List<byte[]> langData = new List<byte[]>();
            for (int i = 0; i < Languages.Count; i++)
            {
                int start = (int)Header.LanguageOffsets[i];
                int end = (int)reader.BaseStream.Length;
                if (i < 7)
                    end = (int)Header.LanguageOffsets[i + 1];
                int size = end - start;
                langBlocks.Add(new Tuple<int, int>(start, size));

                reader.BaseStream.Position = start;
                langData.Add(reader.ReadBytes(size));
            }

            writer.BaseStream.SetLength(0);
            writer.BaseStream.Position = 0;
            Header.Write(writer);

            // write out japanese...
            long pos = ((writer.BaseStream.Position + 0x3) / 4) * 4;
            Header.LanguageOffsets[0] = (uint)pos;
            writer.BaseStream.Position = pos;
            writer.Write(langData[0]);

            // write out supported langs
            for (int i = (int)MesData_LanguageId.English; i < (int)MesData_LanguageId.TradChinese; i++)
            {
                // write out english
                pos = ((writer.BaseStream.Position + 0x3) / 4) * 4;
                Header.LanguageOffsets[i] = (uint)pos;
                writer.BaseStream.Position = pos;
                Languages[i].Write(writer);

                // weird padding 1
                writer.Write(new byte[0x10]);

                // weird padding 2
                if (Languages[i].Messages.Count > 0)
                    writer.Write(new byte[8]);
            }

            // write out the rest
            for (int i = 6; i < Languages.Count; i++)
            {
                //pos = writer.BaseStream.Position;
                //if (langData[i].Length > 0)
                pos = ((writer.BaseStream.Position + 0x3) / 4) * 4;

                Header.LanguageOffsets[i] = (uint)pos;
                writer.BaseStream.Position = pos;

                //if (langData[i].Length > 0)
                writer.Write(langData[i]);
            }

            writer.BaseStream.Position = 0;
            Header.Write(writer);
            writer.Flush();
        }

        public void WriteWholeFile(BinaryWriter writer)
        {
            writer.BaseStream.SetLength(0);

            writer.BaseStream.Position = 0;
            Header.Write(writer);

            for (int i = 0; i < Languages.Count; i++)
            {
                // align to nearest 4
                long pos = writer.BaseStream.Position;
                pos = ((pos + 0x3) / 4) * 4;
                writer.BaseStream.SetLength(pos);
                writer.BaseStream.Position = pos;
                Header.LanguageOffsets[i] = (uint)pos;

                Languages[i].Write(writer);

                if (Languages[i].Messages.Count <= 0)
                {
                    byte[] weirdPad = new byte[0x8];
                    writer.Write(weirdPad);
                }

                byte[] langPad = new byte[0x10];
                writer.Write(langPad);
            }

            writer.BaseStream.Position = 0;
            Header.Write(writer);

            writer.Flush();
        }

        public void WriteOld(BinaryWriter writer)
        {
            long lastLangPos = 0;
            for (int i = 0; i < Languages.Count; i++)
                if (Languages[i].LangPos > lastLangPos)
                    lastLangPos = Languages[i].LangPos;

            if (Languages[1].LangPos == lastLangPos)
            {
                // English lang (the one we're overwriting) is already at end of file
                // Truncate file to that so we can save space...
                writer.BaseStream.SetLength(lastLangPos);
            }

            writer.BaseStream.Position = writer.BaseStream.Length;
            long lang1Pos = writer.BaseStream.Position;
            Languages[1].Write(writer);

            Header.LanguageOffsets[1] = (uint)lang1Pos;
            writer.BaseStream.Position = 0;
            Header.Write(writer);
            writer.Flush();
        }

        public string WriteINI(string baseName)
        {
            var s = new StringBuilder();

            int start = (int)MesData_LanguageId.English;
            int end = (int)MesData_LanguageId.TradChinese;
            if (Languages.Count < 2)
            {
                start = 0;
                end = 1;
            }
            for (int i = start; i < end; i++)
            {
                MesData_LanguageId langIdx = (MesData_LanguageId)i;
                if (Languages.Count < 2)
                    s.AppendLine($"[SingleLanguage]");
                else
                    s.AppendLine($"[{langIdx}]");

                var lang = Languages[i];
                for (int j = 0; j < lang.Messages.Count; j++)
                {
                    var msg = lang.Messages[j];
                    s.AppendLine($"{baseName}-{j} = {msg}");
                }
            }

            return s.ToString();
        }

        public void ReadINI(string iniData)
        {
            int langIdx = 0;
            foreach (var line in iniData.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries))
            {
                var lineLowered = line.ToLower();
                switch (lineLowered)
                {
                    case "[english]":
                        langIdx = (int)MesData_LanguageId.English;
                        continue;
                    case "[german]":
                        langIdx = (int)MesData_LanguageId.German;
                        continue;
                    case "[spanish]":
                        langIdx = (int)MesData_LanguageId.Spanish;
                        continue;
                    case "[italian]":
                        langIdx = (int)MesData_LanguageId.Italian;
                        continue;
                    case "[french]":
                        langIdx = (int)MesData_LanguageId.French;
                        continue;
                    case "[singlelanguage]":
                        langIdx = 0;
                        continue;
                }

                if (lineLowered == "[tradchinese]" ||
                    lineLowered == "[simpchinese]")
                    break;

                int startIdx = line.IndexOf('=');
                if (startIdx <= 0)
                    continue;

                string key = line.Substring(0, startIdx).Trim();
                string value = line.Substring(startIdx + 1);
                if (value.StartsWith(' '))
                    value = value.Substring(1);

                if (key.Contains("-"))
                    key = key.Substring(key.IndexOf('-') + 1);
                int index = int.Parse(key);

                //int langIdx = Languages.Count >= 2 ? (int)MesData_LanguageId.English : 0; // handle single-lang files

                while (index >= Languages[langIdx].Messages.Count)
                {
                    Languages[langIdx].Messages.Add("");
                }
                Languages[langIdx].Messages[index] = value;
            }
        }
    }

    class Program
    {
        static void PrintUsage()
        {
            Console.WriteLine("usage:");
            Console.WriteLine("  re4mdt.exe [-o] <path/to/mdt> [path/to/ini]");
            Console.WriteLine();
            Console.WriteLine("if INI isn't specified, the MDT will be converted to mdtPath.ini");
            Console.WriteLine("if INI is specified, the INI will be applied onto the MDT, with results written to mdtPath.new");
            Console.WriteLine("-o can be optionally specified to update the MDT in-place, overwriting the original data");
            Console.WriteLine();
            Console.WriteLine("batch mode:");
            Console.WriteLine("  re4mdt.exe -b [-o] <path/to/folder/of/mdts>");
            Console.WriteLine();
            Console.WriteLine("Will read a batch list of messages to replace from an input.ini file in the root of the given folder");
            Console.WriteLine("Updated contents will be written next to each updated MDT as a .new file");
            Console.WriteLine("-o can be optionally specified to update the MDT in-place, overwriting the original data");
        }

        static void BatchMode(string mdtFolder, bool overwrite)
        {
            Console.WriteLine("Batch mode!");
            if (overwrite)
                Console.WriteLine("  -o specified, overwriting MDTs in-place");
            else
                Console.WriteLine("  Writing to .new files next to MDTs");
            Console.WriteLine();

            var patchFile = Path.Combine(mdtFolder, "input.ini");
            Console.WriteLine("Batch folder:");
            Console.WriteLine($"  {mdtFolder}");
            Console.WriteLine("Batch file:");
            Console.WriteLine($"  {patchFile}");
            Console.WriteLine();

            if (!File.Exists(patchFile))
            {
                Console.WriteLine("Batch file not found! Exiting...");
                return;
            }

            var dict = new Dictionary<string, Dictionary<int, string>>(); // file, line #, replacement

            var patchLines = File.ReadAllLines(patchFile);
            foreach (var line in patchLines)
            {
                if (line.ToLower() == "[english]")
                    continue;

                if (line.StartsWith("#"))
                    continue;

                int startIdx = line.IndexOf('=');
                if (startIdx <= 0)
                    continue;

                string key = line.Substring(0, startIdx).Trim();
                string value = line.Substring(startIdx + 1);
                if (value.StartsWith(' '))
                    value = value.Substring(1);

                int idx = key.IndexOf('-');
                if (idx < 0)
                    idx = key.IndexOf('_');
                var keyFile = key.Substring(0, idx).Trim();
                var keyIdx = key.Substring(idx+1).Trim();

                int index = int.Parse(keyIdx);

                if (!dict.ContainsKey(keyFile))
                    dict.Add(keyFile, new Dictionary<int, string>());

                dict[keyFile].Add(int.Parse(keyIdx), value);
            }

            int updated = 0;
            var mdts = Directory.EnumerateFiles(mdtFolder, "*.mdt", SearchOption.AllDirectories);
            foreach (var kvp in dict)
            {
                string path = "";
                foreach (var mdtPath in mdts)
                    if (mdtPath.Contains(kvp.Key + ".mdt"))
                    {
                        path = mdtPath;
                        break;
                    }

                if (string.IsNullOrEmpty(path))
                {
                    Console.WriteLine("!!! Failed to find " + kvp.Key);
                    continue;
                }
                Console.WriteLine($"[{updated+1}] {kvp.Key}...");

                var outPath = path + ".new";

                using (var reader = new BinaryReader(File.OpenRead(path)))
                {
                    var mdt = new Mdt();
                    mdt.Read(reader);

                    var engLang = mdt.GetLanguage(Mdt.MesData_LanguageId.English);
                    foreach (var mesKvp in kvp.Value)
                    {
                        var val = mesKvp.Value;
                        if (!val.EndsWith(" "))
                            val += " ";
                        engLang.Messages[mesKvp.Key] = val;
                    }

                    File.Copy(path, outPath, true);

                    using (var writer = new BinaryWriter(File.OpenWrite(outPath)))
                        mdt.Write(writer, reader);

                    updated++;
                }
                if (overwrite)
                {
                    File.Move(outPath, path, true);
                }
            }

            Console.WriteLine($"Batch mode complete, wrote {updated} MDT files!");
        }

        static void Main(string[] args)
        {
            Console.WriteLine("RE4MDT v1 - by emoose");

            string mdtFile = string.Empty;
            string iniFile = string.Empty;
            string outFile = string.Empty;
            bool batchMode = false;
            bool overwrite = false;
            foreach (var arg in args)
            {
                if (arg.ToLower() == "-b" || arg.ToLower() == "/b")
                    batchMode = true;
                else if (arg.ToLower() == "-o" || arg.ToLower() == "/o")
                    overwrite = true;
                else if (string.IsNullOrEmpty(mdtFile))
                    mdtFile = arg;
                else if (string.IsNullOrEmpty(iniFile))
                    iniFile = arg;
                else if (string.IsNullOrEmpty(outFile))
                    outFile = arg;
            }

            if (string.IsNullOrEmpty(mdtFile))
            {
                PrintUsage();
                return;
            }

            if (batchMode)
            {
                BatchMode(mdtFile, overwrite);
                return;
            }

            Console.WriteLine("Single file mode");
            if (overwrite)
                Console.WriteLine("  -o specified, overwriting MDT in-place");
            else
                Console.WriteLine("  Writing to .ini/.new file next to MDT");
            Console.WriteLine();


            Console.WriteLine("Input MDT file:");
            Console.WriteLine($"  {mdtFile}");
            if (!string.IsNullOrEmpty(iniFile))
            {
                Console.WriteLine("Input INI file:");
                Console.WriteLine($"  {iniFile}");

                if (string.IsNullOrEmpty(outFile) || overwrite)
                    outFile = mdtFile + ".new";

                if (!overwrite)
                {
                    Console.WriteLine("Output MDT file:");
                    Console.WriteLine($"  " + outFile);
                }
            }
            else
            {
                Console.WriteLine("Output INI file:");
                Console.WriteLine($"  " + mdtFile + ".ini");
                outFile = mdtFile + ".ini";
            }

            using (var reader = new BinaryReader(File.OpenRead(mdtFile)))
            {
                Mdt mdt = new Mdt();
                mdt.Read(reader);

                if (string.IsNullOrEmpty(iniFile))
                {
                    // not applying INI, write out new one
                    if (File.Exists(outFile))
                        File.Delete(outFile);
                    File.WriteAllText(outFile, mdt.WriteINI(Path.GetFileNameWithoutExtension(mdtFile)));
                    Console.WriteLine("INI written to");
                    Console.WriteLine($"  {outFile}");
                    return;
                }

                // INI file specified, apply it on top of input MDT

                File.Copy(mdtFile, outFile, true);
                mdt.ReadINI(File.ReadAllText(iniFile));
                using (var writer = new BinaryWriter(File.OpenWrite(outFile)))
                    mdt.Write(writer, reader);
            }
            if (overwrite)
            {
                File.Move(outFile, mdtFile, true);
                outFile = mdtFile;
            }
            Console.WriteLine("MDT written to");
            Console.WriteLine($"  {outFile}");
        }
    }
}
