
using PeNet;
using Reloaded.Memory.Sigscan;
using Reloaded.Memory.Sigscan.Definitions;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;

namespace ACSigGen {
    internal class Program {
        static void Main(string[] args) {
            try {
                var sw = new Stopwatch();
                sw.Start();

                using var oldClientStream = File.OpenRead(Path.Combine("data", "old", "acclient.exe"));
                using var newClientStream = File.OpenRead(Path.Combine("data", "new", "acclient.exe"));

                using var oldClientReader = new BinaryReader(oldClientStream);
                using var newClientReader = new BinaryReader(newClientStream);

                var peHeaderOld = LoadPE(Path.Combine("data", "old", "acclient.exe"));
                var peHeaderNew = LoadPE(Path.Combine("data", "new", "acclient.exe"));

                var lstOld = LoadLst(Path.Combine("data", "old", "acclient.exe.lst"));
                //var lstNew = LoadLst(Path.Combine("data", "new", "acclient.exe.lst"));

                Console.WriteLine($"Generating signatures from old client:");
                var signatures = GenerateSignatures(lstOld, peHeaderOld, oldClientReader);

                sw.Stop();

                Console.WriteLine($"Took {((double)sw.ElapsedTicks / Stopwatch.Frequency) * 1000.0:N2} ms to generate {signatures.Count} signatures");

                Console.WriteLine();
                Console.WriteLine($"Scanning for signatures in new client:");

                sw.Restart();

                var newClientTextSection = peHeaderNew.ImageSectionHeaders?.FirstOrDefault(s => s.Name == ".text");
                if (newClientTextSection is null) {
                    throw new Exception($"No .text section in new client PE headers");
                }

                newClientReader.BaseStream.Position = (long)newClientTextSection.VirtualAddress;
                var newClientBytes = newClientReader.ReadBytes((int)newClientTextSection.SizeOfRawData);
                var scanner = new Scanner(newClientBytes);

                var found = 0;
                foreach (var signature in signatures) {
                    Console.WriteLine($"Looking for: {signature.Name}");
                    Console.WriteLine($"\tPattern: {signature.Pattern}");
                    var res = scanner.FindPattern(signature.Pattern);

                    if (res.Found) {
                        found++;
                        var newOffset = res.Offset + (int)newClientTextSection.ImageBaseAddress + (int)newClientTextSection.VirtualAddress;
                        Console.WriteLine($"\tFound signature @ new offset 0x{newOffset:X8}");
                    }
                    else {
                        Console.WriteLine($"\t!!! Unable to find new signature offset");
                    }
                }
                sw.Stop();
                Console.WriteLine($"Took {((double)sw.ElapsedTicks / Stopwatch.Frequency) * 1000.0:N2} ms to find {found}/{signatures.Count} signatures");
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); Console.WriteLine(ex.ToString()); }
        }

        private static List<Signature> GenerateSignatures(string[] lst, PeFile oldClientPeHeader, BinaryReader oldClientBin) {
            var oldClientTextSection = oldClientPeHeader.ImageSectionHeaders?.FirstOrDefault(s => s.Name == ".text");

            if (oldClientTextSection is null) {
                throw new Exception($"No .text section in old client PE headers");
            }

            oldClientBin.BaseStream.Position = (long)0;
            var oldClientBytes = oldClientBin.ReadBytes((int)oldClientBin.BaseStream.Length);

            SharpDisasm.ArchitectureMode mode = SharpDisasm.ArchitectureMode.x86_32;
            SharpDisasm.Disassembler.Translator.IncludeAddress = true;
            SharpDisasm.Disassembler.Translator.IncludeBinary = true;
            
            var disasm = new SharpDisasm.Disassembler(oldClientBytes, mode, 0, true);

            var subs = new List<Signature>();
            var i = 0;
            foreach (var line in lst) {
                if (line.StartsWith(".text:") && line.Contains("S U B R O U T I N E")) {
                    var x = 1;
                    while (lst[i + x].Length < 15) {
                        //Console.WriteLine($"LINE < 15: {lst[i + x]}");
                        x++;
                    }

                    var subLine = lst[i + x];

                    if (subLine.Contains("ECM_Physics")) Console.WriteLine(subLine);

                    // skip unnamed subs
                    if (subLine.Length > 19 && subLine.Substring(15, 4) == "sub_") continue;

                    if (uint.TryParse(subLine.Substring(6, 8), NumberStyles.HexNumber, CultureInfo.CurrentCulture, out var addr)) {
                        var name = $"Sub@{addr:X8}: {subLine.Split(';').Last().Trim()}";

                        // limited testing...
                        if (subLine.Contains(" ACCObjectMaint:")) {
                            var signature = Signature.FindFromAddress(disasm, name, addr - (uint)oldClientTextSection.ImageBaseAddress, oldClientBin);
                            Console.WriteLine(name);
                            Console.WriteLine($"\tSignature: {signature?.Pattern ?? "Unable to find signature..."}");

                            if (signature is not null) {
                                subs.Add(signature);
                            }
                        }
                    }
                    else {
                        throw new Exception($"Could not parse subroutine address... @ line {i}");
                    }
                }
                i++;
            }

            return subs;
        }

        private static byte[] HexStringToByteArray(string hex) {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private static string[] LoadLst(string lstPath) {
            return File.ReadAllLines(lstPath);
        }

        private static PeFile LoadPE(string pePath) {
            Console.WriteLine($"Loading PE: {pePath}");
            var peHeader = new PeFile(pePath);
            
            /*
            if (peHeader.ImageSectionHeaders is not null) {
                foreach (var ef in peHeader.ImageSectionHeaders) {
                    Console.WriteLine($"\t Section {ef.Name.PadRight(8)} VAddress: 0x{ef.VirtualAddress:X8}");
                }
            }
            else {
                Console.WriteLine($"\tNo section headers...?");
            }
            */

            return peHeader;
        }
    }
}
