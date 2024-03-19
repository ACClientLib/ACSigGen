
using PeNet;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;

namespace ACSigGen {
    internal class Program {
        static void Main(string[] args) {
            var sw = new Stopwatch();
            sw.Start();

            using var oldClientStream = File.OpenRead(Path.Combine("data", "old", "acclient.exe"));
            using var newClientStream = File.OpenRead(Path.Combine("data", "new", "acclient.exe"));

            using var oldClientReader = new BinaryReader(oldClientStream);
            using var newClientReader = new BinaryReader(newClientStream);

            var peHeaderOld = LoadPE(Path.Combine("data", "old", "acclient.exe"));
            var peHeaderNew = LoadPE(Path.Combine("data", "new", "acclient.exe"));

            var lstOld = LoadLst(Path.Combine("data", "old", "acclient.exe.lst"));
            var lstNew = LoadLst(Path.Combine("data", "new", "acclient.exe.lst"));

            var newSubs = GenerateSignatures(lstOld, peHeaderOld, oldClientReader);

            Console.WriteLine($"Found {newSubs.Count} subroutines...");

            sw.Stop();

            Console.WriteLine($"Took {((double)sw.ElapsedTicks / Stopwatch.Frequency) * 1000.0:N2} ms to generate signatures");
        }

        private static List<Signature> GenerateSignatures(string[] lst, PeFile peHeader, BinaryReader clientBin) {
            var textSection = peHeader.ImageSectionHeaders?.FirstOrDefault(s => s.Name == ".text");

            if (textSection is null) {
                throw new Exception($"No .text section in PE headers");
            }

            var subs = new List<Signature>();
            var i = 0;
            foreach (var line in lst) {
                if (line.Length > 35 && line.StartsWith(".text:") && line.Contains("S U B R O U T I N E")) {
                    var subLine = lst[i + 3];
                    if (uint.TryParse(subLine.Substring(6, 8), NumberStyles.HexNumber, CultureInfo.CurrentCulture, out var addr)) {
                        // hardcoded sub offset in old client, just for testing...
                        // .text:0041BE40 ; unsigned int __cdecl MasterDBMap::DivineType(const PStringBase<char> *_filename)

                        if (addr == 0x0041BE40) {
                            var signature = Signature.FindFromAddress(addr - (uint)textSection.ImageBaseAddress, clientBin);
                            Console.WriteLine($"Sub@{addr - textSection.ImageBaseAddress:X8}: {subLine.Split(';').Last().Trim()}");
                            Console.WriteLine($"\t Signature: {signature?.Pattern ?? "Unable to find signature..."}");

                            Console.WriteLine();
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

        private static string[] LoadLst(string lstPath) {
            return File.ReadAllLines(lstPath);
        }

        private static PeFile LoadPE(string pePath) {
            Console.WriteLine($"Loading PE: {pePath}");
            var peHeader = new PeFile(pePath);

            if (peHeader.ImageSectionHeaders is not null) {
                foreach (var ef in peHeader.ImageSectionHeaders) {
                    Console.WriteLine($"\t Section {ef.Name} \t VAddr: 0x{ef.VirtualAddress:X8}");

                }
            }
            else {
                Console.WriteLine($"\tNo section headers...?");
            }

            return peHeader;
        }
    }
}
