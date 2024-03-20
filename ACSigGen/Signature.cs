using Reloaded.Memory.Sigscan;
using SharpDisasm;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ACSigGen {
    public class Signature {
        private Disassembler disasm;

        public string Name { get; }
        public string Pattern { get; }

        internal static Signature? FindFromAddress(SharpDisasm.Disassembler disasm, string name, uint addr, BinaryReader clientBin) {
            var pattern = FindUniqueSignaturePattern(addr, clientBin);
            return !string.IsNullOrWhiteSpace(pattern) ? new Signature(disasm, name, pattern) : null;
        }

        private static string? FindUniqueSignaturePattern(uint addr, BinaryReader clientBin) {
            // TODO: this should also try and build a signature based on xrefs?
            clientBin.BaseStream.Seek(addr, SeekOrigin.Begin);
            
            // TODO: need to find shortest *unique* signature..
            var buffer = clientBin.ReadBytes(64);
            var sigStr = new StringBuilder();

            var disasm = new SharpDisasm.Disassembler(buffer, ArchitectureMode.x86_32, 0, true);

            var instructions = disasm.Disassemble();
            foreach (var instruction in instructions) {
                Console.WriteLine(instruction);
            }

            var callCount = 0;

            for(var i = 0; i < buffer.Length; i++) {
                bool foundReturn = false;
                switch (buffer[i]) {
                    case 0xA1:
                    case 0x8b: // method call
                        callCount++;
                        sigStr.Append($"{buffer[i]:X2} ?? ?? ?? ?? ");
                        i += 4;
                        break;
                    case 0xC3: // return
                        callCount--;
                        sigStr.Append($"{buffer[i]:X2} ");
                        if (callCount == 0) {
                            foundReturn = true;
                        }
                        break;
                    case 0x8A:
                    case 0xE8:
                    case 0xB8:
                        sigStr.Append($"{buffer[i]:X2} ?? ?? ?? ?? ");
                        i += 4;
                        break;
                    default:
                        sigStr.Append($"{buffer[i]:X2} ");
                        break;
                }

                if (foundReturn) {
                    break;
                }
            }

            return sigStr.ToString().TrimEnd();
        }

        public Signature(string name, string pattern) {
            Name = name;
            Pattern = pattern;
        }

        public Signature(Disassembler disasm, string name, string pattern) {
            this.disasm = disasm;
            Name = name;
            Pattern = pattern;
        }
    }
}
