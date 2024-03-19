using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ACSigGen {
    public class Signature {

        public string Pattern { get; }

        internal static Signature? FindFromAddress(uint addr, BinaryReader clientBin) {
            var pattern = FindUniqueSignaturePattern(addr, clientBin);
            return !string.IsNullOrWhiteSpace(pattern) ? new Signature(pattern) : null;
        }

        private static string? FindUniqueSignaturePattern(uint addr, BinaryReader clientBin) {
            // TODO: this should also try and build a signature based on xrefs?
            clientBin.BaseStream.Seek(addr, SeekOrigin.Begin);
            
            // TODO: need to find shortest *unique* signature..
            var buffer = clientBin.ReadBytes(32);
            var sigStr = new StringBuilder();

            for(var i = 0; i < buffer.Length; i++) {
                bool foundReturn = false;
                switch (buffer[i]) {
                    case 0x8b: // method call
                        sigStr.Append($"{buffer[i]:X2} ?? ?? ?? ?? ");
                        i += 4;
                        break;
                    case 0xC3: // return
                        sigStr.Append($"{buffer[i]:X2} ");
                        foundReturn = true;
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

        public Signature(string pattern) {
            Pattern = pattern;
        }
    }
}
