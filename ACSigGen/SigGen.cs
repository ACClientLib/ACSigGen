using System;
using System.Collections.Generic;
using SharpDisasm;
using SharpDisasm.Udis86;
/*
namespace ACSigGen {
    public enum PatternType {
        PT_INVALID,
        PT_DIRECT,
        PT_REFERENCE,
        PT_FUNCTION
    }

    public enum SigSelect {
        OPT_LENGTH,
        OPT_OPCODES
    }

    public enum SigType {
        SIG_CODE,
        SIG_OLLY,
        SIG_DEFAULT
    }

    public class SigCreateStruct {
        public List<string> sig;
        public uint dwOrigStartAddress; // ea at cursor when started
        public uint dwStartAddress;
        public uint dwCurrentAddress;
        public bool bUnique;
        public int iOpCount;
        public PatternType eType;

        public static readonly uint BADADDR = 0xBAD00BAD;

        public SigCreateStruct() {
            sig = new List<string>();
            dwOrigStartAddress = BADADDR;
            dwStartAddress = BADADDR;
            dwCurrentAddress = BADADDR;
            bUnique = false;
            iOpCount = 0;
            eType = PatternType.PT_INVALID;
        }
    }

    public class SigMaker {
        private const int UA_MAXOP = 8;
        private byte[] _bytes;
        public List<SigCreateStruct> Sigs;

        public SigMaker(byte[] bytes) {
            _bytes = bytes;
            Sigs = new List<SigCreateStruct>();
        }

        private void _reset() {
            Sigs.Clear();
        }

        private void _addBytesToSig(int sigIndex, uint ea, int size) {
            for (int i = 0; i < size; i++) {
                byte b = _bytes[ea + i];
                Sigs[sigIndex].sig.Add(b.ToString("X2"));
            }
        }

        private void _addWildcards(int sigIndex, int count) {
            for (int i = 0; i < count; i++) {
                Sigs[sigIndex].sig.Add("?");
            }
        }

        private (int, int) _getCurrentOpcodeSize(Instruction cmd) {
            int count = 0;
            for (int i = 0; i < UA_MAXOP; i++) {
                count = i;
                if (cmd.Operands[i].Type == ud_type.UD_NONE) {
                    return (0, count);
                }
                if (cmd.Operands[i].Offset != 0) {
                    return (cmd.Operands[i].Offset, count);
                }
            }
            return (0, count);
        }

        private bool _matchOperands(uint ea) {
            if (idaapi.get_first_dref_from(ea) != SigCreateStruct.BADADDR) {
                return false;
            }
            else if (!__plugin.Settings.bOnlyReliable) {
                if (idaapi.get_first_fcref_from(ea) != SigCreateStruct.BADADDR) {
                    return false;
                }
            }
            else if (idaapi.get_first_cref_from(ea) != SigCreateStruct.BADADDR) {
                return false;
            }
            return true;
        }

        private void _addInsToSig(Instruction cmd, int sigIndex) {
            var (size, count) = _getCurrentOpcodeSize(cmd);
            if (size == 0) {
                _addBytesToSig(sigIndex, cmd.ea, cmd.size);
                return;
            }
            else {
                _addBytesToSig(sigIndex, cmd.ea, size);
            }
            if (_matchOperands(cmd.ea)) {
                _addBytesToSig(sigIndex, cmd.ea + (uint)size, cmd.size - size);
            }
            else {
                _addWildcards(sigIndex, cmd.size - size);
            }
        }

        private bool _addToSig(int sigIndex) {
            Instruction cmd = new Instruction();
            cmd.size = 0;
            SigCreateStruct sig = Sigs[sigIndex];
            if (!idaapi.can_decode(sig.dwCurrentAddress)) {
                return false;
            }
            int count = idaapi.decode_insn(cmd, sig.dwCurrentAddress);
            if (count == 0 || cmd.size == 0) {
                return false;
            }
            if (cmd.size < 5) {
                _addBytesToSig(sigIndex, sig.dwCurrentAddress, cmd.size);
            }
            else {
                _addInsToSig(cmd, sigIndex);
            }
            sig.dwCurrentAddress += (uint)cmd.size;
            sig.iOpCount++;
            Sigs[sigIndex] = sig;
            return true;
        }

        private bool _haveUniqueSig() {
            foreach (var sig in Sigs) {
                if (sig.bUnique) {
                    return true;
                }
            }
            return false;
        }

        private bool _addRefs(uint startea) {
            Console.WriteLine("Adding references");
            if (idaapi.get_func_num(startea) != -1) {
                SigCreateStruct sig = new SigCreateStruct();
                sig.dwStartAddress = startea;
                sig.dwCurrentAddress = startea;
                sig.eType = PatternType.PT_DIRECT;
                Sigs.Add(sig);
                Console.WriteLine($"Added direct reference 0x{startea:X}");
            }
            uint eaCurrent = idaapi.get_first_cref_to(startea);
            while (eaCurrent != SigCreateStruct.BADADDR) {
                if (eaCurrent != startea) {
                    SigCreateStruct sig = new SigCreateStruct();
                    sig.dwStartAddress = eaCurrent;
                    sig.dwCurrentAddress = eaCurrent;
                    sig.eType = PatternType.PT_REFERENCE;
                    Sigs.Add(sig);
                    Console.WriteLine($"Added reference 0x{eaCurrent:X}");
                }
                //if (__plugin.Settings.maxRefs > 0 && Sigs.Count >= __plugin.Settings.maxRefs) {
                //    break;
                //}
                eaCurrent = idaapi.get_next_cref_to(startea, eaCurrent);
            }
            if (Sigs.Count < 5) {
                Console.WriteLine($"Not enough references were found ({Sigs.Count} so far), trying the function.");
                var func = idaapi.get_func(startea);
                if (func == null || func.start_ea == SigCreateStruct.BADADDR) {
                    Console.WriteLine("Selected address not in a valid function.");
                    return false;
                }
                if (func.start_ea != startea) {
                    eaCurrent = idaapi.get_first_cref_to(func.start_ea);
                    while (eaCurrent != SigCreateStruct.BADADDR) {
                        if (eaCurrent != startea) {
                            SigCreateStruct sig = new SigCreateStruct();
                            sig.dwStartAddress = func.start_ea;
                            sig.dwCurrentAddress = eaCurrent;
                            sig.eType = PatternType.PT_FUNCTION;
                            Sigs.Add(sig);
                            Console.WriteLine($"Added function 0x{eaCurrent:X}");
                        }
                        //if (__plugin.Settings.maxRefs > 0 && Sigs.Count >= __plugin.Settings.maxRefs) {
                        //    break;
                        //}
                        eaCurrent = idaapi.get_next_cref_to(func.start_ea, eaCurrent);
                    }
                }
            }
            if (Sigs.Count == 0) {
                Console.WriteLine("Automated signature generation failed, no references found.");
                return false;
            }
            Console.WriteLine($"Added {Sigs.Count} references.");
            return true;
        }

        private bool _chooseSig() {
            int max = 9999;
            int selected = -1;
            foreach (var sig in Sigs) {
                while (sig.sig.Count > 0 && sig.sig[sig.sig.Count - 1] == "?") {
                    sig.sig.RemoveAt(sig.sig.Count - 1);
                }
                if (sig.bUnique) {
                    int sigLen = sig.sig.Count;
                    if (__plugin.Settings.SigSelect == SigSelect.OPT_LENGTH) {
                        if (sigLen < max || (sig.eType == PatternType.PT_DIRECT && max == sigLen)) {
                            max = sigLen;
                            selected = Sigs.IndexOf(sig);
                        }
                    }
                    else {
                        if (__plugin.Settings.SigSelect == SigSelect.OPT_OPCODES) {
                            if (sig.iOpCount < max || (sig.eType == PatternType.PT_DIRECT && max == sig.iOpCount)) {
                                max = sig.iOpCount;
                                selected = Sigs.IndexOf(sig);
                            }
                        }
                        else {
                            int wildcards = 0;
                            foreach (var s in sig.sig) {
                                if (s == "?") {
                                    wildcards++;
                                }
                            }
                            if (wildcards < max || sig.eType == PatternType.PT_DIRECT && max == wildcards) {
                                selected = Sigs.IndexOf(sig);
                                max = wildcards;
                            }
                        }
                    }
                }
            }
            if (selected == -1) {
                Console.WriteLine("Failed to create signature.");
                return false;
            }
            SigCreateStruct sig = Sigs[selected];
            string idaSig = string.Join(" ", sig.sig);
            string strSig = "";
            if (__plugin.Settings.SigType == SigType.SIG_CODE) {
                (string patt, string mask) = Ida2Code(idaSig);
                strSig = patt + " " + mask;
            }
            else if (__plugin.Settings.SigType == SigType.SIG_OLLY) {
                strSig = Ida2Olly(idaSig);
            }
            else {
                strSig = idaSig;
            }
            uint ea = BinQuery(idaSig, QueryTypes.QUERY_FIRST);
            string txt = "";
            if (sig.eType == PatternType.PT_DIRECT) {
                txt = string.Format("result: matches @ 0x{0:X}, sig direct: {1}", ea, strSig);
            }
            else if (sig.eType == PatternType.PT_FUNCTION) {
                txt = string.Format("result: matches @ 0x{0:X}, sig function: (+0x{1:X}) {2}", ea, startea - sig.dwStartAddress, strSig);
            }
            else if (sig.eType == PatternType.PT_REFERENCE) {
                txt = string.Format("result: matches @ 0x{0:X}, sig reference: {1}", ea, strSig);
            }
            Console.WriteLine(txt);

            return true;
        }

        public bool AutoFunction() {
            _reset();
            uint startea = idc.get_screen_ea();
            if (startea == 0 || startea == SigCreateStruct.BADADDR) {
                Console.WriteLine("Current ea == BADADDR.");
                return false;
            }
            if (FUNC_START_EA) {
                var func = idaapi.get_func(startea);
                if (func == null || func.start_ea == SigCreateStruct.BADADDR) {
                    Console.WriteLine("Must be in a function.");
                    return false;
                }
                else if (startea != func.start_ea) {
                    startea = func.start_ea;
                    Console.WriteLine(string.Format("Using function: 0x{0:X}", startea));
                }
            }
            if (!_addRefs(startea)) {
                return false;
            }
            int iCount = 0;
            bool bHaveUniqueSig = false;
            while (!bHaveUniqueSig && Sigs.Count > 0) {
                for (int sigIndex = 0; sigIndex < Sigs.Count; sigIndex++) {
                    if (Sigs[sigIndex].sig.Count < __plugin.Settings.maxSigLength && _addToSig(sigIndex)) {
                        if (Sigs[sigIndex].sig.Count > 5) {
                            Sigs[sigIndex].bUnique = BinQuery(string.Join(" ", Sigs[sigIndex].sig), QueryTypes.QUERY_UNIQUE);
                        }
                    }
                    else {
                        if (sigIndex == 0) {
                            Sigs.RemoveAt(0);
                        }
                        else if (sigIndex == Sigs.Count - 1) {
                            Sigs.RemoveAt(Sigs.Count - 1);
                        }
                        else {
                            Sigs.RemoveRange(sigIndex, Sigs.Count - sigIndex);
                        }
                        sigIndex--;
                    }
                }
                bHaveUniqueSig = _haveUniqueSig();
            }
            return _chooseSig();
        }

        public bool AutoAddress() {
            _reset();
            uint startea = idc.get_screen_ea();
            if (startea == 0 || startea == SigCreateStruct.BADADDR) {
                Console.WriteLine("Click on address you want sig for.");
                return false;
            }
            SigCreateStruct sig = new SigCreateStruct();
            sig.dwStartAddress = startea;
            sig.dwCurrentAddress = startea;
            sig.eType = PatternType.PT_DIRECT;
            Sigs.Add(sig);
            while (!Sigs[0].bUnique && Sigs[0].sig.Count < __plugin.Settings.maxSigLength) {
                int sigIndex = 0;
                if (_addToSig(sigIndex)) {
                    if (Sigs[sigIndex].sig.Count > 5) {
                        Sigs[sigIndex].bUnique = BinQuery(string.Join(" ", Sigs[sigIndex].sig), QueryTypes.QUERY_UNIQUE);
                    }
                }
                else {
                    Console.WriteLine("Unable to create sig at selected address");
                    return false;
                }
            }
            return _chooseSig();
        }
    }
}
*/