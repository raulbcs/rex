// Dataflow hunt for the mRaceRule writer: STORE into (X + 8) where X is
// RaceInfo-derived. Method:
//   1. collect direct references (BL) to the race-info chain anchors
//   2. expand 1 hop (callers of those callers)
//   3. decompile each function, walk Pcode: find STORE(RAM, V+8)
//   4. backslice V (intra-function): CALL to GetRaceInfo/GetNextRaceInfo /
//      holder getters / LOAD(+0x10) / LOAD(+0x2c) / param / other
//   5. print every store with provenance; writers via getter/holder = smoking gun,
//      param-provenance list = candidates receiving RaceInfo as arg.
// Run: analyzeHeadless <proj> MK8DX -process uncompressed_main -noanalysis
//      -postScript RaceInfoDataflow   (~2-4 min for the caller subset)
// @category Switch.Batch
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.RefType;
import java.io.PrintWriter;
import java.util.*;

public class RaceInfoDataflow extends GhidraScript {
    static final long[] ANCHORS = {
        0x710087c244L, // GetRaceInfo
        0x710087c274L, // GetNextRaceInfo
        0x71007f41ccL, // holder getter
        0x71007f41a0L, // holder member getter
        0x710000c754L, // RaceInfoDispatcher
        0x71003b9538L, // setup embed (ri = parent+0x2c, rule = parent+0x34)
        0x7100400088L, // config clone node{rule,course}->obj+0x8/+0xc
        0x71007f3a5cL, // RaceInfo factory (new 0x1e4 -> holder+0x10)
    };

    Address addr(long v) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);
    }

    String prov(HighVariable hv, int depth) {
        if (hv == null || depth > 6) return "deep";
        if (hv instanceof HighParam) return "param_" + ((HighParam) hv).getSlot();
        for (Varnode inst : hv.getInstances()) {
            PcodeOp op = inst.getDef();
            if (op == null || op.getOpcode() != PcodeOp.COPY) continue;
            Varnode in = op.getInput(0);
            if (in.isConstant()) return "const";
            HighVariable ih = in.getHigh();
            if (ih != null && ih != hv) {
                String r = provRaw(ih, depth + 1);
                if (r != null) return r;
            }
        }
        return "other";
    }

    String provRaw(HighVariable ih, int depth) {
        if (ih instanceof HighParam) return "param_" + ((HighParam) ih).getSlot();
        for (Varnode inst : ih.getInstances()) {
            PcodeOp def = inst.getDef();
            if (def == null) continue;
            int oc = def.getOpcode();
            if (oc == PcodeOp.CALL) {
                Address t = def.getInput(0).getAddress();
                if (t != null) return "call:" + t;
            }
            if (oc == PcodeOp.LOAD) return "load";
            if (oc == PcodeOp.MULTIEQUAL) return "phi";
        }
        return null;
    }

    @Override
    public void run() throws Exception {
        Set<Function> work = new LinkedHashSet<>();
        for (long a : ANCHORS) {
            Function f = getFunctionContaining(addr(a));
            if (f == null) continue;
            work.add(f);
            for (Reference r : getReferencesTo(f.getEntryPoint()))
                if (r.getReferenceType().isCall()) {
                    Function c = getFunctionContaining(r.getFromAddress());
                    if (c != null) work.add(c);
                }
        }
        // hop 2
        Set<Function> hop2 = new LinkedHashSet<>();
        for (Function f : work)
            for (Reference r : getReferencesTo(f.getEntryPoint()))
                if (r.getReferenceType().isCall()) {
                    Function c = getFunctionContaining(r.getFromAddress());
                    if (c != null && !work.contains(c)) hop2.add(c);
                }
        work.addAll(hop2);
        println("functions to analyze: " + work.size() + " (hop2: " + hop2.size() + ")");

        DecompInterface di = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.setMaxWidth(200);
        di.setOptions(opts);
        di.toggleSyntaxTree(true);
        di.openProgram(currentProgram);

        long stores = 0, funs = 0, dbgStores = 0, dbgAdd8 = 0;
        PrintWriter out = new PrintWriter(System.getenv("REX_ROOT") + "/data/raceinfo-dataflow.txt");
        out.println("# STOREs to (X+8) in race-chain callers (fn\tstore-pc\tbase-provenance)");
        for (Function f : work) {
            if (monitor.isCancelled()) break;
            DecompileResults res = di.decompileFunction(f, 30, monitor);
            if (!res.decompileCompleted()) continue;
            HighFunction hf = res.getHighFunction();
            boolean fnHas = false;
            Iterator<PcodeOpAST> it = hf.getPcodeOps();
            while (it.hasNext()) {
                PcodeOp op = it.next();
                if (op.getOpcode() != PcodeOp.STORE) continue;
                dbgStores++;
                if (dbgStores < 4)
                    println("DBGSTORE in=" + op.getNumInputs() + " i0=" + op.getInput(0)
                        + " i1=" + op.getInput(1) + " i2=" + op.getInput(2)
                        + " out=" + op.getOutput() + " @" + op.getSeqnum().getTarget());
                Varnode addrV = op.getInput(1), valV = op.getInput(2);
                if (dbgStores < 200) println("DBGDEF op=" + PcodeOp.getMnemonic(addrV.getDef() == null ? -1 : addrV.getDef().getOpcode()) + " addr=" + addrV);
                {
                    PcodeOp d = addrV.getDef();
                    while (d != null && d.getOpcode() == PcodeOp.CAST) d = d.getInput(0).getDef();
                    Varnode baseV = null;
                    if (d != null) {
                        int oc = d.getOpcode();
                        if ((oc == PcodeOp.INT_ADD || oc == PcodeOp.PTRSUB)
                                && d.getInput(1).isConstant()
                                && d.getInput(1).getOffset() == 8) baseV = d.getInput(0);
                        else if (oc == PcodeOp.PTRADD && d.getInput(1).isConstant()
                                && d.getInput(2).isConstant()
                                && d.getInput(1).getOffset() * d.getInput(2).getOffset() == 8)
                            baseV = d.getInput(0);
                    }
                    if (baseV != null) {
                            dbgAdd8++;
                            HighVariable base = baseV.getHigh();
                            String p = base == null ? "null" : prov(base, 0);
                            String line = f.getEntryPoint() + "\t" + op.getSeqnum().getTarget()
                                + "\t" + p + "\tsize=" + valV.getSize();
                            out.println(line);
                            if (!fnHas) { fnHas = true; funs++; }
                            stores++;
                        }
                }
            }
        }
        out.close();
        di.dispose();
        println("DBG: STORE ops=" + dbgStores + " base+8 matches=" + dbgAdd8
            + " decompiled=" + funs);
        println("DONE: " + stores + " stores(+8) in " + funs + " functions -> data/raceinfo-dataflow.txt");
    }
}
