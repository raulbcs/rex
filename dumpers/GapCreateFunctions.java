// Creates functions in .text gaps not covered by getFunctionManager() extents.
// Merge of all function bodies -> gaps >= 12 bytes inside .text -> for each:
// disassemble(addr) + createFunction(addr, "GAP_<va>"). Per-gap try/catch,
// failures logged and skipped. Gaps < 12 bytes are left untouched.
// Run via analyzeHeadless on the existing project: -noanalysis -postScript
// (same Method B as rex shards). No REX_ROOT needed (in-program operation).
// @category Switch.Batch
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;

public class GapCreateFunctions extends GhidraScript {
    static final long MIN_GAP = 12;

    @Override
    public void run() throws Exception {
        MemoryBlock text = currentProgram.getMemory().getBlock(".text");
        if (text == null) throw new RuntimeException(".text block not found");
        Address lo = text.getStart(), hi = text.getEnd();

        // merged extents of existing functions (restrict to .text range)
        java.util.List<long[]> merged = new java.util.ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            for (ghidra.program.model.address.AddressRange r : f.getBody()) {
                long s = r.getMinAddress().getOffset(), e = r.getMaxAddress().add(1).getOffset();
                if (e <= lo.getOffset() || s >= hi.getOffset()) continue;
                s = Math.max(s, lo.getOffset()); e = Math.min(e, hi.getOffset());
                if (!merged.isEmpty() && s <= merged.get(merged.size() - 1)[1]) {
                    long[] last = merged.get(merged.size() - 1);
                    last[1] = Math.max(last[1], e);
                } else {
                    merged.add(new long[]{s, e});
                }
            }
        }

        // gaps >= MIN_GAP
        java.util.List<long[]> gaps = new java.util.ArrayList<>();
        long prev = lo.getOffset();
        for (long[] m : merged) {
            if (m[0] - prev >= MIN_GAP) gaps.add(new long[]{prev, m[0]});
            prev = Math.max(prev, m[1]);
        }
        if (hi.getOffset() - prev >= MIN_GAP) gaps.add(new long[]{prev, hi.getOffset()});

        println("gaps >= " + MIN_GAP + "B in .text: " + gaps.size()
            + " (" + gaps.stream().mapToLong(g -> g[1] - g[0]).sum() + " bytes)");

        long created = 0, failed = 0, skipped = 0;
        for (long[] g : gaps) {
            Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(g[0]);
            try {
                disassemble(a);
                Function nf = createFunction(a, String.format("GAP_%x", g[0]));
                if (nf != null) {
                    created++;
                    if (created % 500 == 0) println("progress: " + created + " created");
                } else {
                    failed++;
                    println("FAIL createFunction @ " + a);
                }
            } catch (Exception e) {
                failed++;
                println("EXC @ " + a + ": " + e.getMessage());
            }
        }
        println("DONE created=" + created + " failed=" + failed + " gaps=" + gaps.size());
    }
}
