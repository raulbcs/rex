// Exports the full asm listing of ALL program functions (no filter).
// Output (default = $REX_ROOT/data/asm-full; override: single arg = output dir):
//   shard-NNN.txt (500 funcs/shard) + functions.tsv (entry, name, insns, shard).
// SHARD=500 aligned with FullDecompDump — identical numbering across corpora
// is a shard_resolve.py requirement (asm↔decomp of the same function set).
// Run via rex shards (~/projects/rex) or Method B: compile, copy .java+.class
// to the Decompiler feature scripts dir, clear OSGi cache, -noanalysis -postScript.
// @category MK8DX.Batch
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class FullAsmDump extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outDir = System.getenv("REX_ROOT");
        String[] args = getScriptArgs();
        if (outDir == null && args.length == 0) {
            throw new RuntimeException("REX_ROOT not set (nor output dir arg)");
        }
        outDir = (outDir != null ? outDir : "") + "/data/asm-full";
        if (args.length > 0) outDir = args[0];
        new File(outDir).mkdirs();
        int SHARD = 500;

        PrintWriter shardPw = null;
        PrintWriter idx = new PrintWriter(new BufferedWriter(
            new FileWriter(outDir + "/functions.tsv"), 1 << 20));
        idx.println("entry\tname\tinsns\tshard");

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        long count = 0, totalInsns = 0;
        while (it.hasNext()) {
            Function f = it.next();
            int shardIdx = (int) (count / SHARD);
            if (count % SHARD == 0) {
                if (shardPw != null) shardPw.close();
                shardPw = new PrintWriter(new BufferedWriter(
                    new FileWriter(outDir + String.format("/shard-%03d.txt", shardIdx)), 2 << 20));
            }
            long ep = f.getEntryPoint().getOffset();
            String addr = Long.toHexString(ep);
            shardPw.println("// " + f.getName() + " @ " + addr);
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            long n = 0;
            while (ii.hasNext()) {
                Instruction ins = ii.next();
                shardPw.println(Long.toHexString(ins.getAddress().getOffset())
                    + "  " + ins.toString());
                n++;
            }
            idx.println(addr + "\t" + f.getName() + "\t" + n + "\t" + shardIdx);
            totalInsns += n;
            count++;
            if (count % 5000 == 0) println("progress: " + count);
        }
        if (shardPw != null) shardPw.close();
        idx.close();
        println("TOTAL functions: " + count + ", instructions: " + totalInsns);
    }
}
