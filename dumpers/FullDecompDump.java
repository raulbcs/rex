// Decompila TODAS as funções do programa (pseudocode C) via DecompInterface.
// Saída (default = REX_ROOT/data/decomp-full; override: único arg = dir de saída):
//   shard-NNN.txt (500 funcs/shard) + functions.tsv (entry\tname\tstatus\tshard)
//   + progress.log (linha a cada 100 funcs com rate/ETA — tail -f friendly).
// Resume: functions.tsv existente é carregado; funções 'ok' são puladas.
// Rodar via rex shards (~/projects/rex) ou Method B, cwd NEUTRO.
// @category MK8DX.Batch
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.*;
import java.util.*;

public class FullDecompDump extends GhidraScript {
    static final int SHARD = 500;

    @Override
    public void run() throws Exception {
        String out = System.getenv("REX_ROOT");
        String[] args = getScriptArgs();
        if (out == null && args.length == 0) {
            throw new RuntimeException("REX_ROOT não setado (nem arg de dir de saída)");
        }
        out = (out != null ? out : "") + "/data/decomp-full";
        if (args.length > 0) out = args[0];
        final String OUT = out;
        new File(OUT).mkdirs();

        // resume: entradas já concluídas
        Set<String> done = new HashSet<>();
        File idxFile = new File(OUT + "/functions.tsv");
        if (idxFile.exists()) {
            try (BufferedReader br = new BufferedReader(new FileReader(idxFile))) {
                String l = br.readLine(); // header
                while ((l = br.readLine()) != null) {
                    String[] p = l.split("\t", -1);
                    if (p.length > 2 && p[2].equals("ok")) done.add(p[0]);
                }
            }
        }
        PrintWriter idx = new PrintWriter(new BufferedWriter(new FileWriter(idxFile, true), 1 << 16));
        if (idxFile.length() == 0) idx.println("entry\tname\tstatus\tshard");
        PrintWriter prog = new PrintWriter(new BufferedWriter(new FileWriter(OUT + "/progress.log", true), 8192));

        // total real do programa (dois passes: contar, depois processar)
        long total = 0;
        FunctionIterator countIt = currentProgram.getFunctionManager().getFunctions(true);
        while (countIt.hasNext()) { countIt.next(); total++; }

        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);

        int shardIdx = 0;
        while (new File(String.format("%s/shard-%03d.txt", OUT, shardIdx)).exists()) shardIdx++;
        PrintWriter shardPw = null;
        int inShard = 0;

        long t0 = System.currentTimeMillis();
        long ok = 0, fail = 0, skipped = done.size();
        prog.println(ts() + " START total=" + total + " resume_skip=" + skipped);
        prog.flush();

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            String addr = Long.toHexString(f.getEntryPoint().getOffset());
            if (done.contains(addr)) continue;
            if (inShard == SHARD) { shardPw.close(); shardPw = null; inShard = 0; }
            if (shardPw == null) {
                while (new File(String.format("%s/shard-%03d.txt", OUT, shardIdx)).exists()) shardIdx++;
                shardPw = new PrintWriter(new BufferedWriter(
                    new FileWriter(String.format("%s/shard-%03d.txt", OUT, shardIdx)), 1 << 20));
            }
            String status;
            DecompileResults res = ifc.decompileFunction(f, 90, monitor);
            shardPw.println("// ===== " + f.getName() + " @ " + addr + " =====");
            if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
                shardPw.println(res.getDecompiledFunction().getC());
                status = "ok"; ok++;
            } else {
                String err = res.getErrorMessage();
                if (err == null) err = "null";
                err = err.replace('\n', ' ').replace('\t', ' ');
                if (err.length() > 120) err = err.substring(0, 120);
                shardPw.println("// DECOMP FAIL: " + err);
                status = "fail"; fail++;
            }
            idx.println(addr + "\t" + f.getName() + "\t" + status + "\t" + shardIdx);
            inShard++;

            if ((ok + fail) % 100 == 0) {
                long el = System.currentTimeMillis() - t0;
                double rate = (ok + fail) * 1000.0 / Math.max(el, 1);
                long doneNow = ok + fail + skipped;
                long eta = (long) ((total - doneNow) / Math.max(rate, 0.001));
                String line = ts() + String.format(" %d/%d (%.1f%%) | %.1f f/s | ETA %s | ok=%d fail=%d | last %s",
                    doneNow, total, 100.0 * doneNow / total, rate, fmtDur(eta), ok, fail, addr);
                prog.println(line); prog.flush();
                idx.flush(); shardPw.flush();
                println(line);
            }
        }
        if (shardPw != null) shardPw.close();
        String fin = ts() + " DONE ok=" + ok + " fail=" + fail + " skipped=" + skipped
            + " elapsed=" + fmtDur((System.currentTimeMillis() - t0) / 1000);
        prog.println(fin); prog.flush(); prog.close();
        idx.close(); ifc.dispose();
        println("TOTAL " + fin);
    }

    private static String ts() {
        return new java.text.SimpleDateFormat("HH:mm:ss").format(new Date());
    }
    private static String fmtDur(long s) {
        return String.format("%02d:%02d:%02d", s / 3600, (s % 3600) / 60, s % 60);
    }
}
