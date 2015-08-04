/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <cstring>
#include <cstdlib>
#include <string>
#include <stdio.h>
#include "pin.H"


FILE * trace;

static int line_index[500];

static long non_memory_ins = 0;
static long tot_ins = 0;

// The cache will be cold when start, both for ramulator and gem5 checkpoint
// static long START = 368000000000;
// static long END = 368001000000;
static long START = 1000000000;
static long END = 200000000;

KNOB<int> KnobInputTraceId(KNOB_MODE_WRITEONCE, "pintool", "s", "401", "specify input trace id");
KNOB<std::string> KnobTraceName(KNOB_MODE_WRITEONCE, "pintool", "name", "401.bzip2", "specify input trace name");

static VOID icount() {
  tot_ins++;
  if (tot_ins > END) {
    exit(0);
  }
}

static VOID non_memory_icount() {
  non_memory_ins++;
}

// Print a memory read record
VOID RecordMemRead(VOID * addr)
{
  if (tot_ins >= START && tot_ins <= END) {
    fprintf(trace,"%ld %p R\n", non_memory_ins, addr);
  }
  non_memory_ins = 0;
}

// Print a memory write record
VOID RecordMemWrite(VOID * addr)
{
  if (tot_ins >= START && tot_ins <= END) {
    fprintf(trace,"%ld %p W\n", non_memory_ins, addr);
  }
  non_memory_ins = 0;
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)icount,
        IARG_END);
    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp)) {
        
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
        // Note that in some architectures a single memory operand can be 
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp)) {
        
            INS_InsertPredicatedCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
    }

    if (memOperands == 0) {
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)non_memory_icount,
          IARG_END);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    printf("tot_ins %ld\n", tot_ins);
    fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    PIN_ERROR( "This Pintool prints a trace of memory addresses\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
  line_index[400] = 541;
  line_index[401] = 368;
  line_index[403] = 64;
  line_index[410] = 680;
  line_index[416] = 48;
  line_index[429] = 370;
  line_index[433] = 272;           
  line_index[434] = 405;           
  line_index[435] = 1;             
  line_index[436] = 81;            
  line_index[437] = 176;           
  line_index[444] = 1527;          
  line_index[445] = 133;           
  line_index[447] = 1387;          
  line_index[450] = 382;           
  line_index[453] = 160;           
  line_index[454] = 4433;          
  line_index[456] = 942;           
  line_index[458] = 477;           
  line_index[459] = 1060;          
  line_index[462] = 2666;          
  line_index[464] = 8;             
  line_index[465] = 44;            
  line_index[470] = 13;            
  line_index[471] = 477;           
  line_index[473] = 185;           
  line_index[481] = 2694;          
  line_index[482] = 3195;          
  line_index[483] = 178;

    if (PIN_Init(argc, argv)) return Usage();

    printf("KnobInputTraceId %d\n", KnobInputTraceId.Value());
    printf("KnobTraceName %s\n", KnobTraceName.Value().c_str());
//     START = line_index[KnobInputTraceId.Value()] * 1000000000l;
    END += START;
    printf("START %ld\n", START);

    std::string output_path = "spectrace/";
    output_path += KnobTraceName.Value();
    printf("output path %s\n", output_path.c_str());
    trace = fopen(output_path.c_str(), "w");

    std::string log_path = "specresult/";
    log_path += KnobTraceName.Value();
    printf("log path %s\n", log_path.c_str());
    if (freopen(log_path.c_str(), "w", stdout) == NULL) {
	printf("freopen(log_path.c_str(), \"w\", stdout) == NULL)\n");	
	exit(1);
    }

    std::string err_path = "specerr/";
    err_path += KnobTraceName.Value();
    printf("err path %s\n", err_path.c_str());
    if (freopen(err_path.c_str(), "w", stderr) == NULL) {
	printf("freopen(err_path.c_str(), \"w\", stderr) == NULL)\n");	
	exit(1);
    } 

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
