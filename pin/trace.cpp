/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This file contains a tool that generates instructions traces with values.
 *  It is designed to help debugging.
 */

#include <cstdlib>
#include <nlohmann/detail/conversions/from_json.hpp>
#include <nlohmann/detail/conversions/to_json.hpp>
#include <types.h>
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include "pin.H"
#include "instlib.H"
#include "control_manager.H"
#include "regvalue_utils.h"
#include "types_foundation.PH"
#include "types_vmapi.PH"
#include <nlohmann/json.hpp>
#include <iostream>

using namespace CONTROLLER;
using namespace INSTLIB;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "trace.out", "trace file");
KNOB< BOOL > KnobPid(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "append pid to output");
KNOB< BOOL > KnobSymbols(KNOB_MODE_WRITEONCE, "pintool", "symbols", "1", "Include symbol information");
KNOB< BOOL > KnobTraceCalls(KNOB_MODE_WRITEONCE, "pintool", "call", "1", "Trace calls");
KNOB< string > KnobSymbolFile(KNOB_MODE_WRITEONCE, "pintool", "s", "symbols.json", "Symbols File");

/* ===================================================================== */

INT32 Usage() {
    cerr << "This pin tool collects an instruction trace for debugging\n" "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;
    return -1;
}

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

static std::ofstream out;
static INT32 enabled = 0;
static FILTER filter;
TLS_KEY tls_key;

struct TraceData {
    UINT64 tsc;
    THREADID tid;
    ADDRINT addr;
};

struct ThreadData {
    FILE* logfile;
    std::vector<TraceData> trace_data;
};


static VOID Fini(int, VOID* v);

static VOID Handler(EVENT_TYPE ev, VOID*, CONTEXT* ctxt, VOID*, THREADID, bool bcast) {
    switch (ev) {
        case EVENT_START:
            enabled = 1;
            PIN_RemoveInstrumentation();
#if defined(TARGET_IA32) || defined(TARGET_IA32E)
            // So that the rest of the current trace is re-instrumented.
            if (ctxt) PIN_ExecuteAt(ctxt);
#endif
            break;

        case EVENT_STOP:
            enabled = 0;
            PIN_RemoveInstrumentation();
#if defined(TARGET_IA32) || defined(TARGET_IA32E)
            // So that the rest of the current trace is re-instrumented.
            if (ctxt) PIN_ExecuteAt(ctxt);
#endif
            break;

        default:
            ASSERTX(false);
    }
}

std::set<ADDRINT> instrumentPoints;
ADDRINT exeBase = 0;

VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
    ThreadData* tdata = new ThreadData();

    char filename[128];
    sprintf(filename, "thread_%u.log", tid);
    tdata->logfile = fopen(filename, "w");

    PIN_SetThreadData(tls_key, tdata, tid);
}

VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v) {
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    if (tdata) {
        if (tdata->logfile) fclose(tdata->logfile);
        for (auto& e : tdata->trace_data) {
            //fprintf(out, "tsc=%lu, tid=%u, ip=%p\n", e.tsc, e.tid, (void*)(e.addr - exeBase));
            out << "tsc=" << std::dec << e.tsc << ", tid=" << e.tid << ", ip=" << std::hex << e.addr << std::endl;
            //printf("tsc=%lu, tid: %u, ip=%p\n", e.tsc, e.tid, (void*)(e.addr - exeBase));

        }
        delete tdata;
    }
}

VOID AnalysisFunction(ADDRINT addr, UINT64 tsc) {
    out << addr - exeBase << endl;
    printf("at addr: 0x%lx\n", addr - exeBase);
    
}

VOID AnalysisThread(THREADID tid, ADDRINT addr, UINT64 tsc) {
    ThreadData* tdata = static_cast<ThreadData*>(PIN_GetThreadData(tls_key, tid));
    if (tdata && tdata->logfile) {
        //fprintf(tdata->logfile, "tsc=%lu, ip=%p\n", tsc, (void*)(addr - exeBase));
        tdata->trace_data.push_back(TraceData{tsc, tid, (addr - exeBase)});
        if (tdata->trace_data.size() >= 1024 * 1024 * 16) {
            for (auto& e : tdata->trace_data) {
                //fprintf(out, "tsc=%lu, tid=%u, ip=%p\n", e.tsc, e.tid, (void*)(e.addr - exeBase));
                out << "tsc=" << std::dec << e.tsc << ", tid=" << e.tid << ", ip=" << std::hex << e.addr << std::endl;
                //printf("tsc=%lu, tid: %u, ip=%p\n", e.tsc, e.tid, (void*)(e.addr - exeBase));

            }
            tdata->trace_data.clear();
        }
    }
    //out << "Thread: " << tid << ", addr: " << std::hex << addr - exeBase << std::endl;
    //printf("at addr: 0x%lx\n", addr - exeBase);
    
}

VOID Instruction(INS ins, VOID *v) {
    ADDRINT addr = INS_Address(ins);
    if (instrumentPoints.count(addr - exeBase)) {
        printf("added addr: %ld\n", addr - exeBase);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AnalysisThread, IARG_THREAD_ID, IARG_INST_PTR, IARG_TSC, IARG_END);
        //INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)AnalysisFunction, IARG_ADDRINT, addr, IARG_END);
    }
}


VOID SymbolLoad(IMG img, VOID *v) {

    if (IMG_IsMainExecutable(img)) {
        exeBase = IMG_LoadOffset(img);
        std::cout << "Base address of executable: 0x" << std::hex << exeBase << std::endl;
        for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
            for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
                RTN_Open(rtn);
                //std::cout << RTN_Name(rtn) << std::endl;
                for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {

                    //std::cout << INS_Disassemble(ins) << std::endl;
                    Instruction(ins, 0);
                }
                RTN_Close(rtn);
            }
        }
    }
}

VOID Fini(int, VOID* v) {
    
    out.close();
}

static void OnSig(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT* ctxtFrom, CONTEXT* ctxtTo, INT32 sig, VOID* v) {
    if (ctxtFrom != 0)
    {
        ADDRINT address = PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
        out << "SIG signal=" << sig << " on thread " << threadIndex << " at address " << hex << address << dec << " ";
    }

    switch (reason)
    {
        case CONTEXT_CHANGE_REASON_FATALSIGNAL:
            out << "FATALSIG" << sig;
            break;
        case CONTEXT_CHANGE_REASON_SIGNAL:
            out << "SIGNAL " << sig;
            break;
        case CONTEXT_CHANGE_REASON_SIGRETURN:
            out << "SIGRET";
            break;

        case CONTEXT_CHANGE_REASON_APC:
            out << "APC";
            break;

        case CONTEXT_CHANGE_REASON_EXCEPTION:
            out << "EXCEPTION";
            break;

        case CONTEXT_CHANGE_REASON_CALLBACK:
            out << "CALLBACK";
            break;

        default:
            break;
    }
    out << std::endl;
}

/* ===================================================================== */

static CONTROL_MANAGER control;
static SKIPPER skipper;

/* ===================================================================== */

std::string SetToString(const std::set<ADDRINT>& s) {
    std::ostringstream oss;
    oss << "{ ";
    for (auto it = s.begin(); it != s.end(); ++it) {
        if (it != s.begin()) oss << ", ";
        oss << "0x" << std::hex << *it;
    }
    oss << " }";
    return oss.str();
}

int main(int argc, CHAR* argv[]) {
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    tls_key = PIN_CreateThreadDataKey(NULL);
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);
    string filename = KnobOutputFile.Value();

    if (KnobPid) {
        filename += "." + decstr(getpid());
    }

    std::ifstream file(KnobSymbolFile);
    if (!file.is_open()) {
        printf("Failed to open file\n");
        exit(1);
    }
    using json = nlohmann::json;
    json symbols = json::parse(file);
    //ADDRINT base = symbols["offset"];
    for (const auto& fn : symbols["functions"]) {
        instrumentPoints.insert(fn["addr"].get<ADDRINT>());
        for (const auto& ret : fn["returns"]) {
            instrumentPoints.insert(ret.get<ADDRINT>());
        }
    }
    std::cout << SetToString(instrumentPoints) << std::endl;

    // Do this before we activate controllers
    out.open(filename.c_str());
    out << hex << right;
    out.setf(ios::showbase);

    control.RegisterHandler(Handler, 0, FALSE);
    control.Activate();
    skipper.CheckKnobs(0);
    IMG_AddInstrumentFunction(SymbolLoad, NULL);
    //INS_AddInstrumentFunction(Instruction, 0);
    //TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddContextChangeFunction(OnSig, 0);

    PIN_AddFiniFunction(Fini, 0);

    filter.Activate();

    PIN_StartProgram();

    return 0;
}
