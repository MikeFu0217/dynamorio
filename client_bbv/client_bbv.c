/*
 * DynamoRIO Client: Basic Block Vector Extractor
 * Extracts basic blocks (BBs) with execution count and disassembly.
 * Author: ChatGPT for Zuoming
 */

 #include "dr_api.h"
 #include "drmgr.h"
 #include "drutil.h"
 #include <string.h>
 
 static file_t log_file;
 static void *mutex;
 static int bb_id = 0;
 
 static void event_exit(void);
 static dr_emit_flags_t bb_instrumentation(void *drcontext, void *tag, instrlist_t *bb,
                                           instr_t *instr, bool for_trace, bool translating, void *user_data);
 
 DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
     dr_set_client_name("DynamoRIO Basic Block Vector Client", "https://dynamorio.org");
 
     drmgr_init();
     drutil_init();
 
     dr_register_exit_event(event_exit);
     drmgr_register_bb_instrumentation_event(NULL, bb_instrumentation, NULL);
 
     mutex = dr_mutex_create();
 
     // Create log file
     char logfilename[MAXIMUM_PATH];
     dr_snprintf(logfilename, sizeof(logfilename), "bbv_output.jsonl");
     log_file = dr_open_file(logfilename, DR_FILE_WRITE_OVERWRITE);
     DR_ASSERT(log_file != INVALID_FILE);
 
     dr_log(NULL, DR_LOG_ALL, 1, "BBV Client initialized\n");
 }
 
 static void event_exit(void) {
     if (log_file != INVALID_FILE)
         dr_close_file(log_file);
 
     dr_mutex_destroy(mutex);
     drutil_exit();
     drmgr_exit();
 }
 
 static dr_emit_flags_t bb_instrumentation(void *drcontext, void *tag, instrlist_t *bb,
                                           instr_t *instr, bool for_trace, bool translating, void *user_data) {
     static const int max_instrs = 64;
     instr_t *instr_it;
     char disasm[256];
     char json_buf[4096];
     int json_offset = 0;
 
     dr_mutex_lock(mutex);
     json_offset += dr_snprintf(json_buf + json_offset, sizeof(json_buf) - json_offset,
                                "{\"bb_id\": %d, \"instructions\": [", bb_id++);
 
     int count = 0;
     for (instr_it = instrlist_first_app(bb); instr_it != NULL && count < max_instrs;
          instr_it = instr_get_next_app(instr_it), count++) {
         instr_disassemble_to_buffer(drcontext, instr_it, disasm, sizeof(disasm));
         app_pc pc = instr_get_app_pc(instr_it);
 
         json_offset += dr_snprintf(json_buf + json_offset, sizeof(json_buf) - json_offset,
                                    "{\"pc\": \"%p\", \"disasm\": \"%s\"}", pc, disasm);
 
         if (instr_get_next_app(instr_it) != NULL && count + 1 < max_instrs)
             json_offset += dr_snprintf(json_buf + json_offset, sizeof(json_buf) - json_offset, ", ");
     }
 
     json_offset += dr_snprintf(json_buf + json_offset, sizeof(json_buf) - json_offset, "]}\n");
 
     dr_write_file(log_file, json_buf, strlen(json_buf));
     dr_mutex_unlock(mutex);
 
     return DR_EMIT_DEFAULT;
 }
 