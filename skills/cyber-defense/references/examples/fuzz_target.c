// Template for a libFuzzer harness aimed at one blind-spot function from introspector.py (oss-hunt §5b).
// Rules that make the crash count as a finding, not a harness bug:
//  - call the project's public entry point the way a real caller does, with the same preconditions
//    (init calls, option structs) the docs or tests use; never call static helpers directly;
//  - the harness owns no buffers the project writes into, except ones a real caller would pass
//    with the documented size;
//  - free/close everything the API allocates, so a leak or double free is the project's.
// Control: the same harness on the fixed version (or with the check restored) runs clean for the
// same time budget.
#include <stddef.h>
#include <stdint.h>

int parse_record(const uint8_t *data, size_t size);  // replace with the project's header

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_record(data, size);
    return 0;
}
