#include <stdio.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <bfd.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <sstream>
#include <memory>
#include <map>
#include <cxxabi.h>
#include <vector>
#include <utility>
#include <iomanip>
#include <execinfo.h>
#include <dlfcn.h>

#define LOG_TRACE(level,fmt,...) fprintf(stderr,fmt, __VA_ARGS__); 

std::string demangle_cxa(const std::string &_cxa) {
    int status;
    std::unique_ptr<char[]> realname;
    realname.reset(abi::__cxa_demangle(_cxa.data(), 0, 0, &status));
    if (status != 0) {
        return _cxa;
    }
    if (realname) {
        return std::string(realname.get());
    } else {
        return "";
    }
}

struct bfdResolver {
    struct storedBfd {
        bfd* abfd;
        asymbol** symbols;
        intptr_t offset;
    };
    static std::map<void *, storedBfd> bfds;
    static bool bfd_initialized;


    static std::string resolve(void *address) {
        if (!bfd_initialized) {
            bfd_init();
            bfd_initialized = true;
        }

        std::stringstream res;
        res << "[0x" << std::setw((int)sizeof(void*)*2) << std::setfill('0') << std::hex << (uintptr_t)address;

        // get path and offset of shared object that contains this address
        Dl_info info;
        dladdr(address, &info);
        if (info.dli_fbase == nullptr) {
            return res.str()+" .?] <object to address not found>";
        }

        // load the corresponding bfd file (from file or map)
        if (bfds.count(info.dli_fbase) == 0) {
            std::unique_ptr<storedBfd> newBfd(new storedBfd);
            newBfd->abfd = bfd_openr(info.dli_fname, 0);
            if (!newBfd->abfd) {
                return res.str()+" .?] <could not open object file>";
            }
            bfd_check_format(newBfd->abfd,bfd_object);
            size_t storage_needed = bfd_get_symtab_upper_bound(newBfd->abfd);
            newBfd->symbols =reinterpret_cast<asymbol**>(new char[storage_needed]);
            /*size_t numSymbols = */bfd_canonicalize_symtab(newBfd->abfd, newBfd->symbols );

            newBfd->offset = (intptr_t)info.dli_fbase;

            bfds.insert(std::pair<void *, storedBfd>(info.dli_fbase, *newBfd.release()));
        } 

        storedBfd &currBfd = bfds.at(info.dli_fbase);

        asection *section = currBfd.abfd->sections;
        bool relative = section->vma < (uintptr_t)currBfd.offset;
//      std::cout << '\n' << "sections:\n";
        while (section != nullptr) {
            intptr_t offset = ((intptr_t)address) - (relative?currBfd.offset:0) - section->vma;
//          std::cout << section->name << " " << section->id << " file: " << section->filepos << " flags: " << section->flags 
//                      << " vma: " << std::hex << section->vma << " - " << std::hex << (section->vma+section->size) << std::endl;

            if (offset < 0 || (size_t)offset > section->size) {
                section = section->next;
                continue;
            }
            res << ' ' << section->name;
            if (!(section->flags | SEC_CODE)) {
                return res.str()+"] <non executable address>";
            }
            // get more info on legal addresses
            const char *file;
            const char *func;
            unsigned line;
            if (bfd_find_nearest_line(currBfd.abfd, section, currBfd.symbols, offset, &file, &func, &line)) {
		return demangle_cxa(func);
            }
        }
//      std::cout << " ---- sections end ------ " << std::endl;
        return res.str()+" .none] <not sectioned address>";
    }
};

std::map<void *, bfdResolver::storedBfd> bfdResolver::bfds;
bool bfdResolver::bfd_initialized = false;

std::string get_call_stack() {
    const size_t MAX_FRAMES = 100;
    std::vector<void *> stack(MAX_FRAMES);
    int num = backtrace(&stack[0], MAX_FRAMES);
    if (num <= 0) {
        return "Callstack could not be built.";
    }
    stack.resize((size_t) num);
    std::string res;
    //NOTE i=0 corresponds to get_call_stack and is omitted
    for (size_t i=1; i<(size_t)num; ++i) {
        res += bfdResolver::resolve(stack[i]) + '\n';
    }
    return res;
}

const char* resolve_address(void *this_fn)
{
	return bfdResolver::resolve(this_fn).c_str();
}

extern "C"
{
#define ATRACE_MESSAGE_LEN 256
int     atrace_marker_fd = -1;


#define 	DMGL_PARAMS   (1 << 0)
#define 	DMGL_ANSI   (1 << 1)
#  define CHAR_BIT	8
char program_name[1024];

void trace_init()
{
	atrace_marker_fd = open("/sys/kernel/debug/tracing/trace_marker", O_WRONLY);
  	if (atrace_marker_fd == -1)
	{
		printf("ERROR: Could not open /sys/kernel/debug/tracing/trace_marker");
		exit(-1);	
	}
}

void trace_exit()
{
	close(atrace_marker_fd);
}

inline void trace_begin(const char *name)
{
    char buf[ATRACE_MESSAGE_LEN];
    int len = snprintf(buf, ATRACE_MESSAGE_LEN, "B|%d|%s", getpid(), name);
   	write(atrace_marker_fd, buf, len);
}

inline void trace_end()
{
    char c = 'E';
    write(atrace_marker_fd, &c, 1);
}


extern int __attribute__((__no_instrument_function__))
fprintf(FILE *stream, const char *format, ...)  ;
 
void __attribute__ ((constructor)) __attribute__((__no_instrument_function__))
start_trace (void);

void
__attribute__ ((destructor)) __attribute__((__no_instrument_function__))
end_trace (void);

void __attribute__((__no_instrument_function__))
__cyg_profile_func_enter (void *func,  void *callsite);


void __attribute__((__no_instrument_function__))
__cyg_profile_func_exit (void *func, void *caller);

void
start_trace (void)
{
		if (program_name != NULL) {
				if (readlink("/proc/self/exe", program_name, 1024) == -1) {
						printf("Could not read the executable name\n");
				}
		}
		trace_init();
}
 
void
end_trace (void)
{
	trace_exit();
}

void 
__cyg_profile_func_enter (void *func,  void *callsite)
{
	char buf_func[100];
        /*Which function*/
	trace_begin(resolve_address(func));
}

void 
__cyg_profile_func_exit (void *func, void *caller)
{
		trace_end();
}
}
