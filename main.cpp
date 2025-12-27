#include <iostream>
#include <string.h>
#include <unistd.h>			// Required for execve()
#include <sys/types.h>
#include <errno.h>
#include <cstdint>			// Required for uintptr_t
#include <unordered_map>

#include <sys/wait.h>		// Required for wait()
#include <sys/ptrace.h>		// Required for ptrace()
#include <sys/user.h>		

using namespace std;

enum LastAction { NONE, CONTINUE, SINGLESTEP };
enum RunState { STOPPED, RUNNING, EXITED };

struct Breakpoint {
	uintptr_t address;
	uint8_t original_byte;
	bool enabled;
};

struct Debugger_State {
	pid_t child_pid;
	LastAction last_action;
	RunState run_state;
	bool stepping_over_breakpoint = false;
	uintptr_t stepping_bp_addr;
	unordered_map<uintptr_t, Breakpoint> breakpoints;
	bool just_execed = true;
} state;

uintptr_t parse_breakpoint(const string& cmd) {
    // Skip 'b' and any whitespace
    size_t start = cmd.find_first_not_of(" \t", 1);
    if (start == string::npos) 
        throw runtime_error("Invalid breakpoint command");

    // Remove optional '0x' prefix
    if (cmd.substr(start, 2) == "0x")
        start += 2;

    // Parse hex address
    return stoull(cmd.substr(start), nullptr, 16);
}

void handle_debug_event(Debugger_State &state, int status) {
	if (state.just_execed) {
		state.run_state = STOPPED;
		return;
	}

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        state.run_state = EXITED;
        return;
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        if (state.last_action == CONTINUE) {

            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, state.child_pid, nullptr, &regs) == -1) {
				perror("ptrace(GETREGS)");
				return;
			}

			uintptr_t hit_addr = regs.rip - 1;
            if (state.breakpoints.count(hit_addr) && state.breakpoints[hit_addr].enabled) {
				Breakpoint &bp = state.breakpoints[hit_addr];

				state.stepping_bp_addr = hit_addr;

                cout << "[Debugger] Breakpoint hit at 0x" << hex << hit_addr << "\n";

                long data = ptrace(PTRACE_PEEKDATA, state.child_pid, (void*)hit_addr, nullptr);

				if (data == -1) {
					perror("ptrace(PEEKDATA)");
					return;
				}

                long restored = (data & ~0xFF) | bp.original_byte;

                if (ptrace(PTRACE_POKEDATA, state.child_pid, (void*)hit_addr, (void*)restored) == -1) {
					perror("ptrace(POKEDATA");
					return;
				}

                regs.rip -= 1;
                
				if (ptrace(PTRACE_SETREGS, state.child_pid, nullptr, &regs) == -1) {
					perror("ptrace(SETREGS)");
					return;
				}

				state.stepping_over_breakpoint = true;
                bp.enabled = false;			// disable the breakpoint once reached
                state.last_action = NONE;
            }
        }

        else if (state.last_action == SINGLESTEP && state.stepping_over_breakpoint) {
			uintptr_t addr = state.stepping_bp_addr;

			if (!state.breakpoints.count(addr)) {
				state.stepping_over_breakpoint = false;
				return;
			}

            long data = ptrace(PTRACE_PEEKDATA, state.child_pid, (void*)addr, nullptr);

			if (data == -1) {
				perror("ptrace(PEEKDATA)");
				return;
			}

            long patched = (data & ~0xFF) | 0xCC;

			if (ptrace(PTRACE_POKEDATA, state.child_pid, (void*)addr, (void*)patched) == -1) {
				perror("ptrace(POKEDATA");
				return;
			}

			state.breakpoints[addr].enabled = true;
			state.stepping_over_breakpoint = false;
			state.stepping_bp_addr = 0;
			state.last_action = NONE;
        }
    }

    state.run_state = STOPPED;
}

int main(int argc, char *argv[]) {
	// take the target binary from user input
	if (argc < 2) {
		cerr << "Usage: " << argv[0] << " <program-to-debug>\n";
        return 1;
	}

	pid_t pid = fork();

	int status;
	if (pid == 0) {
		// child process (debuggee)
		cout << "Executing Child\n";
		// PTRACE_TRACEME allows the child process to be traced by its parent (all other params are ignored)
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
			perror("ptrace TRACEME");
			_exit(EXIT_FAILURE);
		}

		// Stop so parent can attach cleanly
		raise(SIGSTOP);

		execl(argv[1], argv[1], nullptr);

		// program reaches here only if there was some error in execve
		perror("execl");

		// this terminates the calling process immediately
		_exit(127);
		
	} else if (pid > 0) {
		// parent process (debugger)
		state.child_pid = pid;
		cout << "[Debugger] : Executing Parent\n";
		
		// wait for the child’s initial SIGSTOP (pre-exec synchronization)
		int rv = waitpid(pid, &status, 0);
		if (rv == -1) {
			perror("waitpid");
			return 1;
		}

		if (WIFSTOPPED(status)) {
			cout << "[Debugger] : Child process initial stopped with signal :" << WSTOPSIG(status) << endl;
		} else if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
			cerr << "[Debugger] : Unexpected initial stop\n";
			return 1;
		}

		long options = 0;

		// kill the child if the debugger dies
		options |= PTRACE_O_EXITKILL;

		// Make syscall traps distinguishable (important later)
		options |= PTRACE_O_TRACESYSGOOD;

		// (Optional but recommended) notify on execl
		options |= PTRACE_O_TRACEEXEC;

		if (ptrace(PTRACE_SETOPTIONS, pid, 0, options) == -1) {
			perror("ptrace(PTRACE_SETOPTIONS)");
			return 1;
		}

		// Let the child run until execl() completes
		if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
			perror("ptrace(PTRACE_CONT)");
			return 1;
		}

		// Wait for the execl trap
		if (waitpid(pid, &status, 0) == -1) {
			perror("waitpid");
			return 1;
		}

		// Child must stop again
		if (!WIFSTOPPED(status)) {
			cerr << "[Debugger] : Child did not stop after execl\n";
			return 1;
		}

		// Expect SIGTRAP here
		int sig = WSTOPSIG(status);
		if (sig != SIGTRAP) {
			cerr << "[Debugger] : Unexpected stop signal after execl: " << sig << "\n";
			return 1;
		} 
		
		state.just_execed = false;
		string line;

		while(1) {
			cout << "(dgb) ";
			getline(cin, line);

			if (line == "quit") break;

			if (line[0] == 'b') {
				// add breakpoint

				// 1. parse address
				uintptr_t breakpoint_addr = parse_breakpoint(line);
				if (state.breakpoints.find(breakpoint_addr) == state.breakpoints.end()) {
					// new breakpoint insert and populate the breakpoints
					long data = ptrace(PTRACE_PEEKDATA, pid, (void*)breakpoint_addr, nullptr);

					if (data == -1) {
						perror("ptrace(PEEKDATA)");
						continue;
					}

					// Save original byte
					uint8_t original_byte = static_cast<uint8_t>(data & 0xFF);

					state.breakpoints[breakpoint_addr] = {breakpoint_addr, original_byte, true};

					// Replace lowest byte with INT3 (0xCC)
					long patched_data = (data & ~0xFF) | 0xCC;

					// insert INT3 at lower byte
					if (ptrace(PTRACE_POKEDATA, pid, reinterpret_cast<void*>(breakpoint_addr), reinterpret_cast<void*>(patched_data)) == -1) {
						perror("ptrace(POKEDATA)");
						return 1;
					}
				} else {
					cout << "Breakpoint already set at 0x" << hex << breakpoint_addr << "\n";
				}
			} else if (line == "run" || line == "continue") {
				if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
					perror("ptrace(CONT)");
					break;
				}

				state.last_action = CONTINUE;
				state.run_state = RUNNING;

				if (waitpid(pid, &status, 0) == -1) {
					perror("waitpid");
					break;
				}

				handle_debug_event(state, status);
			} else if (line == "step") {
				if (state.stepping_over_breakpoint && state.last_action == SINGLESTEP) {
					cout << "[Debugger] Finish stepping over breakpoint first\n";
					continue;
				}

				if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
					perror("ptrace(SINGLESTEP)");
					break;
				}

				state.last_action = SINGLESTEP;
				state.run_state = RUNNING;

				if (waitpid(pid, &status, 0) == -1) {
					perror("waitpid");
					break;
				}

				handle_debug_event(state, status);
			} else if (line == "regs") {
				if (state.run_state != STOPPED) {
					cout << "[Debugger] Process not stopped\n";
					continue;
				}

				struct user_regs_struct regs;
				if (ptrace(PTRACE_GETREGS, state.child_pid, nullptr, &regs) == -1) {
					perror("ptrace(GETREGS)");
					break;
				}

				cout << "RIP = 0x" << regs.rip << "\n";
				cout << "RSP = 0x" << regs.rsp << "\n";
				cout << "RAX = 0x" << regs.rax << "\n";
			} else if (line[0] == 'd') {
				uintptr_t addr = parse_breakpoint(line);

				if (!state.breakpoints.count(addr)) {
					cout << "No breakpoint at 0x" << hex << addr << "\n";
					continue;
				}

				Breakpoint &bp = state.breakpoints[addr];

				if (bp.enabled) {
					long data = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, nullptr);

					if (data == -1) {
						perror("ptrace(PEEKDATA)");
						continue;
					}

					long restored = (data & ~0xFF) | bp.original_byte;

					if (ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)restored) == -1) {
						perror("ptrace(POKEDATA)");
						continue;
					}
				}

				state.breakpoints.erase(addr);

				if (state.stepping_bp_addr == addr) {
					state.stepping_over_breakpoint = false;
					state.stepping_bp_addr = 0;
				}

				cout << "[Debugger] Breakpoint removed at 0x" << hex << addr << "\n";
			}

			if (state.run_state == EXITED) {
				break;
			}
		}
	} else {
		perror("fork");
		return 1;
	}
	return 0;
}
