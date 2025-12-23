#include <iostream>
#include <string.h>
#include <unistd.h>			// Required for execve()
#include <sys/types.h>
#include <errno.h>
#include <cstdint>			// Required for uintptr_t

#include <sys/wait.h>		// Required for wait()
#include <sys/ptrace.h>		// Required for ptrace()
#include <sys/user.h>		

using namespace std;

enum LastAction { NONE, CONTINUE, SINGLESTEP };

struct Debugger_State {
	pid_t child_pid;
	uintptr_t breakpoint_addr;
	bool breakpoint_enabled = false;
	LastAction last_action;
} state;

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

		// (Optional but recommended) notify on execve
		options |= PTRACE_O_TRACEEXEC;

		if (ptrace(PTRACE_SETOPTIONS, pid, 0, options) == -1) {
			perror("ptrace(PTRACE_SETOPTIONS)");
			return 1;
		}

		// Let the child run until execve() completes
		if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
			perror("ptrace(PTRACE_CONT)");
			return 1;
		}

		// Wait for the execve trap
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

		// the child is in stop/pause state currently after execl
		cout << "[Debugger] : Enter breakpoint address (hex): 0x";
		cin >> hex >> state.breakpoint_addr;

		long data = ptrace(PTRACE_PEEKDATA, pid, reinterpret_cast<void*>(state.breakpoint_addr), nullptr);

		if (data == -1 && errno) {
			perror("ptrace(PEEKDATA)");
			return 1;
		}

		// Save original byte
		uint8_t original_byte = static_cast<uint8_t>(data & 0xFF);

		// Replace lowest byte with INT3 (0xCC)
		long patched_data = (data & ~0xFF) | 0xCC;

		if (ptrace(PTRACE_POKEDATA, pid, reinterpret_cast<void*>(state.breakpoint_addr), reinterpret_cast<void*>(patched_data)) == -1) {
			perror("ptrace(POKEDATA)");
			return 1;
		}

		cout << "[Debugger] Breakpoint set at 0x" << hex << state.breakpoint_addr << "\n";

		state.breakpoint_enabled = true;

		// let the child continue
		ptrace(PTRACE_CONT, pid, nullptr, nullptr);

		state.last_action = CONTINUE;

		// wait for the stop at breakpoint
		if (waitpid(pid, &status, 0) == -1) {
			perror("waitpid");
			return 1;
		}

		// Detect child exit
		if (WIFEXITED(status)) {
			cout << "[Debugger] : Child exited with code " << WEXITSTATUS(status) << "\n";
			return 1;
		}

		// Detect breakpoint hit (SIGTRAP) after CONTINUE
		if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
			if (state.last_action == CONTINUE) {
				// possible breakpoint 
				struct user_regs_struct regs;
				ptrace(PTRACE_GETREGS, pid, nullptr, &regs);

				if (regs.rip - 1 == state.breakpoint_addr) {
					cout << "[Debugger] Breakpoint hit at 0x" << hex << state.breakpoint_addr << "\n";
					cout << "RIP = 0x" << regs.rip << "\n";
					cout << "RSP = 0x" << regs.rsp << "\n";
					cout << "RAX = 0x" << regs.rax << "\n";

					// Step back RIP
					regs.rip -= 1;
					ptrace(PTRACE_SETREGS, pid, nullptr, &regs);

					// Restore original instruction byte
					long data = ptrace(PTRACE_PEEKDATA, pid, (void*)state.breakpoint_addr, nullptr);

					long restored = (data & ~0xFF) | original_byte;
					ptrace(PTRACE_POKEDATA, pid, (void*)state.breakpoint_addr, (void*)restored);

					state.breakpoint_enabled = false;
				}
			}
		
			if (state.last_action == SINGLESTEP) {
				long data = ptrace(PTRACE_PEEKDATA, pid,(void*)state.breakpoint_addr, nullptr);

				long patched = (data & ~0xFF) | 0xCC;
				ptrace(PTRACE_POKEDATA, pid, (void*)state.breakpoint_addr, (void*)patched);

				state.breakpoint_addr = true;
				state.last_action = CONTINUE;
			}
		}

	} else {
		perror("fork");
		return 1;
	}
	return 0;
}


