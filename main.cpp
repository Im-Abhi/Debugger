#include <iostream>
#include <string.h>
#include <unistd.h>			// Required for execve()
#include <sys/types.h>
#include <errno.h>

#include <sys/wait.h>		// Required for wait()
#include <sys/ptrace.h>		// Required for ptrace()
#include <sys/user.h>		

using namespace std;

int main(int argc, char *argv[]) {
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

		// const char *args[] = {"ls", "-la", nullptr};
		char *const args[] = {(char *)"./debug", nullptr};
		extern char **environ;

		// rv = execve("/usr/bin/ls", (char *const *)args, nullptr);
		execve("./debug", args, environ);

		// program reaches here only if there was some error in execve
		perror("execve");

		// this terminates the calling process immediately
		_exit(127);
		
	} else if (pid > 0) {
		// parent process (debugger)
		cout << "Executing Parent\n";
		
		// wait for the child’s initial SIGSTOP (pre-exec synchronization)
		int rv = waitpid(pid, &status, 0);
		if (rv == -1) {
			perror("waitpid");
			return 1;
		}

		if (WIFSTOPPED(status)) {
			cout << "Child process initial stopped with signal :" << WSTOPSIG(status) << endl;
		} else if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
			std::cerr << "Unexpected initial stop\n";
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
			std::cerr << "Child did not stop after execve\n";
			return 1;
		}

		// Expect SIGTRAP here
		int sig = WSTOPSIG(status);
		if (sig != SIGTRAP) {
			std::cerr << "Unexpected stop signal after execve: " << sig << "\n";
			return 1;
		}

		int step_count = 0;
		const int max_steps = 50;
		
		while(step_count++ < max_steps) {
            		struct user_regs_struct regs;
            		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {	
                		perror("GETREGS: ");
                		break;
            		}

            		cout << hex << "IP = 0x" << regs.rip << " SP = 0x" << regs.rsp << "\n";
            		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
                		perror("ptrace SINGLESTEP");
                		break;
            		}

			if (waitpid(pid, &status, 0) == -1) {
                		if (errno == EINTR) continue; // retry on interrupt
                		perror("waitpid");
                		break;
            		}

			if (WIFEXITED(status)) {
                		cout << "Child exited with status " << WEXITSTATUS(status) << endl;
                		break;
            		}
            		if (WIFSIGNALED(status)) {
                		cout << "Child terminated by signal " << WTERMSIG(status) << endl;
                		break;
            		}
            		if (!WIFSTOPPED(status)) {
                		break; // no stop to handle
            		}

			if (step_count == 50) {
				ptrace(PTRACE_CONT, pid, NULL, NULL);
				waitpid(pid, &status, 0);
				if (WIFEXITED(status)) {
					cout << "Child terminated by signal " << WTERMSIG(status) << endl;
				}
				break;
			}
		}
	} else {
		perror("fork");
	}
	return 0;
}


