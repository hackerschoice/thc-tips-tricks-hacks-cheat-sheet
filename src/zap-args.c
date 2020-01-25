/*
 * gcc -Wall -O2 -fpic -shared -o zap-args.so zap-args.c -ldl
 *
 * LD_PRELOAD=./zap-args.so exec -a syslogd nmap -T0 10.0.0.1/24
 */
#define _GNU_SOURCE 
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>

typedef int (*pfi)(int, char **, char **);
static pfi real_main;

/*
 * Copy original argv to new location and delete original location
 * so that 'ps alxww' wont have anything to display.
 */
char **copyargs(int argc, char** argv){
    char **newargv = malloc((argc+1)*sizeof(*argv));
    char *from,*to;
    int i,len;

    for(i = 0; i<argc; i++){
        from = argv[i];
        len = strlen(from)+1;
        to = malloc(len);
        memcpy(to,from,len);
	// Zap the old args but not the programm name
	if (i >= 1)
	        memset(from,'\0',len);
        newargv[i] = to;
        argv[i] = 0;
    }
    newargv[argc] = 0;
    return newargv;
}

static int mymain(int argc, char** argv, char** env) {
    return real_main(argc, copyargs(argc,argv), env);
}

int __libc_start_main(pfi main, int argc,
                      char **ubp_av, void (*init) (void),
                      void (*fini)(void),
                      void (*rtld_fini)(void), void (*stack_end)){
    static int (*real___libc_start_main)() = NULL;

    if (!real___libc_start_main) {
        char *error;
        real___libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
        if ((error = dlerror()) != NULL) {
            fprintf(stderr, "%s\n", error);
            exit(1);
        }
    }
    real_main = main;
    return real___libc_start_main(mymain, argc, ubp_av, init, fini,
            rtld_fini, stack_end);
}

