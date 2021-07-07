#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/fcntl.h"
#include "user/user.h"

#define PGSIZE 4096

int main(void){
    fprintf(1,"sbrk - allocating memory in PGSIZE\n");
    
    uint64 a,b,c;
    a = (uint64)sbrk(PGSIZE);
    b = (uint64)sbrk(PGSIZE);
    c = (uint64)sbrk(PGSIZE);

    *(int*)a = 1; // writing
    *(int*)b = *(int*)a; // reading
    *(int*)c = *(int*)b + 2; // reading

    fprintf(1,"should print 1,1,3\t%d,%d,%d\n", *(int*)a, *(int*)b, *(int*)c);

    fprintf(1,"allocating memory with sbrk PASSED\n");
    
    char *m1;
    int pid;

    if((pid = fork()) == 0){
        fprintf(1,"in child now\n");
        m1 = malloc(PGSIZE*5);
        m1[PGSIZE] = 1;
        m1[2*PGSIZE] = 'a';
        m1[3*PGSIZE] = 't';
        fprintf(1,"should print 1 : %d\n",m1[PGSIZE]);
        fprintf(1,"should print a : %c\n",m1[2*PGSIZE]);
        fprintf(1,"should print t : %c\n",m1[3*PGSIZE]);

        fprintf(1,"now forktest from usertests.c (may take some time)\n");

        enum{ N = 1000 };
        int n, pid;

        for(n=0; n<N; n++){
            pid = fork();
            if(pid < 0)
            break;
            if(pid == 0)
            exit(0);
        }

        if (n == 0) {
            fprintf(1,"%s: no fork at all!\n");
            exit(1);
        }

        if(n == N){
            fprintf(1,"%s: fork claimed to work 1000 times!\n");
            exit(1);
        }

        for(; n > 0; n--){
            if(wait(0) < 0){
            fprintf(1,"%s: wait stopped early\n");
            exit(1);
            }
        }

        if(wait(0) != -1){
            fprintf(1,"%s: wait got too many\n");
            exit(1);
        }


        fprintf(1,"all tests PASSED\n");

        fprintf(1,"note: I tested NFUA,LAPA,SCFIFO with printings i left in comments - mostly in vm.c\n");

        exit(0);
    } else { // as in "mem" test in usertests.c
        int xstatus;
        wait(&xstatus);
        if(xstatus == -1){ 
        exit(0);
        }
        exit(xstatus);
    }


    exit(0);
    return 0;
}