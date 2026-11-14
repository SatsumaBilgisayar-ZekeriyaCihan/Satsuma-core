/* Linux-PAM public ABI. No development headers needed; libpam is runtime-provided.
 * A separate account gate runs before sudo command execution, also with cached auth.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <syslog.h>
#include <errno.h>
#include <stdio.h>
typedef struct pam_handle pam_handle_t;
struct pam_message { int msg_style; const char *msg; };
struct pam_response { char *resp; int resp_retcode; };
struct pam_conv { int (*conv)(int,const struct pam_message **,struct pam_response **,void *); void *appdata_ptr; };
extern int pam_get_item(const pam_handle_t *,int,const void **);
extern int pam_get_user(pam_handle_t *,const char **,const char *);
#define PAM_SUCCESS 0
#define PAM_SYSTEM_ERR 4
#define PAM_PERM_DENIED 6
#define PAM_CONV_ERR 19
#define PAM_CONV 5
#define PAM_PROMPT_ECHO_OFF 1
#ifndef PYTHON_PATH
#define PYTHON_PATH "/usr/bin/python3"
#endif
#ifndef HELPER_PATH
#define HELPER_PATH "/opt/satsuma-core/installer/admin_auth.py"
#endif
static void wipe(char *p,size_t n) { volatile char *v=p; while(n--) *v++=0; }
int pam_sm_acct_mgmt(pam_handle_t *pamh,int flags,int argc,const char **argv) {
    (void)flags;(void)argc;(void)argv;
    const struct pam_conv *conv=NULL; const char *user=NULL;
    if(pam_get_user(pamh,&user,NULL)!=PAM_SUCCESS || !user) return PAM_PERM_DENIED;
    if(pam_get_item(pamh,PAM_CONV,(const void **)&conv)!=PAM_SUCCESS || !conv) return PAM_CONV_ERR;
    struct pam_message msg={PAM_PROMPT_ECHO_OFF,"Satsuma yonetici onayi (bu sudo cagrisi): "};
    const struct pam_message *mp=&msg; struct pam_response *resp=NULL;
    int rc=conv->conv(1,&mp,&resp,conv->appdata_ptr);
    if(rc!=PAM_SUCCESS || !resp || !resp->resp) { if(resp)free(resp); return PAM_PERM_DENIED; }
    size_t len=strnlen(resp->resp,1025);
    if(len==0 || len>1024) {wipe(resp->resp,len);free(resp->resp);free(resp);return PAM_PERM_DENIED;}
    int fds[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,fds)) {wipe(resp->resp,len);free(resp->resp);free(resp);return PAM_SYSTEM_ERR;}
    pid_t pid=fork();
    if(pid==0) {
        close(fds[1]);if(dup2(fds[0],0)<0)_exit(126);close(fds[0]);
        if(setuid(0)!=0)_exit(126);
        alarm(15);
        char *env[]={"PATH=/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8",NULL};
        char *args[]={PYTHON_PATH,"-I","-B",HELPER_PATH,"verify",(char *)user,NULL};
        execve(PYTHON_PATH,args,env);_exit(127);
    }
    close(fds[0]);
    /* Single short pipe write; child reads before evaluating the password. */
    ssize_t wrote=-1;if(pid>0)wrote=send(fds[1],resp->resp,len,MSG_NOSIGNAL);
    close(fds[1]);wipe(resp->resp,len);free(resp->resp);free(resp);
    if(pid<0)return PAM_SYSTEM_ERR;
    int status=0;while(waitpid(pid,&status,0)<0) {if(errno!=EINTR)return PAM_SYSTEM_ERR;}
    int ok=wrote==(ssize_t)len && WIFEXITED(status) && WEXITSTATUS(status)==0;
    syslog(LOG_AUTHPRIV|LOG_NOTICE,"Satsuma sudo approval user=%s result=%s",user,ok?"allowed":"denied");
    return ok?PAM_SUCCESS:PAM_PERM_DENIED;
}
