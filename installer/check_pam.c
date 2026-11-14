#include "pam_satsuma.c"
extern int pam_start(const char *,const char *,const struct pam_conv *,pam_handle_t **);
extern int pam_end(pam_handle_t *,int);
static int prompt(int n,const struct pam_message **msg,struct pam_response **out,void *data) {
 (void)data;
 if(n!=1 || msg[0]->msg_style!=PAM_PROMPT_ECHO_OFF)return PAM_CONV_ERR;
 char *pw=getpass(msg[0]->msg);if(!pw)return PAM_CONV_ERR;
 *out=calloc(1,sizeof(**out));if(!*out)return PAM_SYSTEM_ERR;
 (*out)->resp=strdup(pw);wipe(pw,strlen(pw));return (*out)->resp?0:PAM_SYSTEM_ERR;
}
int main(void) {
 struct pam_conv conv={prompt,NULL};pam_handle_t *handle=NULL;
 int rc=pam_start("sudo","root",&conv,&handle);if(rc)return 1;
 rc=pam_sm_acct_mgmt(handle,0,0,NULL);pam_end(handle,rc);
 return rc==0?0:1;
}
