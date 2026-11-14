#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../installer/pam_satsuma.c"
static const char *password;
static int cancel;
static int converse(int n,const struct pam_message **m,struct pam_response **out,void *data) {
 (void)data;
 if(cancel)return PAM_CONV_ERR;
 if(n!=1 || m[0]->msg_style!=PAM_PROMPT_ECHO_OFF)return PAM_CONV_ERR;
 *out=calloc(1,sizeof(**out));(*out)[0].resp=strdup(password);return PAM_SUCCESS;
}
int pam_get_user(pam_handle_t *h,const char **u,const char *p) {(void)h;(void)p;*u="test-user";return 0;}
int pam_get_item(const pam_handle_t *h,int item,const void **v) {
 (void)h;static struct pam_conv c={converse,NULL};if(item!=PAM_CONV)return 1;*v=&c;return 0;
}
int main(void) {
 password="test-only-correct";if(pam_sm_acct_mgmt(NULL,0,0,NULL)!=0)return 1;
 password="wrong";if(pam_sm_acct_mgmt(NULL,0,0,NULL)==0)return 2;
 cancel=1;if(pam_sm_acct_mgmt(NULL,0,0,NULL)==0)return 3;
 puts("PAM conversation: correct accepted, wrong denied, cancel denied; OK");return 0;
}
