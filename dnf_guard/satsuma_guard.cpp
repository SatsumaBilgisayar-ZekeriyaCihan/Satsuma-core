// Satsuma-controlled libdnf5 veto points. No shell, TOFU or automatic URL key import.
#include <libdnf5/base/base.hpp>
#include <libdnf5/base/transaction.hpp>
#include <libdnf5/base/transaction_package.hpp>
#include <libdnf5/plugin/iplugin.hpp>
#include <libdnf5/repo/repo_query.hpp>
#include <libdnf5/repo/config_repo.hpp>
#include <libdnf5/repo/repo_callbacks.hpp>
#include <libdnf5/rpm/package.hpp>
#include <libdnf5/transaction/transaction_item_action.hpp>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <poll.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <stdexcept>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

namespace {
constexpr const char * NAME="satsuma_package_guard";
constexpr libdnf5::PluginAPIVersion API{2,1};
constexpr libdnf5::plugin::Version VERSION{0,1,0};
std::exception_ptr last_exception;
std::string quote(const std::string & value) {
    static constexpr char hex[]="0123456789abcdef";
    std::string out="\"";
    for (unsigned char c:value) {
        if (c=='"' || c=='\\') {out+='\\';out+=static_cast<char>(c);}
        else if(c<32) {out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}
        else out+=static_cast<char>(c);
    }
    return out+'"';
}
void gate(const std::string & request) {
    if(geteuid()!=0) throw std::runtime_error("Satsuma package enforcement requires root");
    if(request.size()>8*1024*1024) throw std::runtime_error("Oversized transaction");
    int input[2],output[2];
    if(pipe(input)) throw std::runtime_error("Cannot create verifier input pipe");
    if(pipe(output)) {close(input[0]);close(input[1]);throw std::runtime_error("Cannot create verifier output pipe");}
    pid_t child=fork();
    if(child==0) {
        dup2(input[0],STDIN_FILENO);dup2(output[1],STDOUT_FILENO);
        close(input[0]);close(input[1]);close(output[0]);close(output[1]);
        syscall(SYS_close_range,3,~0U,0);
        clearenv();setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1);setenv("LC_ALL","C",1);
        execl("/usr/bin/python3","python3","-I","-B","/opt/satsuma-core/installer/package_gate.py",nullptr);
        _exit(127);
    }
    close(input[0]);close(output[1]);
    if(child<0) {close(input[1]);close(output[0]);throw std::runtime_error("Cannot launch package verifier");}
    bool okay=true;
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(300);
    fcntl(input[1],F_SETFL,fcntl(input[1],F_GETFL)|O_NONBLOCK);
    // Block SIGPIPE for the write; a failed helper must not kill DNF without an error.
    sigset_t set,old;sigemptyset(&set);sigaddset(&set,SIGPIPE);sigprocmask(SIG_BLOCK,&set,&old);
    size_t offset=0;
    while(offset<request.size()) {
        ssize_t n=write(input[1],request.data()+offset,request.size()-offset);
        if(n<0 && errno==EINTR) continue;
        if(n<0 && errno==EAGAIN){
            auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
            if(left<=0){okay=false;break;}
            pollfd item{input[1],POLLOUT,0};if(poll(&item,1,static_cast<int>(left))<=0){okay=false;break;}continue;
        }
        if(n<=0) {okay=false;break;}offset+=static_cast<size_t>(n);
    }
    close(input[1]);
    if(!okay) {timespec zero{0,0};sigtimedwait(&set,nullptr,&zero);}
    sigprocmask(SIG_SETMASK,&old,nullptr);
    std::string reply;
    while(okay) {
        auto left=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
        if(left<=0) {okay=false;break;}
        pollfd item{output[0],POLLIN|POLLHUP,0};int rc=poll(&item,1,static_cast<int>(left));
        if(rc<0 && errno==EINTR) continue;
        if(rc<=0) {okay=false;break;}
        char buffer[64];ssize_t n=read(output[0],buffer,sizeof(buffer));
        if(n==0)break;
        if(n<0) {if(errno==EINTR)continue;okay=false;break;}
        reply.append(buffer,static_cast<size_t>(n));
        if(reply.size()>64) {okay=false;break;}
    }
    close(output[0]);int status=0;bool exited=false;
    while(okay && std::chrono::steady_clock::now()<deadline) {
        pid_t result=waitpid(child,&status,WNOHANG);
        if(result==child){exited=true;break;}
        if(result<0 && errno!=EINTR){okay=false;break;}
        usleep(10000);
    }
    if(!exited){kill(child,SIGKILL);while(waitpid(child,&status,0)<0 && errno==EINTR){};okay=false;}
    if(!okay || !WIFEXITED(status) || WEXITSTATUS(status)!=0 || reply!="OK\n")
        throw std::runtime_error("Satsuma denied repository/package verification");
}
class DenyImport final:public libdnf5::repo::RepoCallbacks {
    bool repokey_import(const libdnf5::rpm::KeyInfo &) override {return false;}
};
template<class O,class V> void enforce(O & option,const V & value) {
    option.set(libdnf5::Option::Priority::RUNTIME,value);
    option.lock("Managed by Satsuma package trust policy");
}
class Guard final:public libdnf5::plugin::IPlugin2_1 {
public:
    explicit Guard(libdnf5::plugin::IPluginData & data):IPlugin2_1(data){}
    libdnf5::PluginAPIVersion get_api_version()const noexcept override{return API;}
    const char *get_name()const noexcept override{return NAME;}
    libdnf5::plugin::Version get_version()const noexcept override{return VERSION;}
    const char *const *get_attributes()const noexcept override{static const char * a[]={nullptr};return a;}
    const char *get_attribute(const char *)const noexcept override{return nullptr;}
    void repos_configured()override {
        auto & base=get_base();auto & main=base.get_config();
        enforce(main.get_pkg_gpgcheck_option(),true);enforce(main.get_localpkg_gpgcheck_option(),true);
        enforce(main.get_sslverify_option(),true);enforce(main.get_proxy_sslverify_option(),true);
        enforce(main.get_gpgkey_dns_verification_option(),false);
        // This option is absent on older DNF5 versions. Empty gpgkey + denied callbacks also apply there.
        auto disable_auto=[](libdnf5::Config & config){
            auto & bindings=config.opt_binds();auto it=bindings.find("auto_import_local_keys");
            if(it!=bindings.end())it->second.new_string(libdnf5::Option::Priority::RUNTIME,"0");
        };
        disable_auto(main);
        std::string repos;libdnf5::repo::RepoQuery query(base);query.filter_enabled(true);
        for(auto & repo:query){
            if(repo->get_type()!=libdnf5::repo::Repo::Type::AVAILABLE)continue;
            auto & config=repo->get_config();
            enforce(config.get_pkg_gpgcheck_option(),true);enforce(config.get_repo_gpgcheck_option(),true);
            enforce(config.get_sslverify_option(),true);enforce(config.get_proxy_sslverify_option(),true);enforce(config.get_skip_if_unavailable_option(),false);
            enforce(config.get_gpgkey_option(),std::vector<std::string>{});disable_auto(config);
            repo->set_callbacks(std::make_unique<DenyImport>());
            std::string sources;
            for(const auto & source:config.get_baseurl_option().get_value()){if(!sources.empty())sources+=',';sources+=quote(source);}
            for(const auto * option:{&config.get_metalink_option(),&config.get_mirrorlist_option()}){
                if(option->empty())continue;
                const auto & source=option->get_value();
                if(!source.empty()){if(!sources.empty())sources+=',';sources+=quote(source);}
            }
            if(!repos.empty())repos+=',';
            repos+="{\"id\":"+quote(repo->get_id())+",\"sources\":["+sources+"],\"cachedir\":"+quote(repo->get_cachedir())+'}';
        }
        gate("{\"stage\":\"repositories\",\"repositories\":["+repos+"]}");
    }
    void goal_resolved(const libdnf5::base::Transaction & transaction)override{verify(transaction,"planned");}
    void pre_transaction(const libdnf5::base::Transaction & transaction)override{verify(transaction,"downloaded");}
private:
    void verify(const libdnf5::base::Transaction & transaction,const char * stage){
        std::string packages;
        for(const auto & item:transaction.get_transaction_packages()){
            if(!libdnf5::transaction::transaction_item_action_is_inbound(item.get_action()))continue;
            auto pkg=item.get_package();auto sum=pkg.get_checksum();
            if(!packages.empty())packages+=',';
            packages+="{\"repo\":"+quote(pkg.get_repo_id())+",\"nevra\":"+quote(pkg.get_full_nevra())+
                ",\"algorithm\":"+quote(sum.get_type_str())+",\"checksum\":"+quote(sum.get_checksum())+
                ",\"size\":"+std::to_string(pkg.get_download_size())+",\"path\":"+quote(pkg.get_package_path())+
                ",\"action\":"+quote(item.get_action()==libdnf5::transaction::TransactionItemAction::DOWNGRADE?"downgrade":"inbound")+'}';
        }
        gate(std::string("{\"stage\":")+quote(stage)+",\"packages\":["+packages+"]}");
    }
};
}
extern "C" {
libdnf5::PluginAPIVersion libdnf_plugin_get_api_version(){return API;}
const char *libdnf_plugin_get_name(){return NAME;}
libdnf5::plugin::Version libdnf_plugin_get_version(){return VERSION;}
libdnf5::plugin::IPlugin *libdnf_plugin_new_instance(libdnf5::LibraryVersion,libdnf5::plugin::IPluginData & data,libdnf5::ConfigParser &){
    try{auto api=libdnf5::get_plugin_api_version();if(api.major!=2 || api.minor<1)throw std::runtime_error("Satsuma requires libdnf5 plugin API >= 2.1");return new Guard(data);}
    catch(...){last_exception=std::current_exception();return nullptr;}
}
void libdnf_plugin_delete_instance(libdnf5::plugin::IPlugin * p){delete p;}
std::exception_ptr *libdnf_plugin_get_last_exception(){return &last_exception;}
}
