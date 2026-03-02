#include <Windows.h>
#include "lib/auth.hpp"
#include "lib/utils.hpp"
#include "auth_guard.hpp"
#include "lib/WinSecRuntime/WinSecRuntime.h"
#include "lib/nigelcrypt/nigelcrypt.hpp"
#include "storage.hpp"
#include <chrono>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <thread>
#undef max

using namespace KeyAuth;

std::string tm_to_readable_time(std::tm ctx);
std::string remaining_until(const std::string& timestamp);

namespace {

constexpr WinSecRuntime::Mode kSecurityMode = WinSecRuntime::Mode::Paranoid;
constexpr bool kRunPeriodicChecks = true;
constexpr DWORD kPeriodicCheckMs = 15000;

void wipe_string(std::string& value) {
    if (value.empty())
        return;
    SecureZeroMemory(value.data(), value.size());
    value.clear();
    value.shrink_to_fit();
}

std::string nigel_string(const char* literal, std::string_view aad) {
    try {
        nigelcrypt::SecureString s(literal, aad);
        auto view = s.decrypt(aad, nigelcrypt::hardened_decrypt_options());
        return std::string(view.c_str(), view.size());
    } catch (...) {
        return std::string(literal);
    }
}

std::string nc(const char* literal, std::string_view aad) {
    return nigel_string(literal, aad);
}

secure::runtime::Config build_security_config() {
    secure::runtime::Config cfg{};

    cfg.expected_parent_pid = 0;
    cfg.expected_image_path = L"...";
    cfg.require_same_session = false;
    cfg.expected_integrity_rid = 0;
    cfg.cmdline_hash_baseline = 0;
    cfg.cwd_hash_baseline = 0;
    cfg.disallow_unc = true;
    cfg.disallow_motw = true;
    cfg.cwd_allowlist_hashes = nullptr;
    cfg.cwd_allowlist_count = 0;
    cfg.image_path_allowlist_hashes = nullptr;
    cfg.image_path_allowlist_count = 0;
    cfg.enforce_safe_dll_search = true;
    cfg.known_dll_hashes = nullptr;
    cfg.known_dll_count = 0;

    cfg.parent_chain_hashes = nullptr;
    cfg.parent_chain_hash_count = 0;
    cfg.parent_chain_max_depth = 4;

    cfg.module_hashes = nullptr;
    cfg.module_hash_count = 0;

    cfg.module_whitelist_hashes = nullptr;
    cfg.module_whitelist_count = 0;

    cfg.module_list_hash_baseline = 0;
    cfg.module_count_baseline = 0;

    cfg.driver_blacklist_hashes = nullptr;
    cfg.driver_blacklist_count = 0;

    cfg.exec_private_max_regions = 0;
    cfg.enforce_module_path_policy = false;

    cfg.process_hashes = nullptr;
    cfg.process_hash_count = 0;

    cfg.window_hashes = nullptr;
    cfg.window_hash_count = 0;

    cfg.vm_vendor_hashes = nullptr;
    cfg.vm_vendor_hash_count = 0;
    cfg.vm_min_cores = 2;
    cfg.vm_min_ram_gb = 2;

    cfg.iat_baseline = 0;
    cfg.import_name_hash_baseline = 0;
    cfg.import_module_hash_baseline = 0;
    cfg.import_module_count_baseline = 0;
    cfg.import_func_count_baseline = 0;

    cfg.iat_write_protect = true;
    cfg.iat_writable_check = true;
    cfg.iat_count_baseline = 0;
    cfg.iat_mirror = nullptr;
    cfg.iat_mirror_count = 0;
    cfg.iat_bounds_check = true;
    cfg.iat_require_executable = true;
    cfg.iat_disallow_self = true;

    cfg.text_sha256_baseline = {};
    cfg.text_rolling_crc_baseline = 0;
    cfg.text_rolling_crc_window = 64;
    cfg.text_rolling_crc_stride = 16;

    cfg.text_entropy_min = 0.0;
    cfg.text_entropy_max = 0.0;

    cfg.text_chunk_seed = 0;
    cfg.text_chunk_size = 64;
    cfg.text_chunk_count = 32;
    cfg.text_chunk_baseline = 0;

    cfg.nop_sled_threshold = 8;
    cfg.int3_sled_threshold = 8;

    cfg.delay_import_name_hash_baseline = 0;

    cfg.tls_callback_expected = 0;
    cfg.tls_callback_hash_baseline = 0;

    cfg.entry_prologue_size = 16;
    cfg.entry_prologue_baseline = 0;

    cfg.signature_required = false;

    cfg.export_name_hash_baseline = 0;
    cfg.export_rva_hash_baseline = 0;
    cfg.export_name_table_hash_baseline = 0;
    cfg.export_ordinal_table_hash_baseline = 0;
    cfg.export_count_baseline = 0;

    cfg.export_whitelist_hashes = nullptr;
    cfg.export_whitelist_count = 0;

    cfg.export_blacklist_hashes = nullptr;
    cfg.export_blacklist_count = 0;

    cfg.exec_private_whitelist = nullptr;
    cfg.exec_private_whitelist_count = 0;

    cfg.prologue_guards = nullptr;
    cfg.prologue_guard_count = 0;
    cfg.prologue_jmp_forbidden = false;

    return cfg;
}

bool run_runtime_security() {
    WinSecRuntime::Policy policy{};
    policy.mode = kSecurityMode;
    policy.cfg = build_security_config();

    if (!WinSecRuntime::Initialize(policy.mode, policy.cfg))
        return false;

    WinSecRuntime::StartIntegrityEngine(policy);
    WinSecRuntime::EnableAntiDebug(policy);
    WinSecRuntime::EnableHookGuard(policy);
    const auto report = WinSecRuntime::RunAll(policy);
    return report.ok();
}

void start_periodic_security_checks() {
    if (!kRunPeriodicChecks)
        return;

    std::thread([]() {
        while (true) {
            Sleep(kPeriodicCheckMs);
            if (!run_runtime_security()) {
                ExitProcess(0);
            }
        }
    }).detach();
}



bool read_int(int& out) {
    std::cin >> out;
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        return false; // bad input read. -nigel
    }
    return true;
}

char read_choice(char fallback) {
    char choice = fallback;
    std::cin >> choice;
    if (std::cin.fail()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        choice = fallback; // default on bad input. -nigel
    }
    return choice;
}

bool try_auto_login(api& app, std::string& username, std::string& password, std::string& key) {
    if (!std::filesystem::exists(api::kSavePath))
        return false;

    const auto saved_license = ReadFromJson(api::kSavePath, "license");
    const auto saved_username = ReadFromJson(api::kSavePath, "username");
    const auto saved_password = ReadFromJson(api::kSavePath, "password");

    if (!saved_license.empty()) {
        key = saved_license;
        app.license(key);
        return true;
    }

    if (!saved_username.empty() && !saved_password.empty()) {
        username = saved_username;
        password = saved_password;
        app.login(username, password);
        return true;
    }

    return false;
}

void save_or_clear_creds(bool save, const std::string& username, const std::string& password, const std::string& key) {
    if (!save) {
        std::remove(api::kSavePath); // remove stale creds when opting out. -nigel
        return;
    }

    if (username.empty() || password.empty()) {
        WriteToJson(api::kSavePath, "license", key, false, "", "");
        return;
    }

    WriteToJson(api::kSavePath, "username", username, true, "password", password);
}

void print_user_data(const api& app) {
    std::cout << nc("\n User data:", "ui:user_data");
    std::cout << nc("\n Username: ", "ui:username") << app.user_data.username;
    std::cout << nc("\n IP address: ", "ui:ip") << app.user_data.ip;
    std::cout << nc("\n Hardware-Id: ", "ui:hwid") << app.user_data.hwid;
    std::cout << nc("\n Create date: ", "ui:createdate")
              << tm_to_readable_time(utils::timet_to_tm(utils::string_to_timet(app.user_data.createdate)));
    std::cout << nc("\n Last login: ", "ui:lastlogin")
              << tm_to_readable_time(utils::timet_to_tm(utils::string_to_timet(app.user_data.lastlogin)));
    std::cout << nc("\n Subscription(s): ", "ui:subs");

    for (size_t i = 0; i < app.user_data.subscriptions.size(); i++) {
        const auto& sub = app.user_data.subscriptions.at(i);
        std::cout << nc("\n name: ", "ui:sub_name") << sub.name;
        std::cout << nc(" : expiry: ", "ui:sub_expiry")
                  << tm_to_readable_time(utils::timet_to_tm(utils::string_to_timet(sub.expiry)));
        std::cout << nc(" (", "ui:paren_open") << remaining_until(sub.expiry) << nc(")", "ui:paren_close");
    }
}
} // namespace

const std::string compilation_date = nigel_string(__DATE__, "build:date");
const std::string compilation_time = nigel_string(__TIME__, "build:time");
void sessionStatus();

static api* g_app = nullptr;
api::lockout_state login_guard{};

int main()
{
    nigelcrypt::set_policy(nigelcrypt::hardened_policy());
    nigelcrypt::StrictMode strict{};
    strict.enabled = true;
    nigelcrypt::set_strict_mode(strict);

    if (!run_runtime_security()) {
        std::cout << nc("\n\n Security checks failed.", "ui:sec_fail");
        Sleep(1500);
        return 1;
    }
    start_periodic_security_checks();

    // copy and paste from https://keyauth.cc/app/ and replace these string variables
    // Please watch tutorial HERE https://www.youtube.com/watch?v=5x4YkTmFH-U
    std::string name = nigel_string("name", "app:name"); // App name
    std::string ownerid = nigel_string("ownerid", "app:ownerid"); // Account ID
    std::string version = nigel_string("1.0", "app:version"); // Application version. Used for automatic downloads see video here https://www.youtube.com/watch?v=kW195PLCBKs
    std::string url = nigel_string("https://keyauth.win/api/1.3/", "app:url"); // change if using KeyAuth custom domains feature
    std::string path = nigel_string("", "app:path"); // (OPTIONAL) see tutorial here https://www.youtube.com/watch?v=I9rxt821gMk&t=1s

    api app_instance(name, ownerid, version, url, path);
    g_app = &app_instance;

    std::string consoleTitle = nc("Loader - Built at:  ", "ui:title") + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << nc("\n\n Connecting..", "ui:connecting");

    app_instance.init();
    if (!app_instance.response.success)
    {
        std::cout << nc("\n Status: ", "ui:status") << app_instance.response.message;
        app_instance.init_fail_delay();
        exit(1);
    }

    const std::string ownerid_copy = ownerid; // preserve for auth check thread. -nigel
    wipe_string(name);
    wipe_string(ownerid);
    wipe_string(version);
    wipe_string(url);
    wipe_string(path);

    if (api::lockout_active(login_guard)) {
        std::cout << nc("\n Status: Too many attempts. Try again in ", "ui:lockout")
                  << api::lockout_remaining_ms(login_guard) << nc(" ms.", "ui:ms");
        app_instance.close_delay();
        return 0;
    }

    std::string username;
    std::string password;
    std::string key;
    std::string TfaCode;

    const bool used_saved_creds = try_auto_login(app_instance, username, password, key);

    if (!used_saved_creds)
    {
        std::cout << nc("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ", "ui:menu");

        int option = 0;
        if (!read_int(option))
        {
            std::cout << nc("\n\n Status: Failure: Invalid Selection", "ui:bad_selection");
            app_instance.bad_input_delay();
            exit(1);
        }

        switch (option)
        {
        case 1:
            std::cout << nc("\n\n Enter username: ", "ui:enter_user");
            std::cin >> username;
            std::cout << nc("\n Enter password: ", "ui:enter_pass");
            std::cin >> password;
            app_instance.login(username, password, "");
            break;
        case 2:
            std::cout << nc("\n\n Enter username: ", "ui:enter_user");
            std::cin >> username;
            std::cout << nc("\n Enter password: ", "ui:enter_pass");
            std::cin >> password;
            std::cout << nc("\n Enter license: ", "ui:enter_license");
            std::cin >> key;
            app_instance.regstr(username, password, key);
            break;
        case 3:
            std::cout << nc("\n\n Enter username: ", "ui:enter_user");
            std::cin >> username;
            std::cout << nc("\n Enter license: ", "ui:enter_license");
            std::cin >> key;
            app_instance.upgrade(username, key);
            break;
        case 4:
            std::cout << nc("\n Enter license: ", "ui:enter_license");
            std::cin >> key;
            app_instance.license(key, "");
            break;
        default:
            std::cout << nc("\n\n Status: Failure: Invalid Selection", "ui:bad_selection");
            app_instance.bad_input_delay();
            exit(1);
        }
    }

    if (app_instance.response.message.empty())
        exit(11);

    if (!app_instance.response.success)
    {
        const std::string twofa_msg = nc("2FA code required.", "msg:2fa_required");
        if (app_instance.response.message == twofa_msg) {
            if (username.empty() || password.empty()) {
                std::cout << nc("\n Your account has 2FA enabled, please enter 6-digit code:", "ui:2fa_prompt");
                std::cin >> TfaCode;
                app_instance.license(key, TfaCode);
            }
            else {
                std::cout << nc("\n Your account has 2FA enabled, please enter 6-digit code:", "ui:2fa_prompt");
                std::cin >> TfaCode;
                app_instance.login(username, password, TfaCode);
            }

            if (app_instance.response.message.empty())
                exit(11);
            if (!app_instance.response.success) {
                std::cout << nc("\n Status: ", "ui:status") << app_instance.response.message;
                std::remove(api::kSavePath);
                api::record_login_fail(login_guard);
                app_instance.init_fail_delay();
                exit(1);
            }
        }
        else {
            std::cout << nc("\n Status: ", "ui:status") << app_instance.response.message;
            std::remove(api::kSavePath);
            api::record_login_fail(login_guard);
            app_instance.init_fail_delay();
            exit(1);
        }
    }
    api::reset_lockout(login_guard);

    std::cout << nc("\n\n Save credentials to disk for auto-login? [y/N]: ", "ui:save_creds");
    const char save_choice = read_choice('n'); // read once to avoid double input. -nigel
    const bool save_creds = (save_choice == 'y' || save_choice == 'Y');
    save_or_clear_creds(save_creds, username, password, key);
    if (save_creds)
        std::cout << nc("Successfully Created File For Auto Login", "ui:save_ok");

    /*
    * Do NOT remove this checkAuthenticated() function.
    * It protects you from cracking, it would be NOT be a good idea to remove it
    */
    std::thread run(checkAuthenticated, ownerid_copy);
    // do NOT remove checkAuthenticated(), it MUST stay for security reasons
    std::thread check(sessionStatus); // do NOT remove this function either.
    run.detach(); // detach immediately to avoid terminate on early exits. -nigel
    check.detach(); // detach immediately to avoid terminate on early exits. -nigel

    //enable 2FA 
    // KeyAuthApp.enable2fa(); you will need to ask for the code
    //enable 2fa without the need of asking for the code
    //KeyAuthApp.enable2fa().handleInput(KeyAuthApp);

    //disbale 2FA
    // KeyAuthApp.disable2fa();

    if (app_instance.user_data.username.empty())
        exit(10);

    print_user_data(app_instance);

    std::cout << nc("\n\n Status: ", "ui:status") << app_instance.response.message;
    std::cout << nc("\n\n Closing in five seconds...", "ui:closing");
    app_instance.close_delay();

    return 0;
}

void sessionStatus() {
    if (!g_app)
        return;

    g_app->check(true); // do NOT specify true usually, it is slower and will get you blocked from API
    if (!g_app->response.success) {
        return; // allow clean exit from thread. -nigel
    }

    if (g_app->response.isPaid) {
        while (true) {
            Sleep(20000); // this MUST be included or else you get blocked from API
            g_app->check();
            if (!g_app->response.success) {
                return; // allow clean exit from thread. -nigel
            }
        }
    }
}

std::string tm_to_readable_time(std::tm ctx) {
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);
    return std::string(buffer);
}

std::string remaining_until(const std::string& timestamp) {
    return api::expiry_remaining(timestamp);
}
