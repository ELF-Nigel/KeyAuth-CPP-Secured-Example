#include <Windows.h>
#include "lib/auth.hpp"
#include "lib/WinSecRuntime/WinSecRuntime.h"
#include "lib/nigelcrypt/nigelcrypt.hpp"
#include "lib/utils.hpp"
#include <chrono>
#include <ctime>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>

using namespace KeyAuth;

namespace {

std::string tm_to_readable_time(std::tm ctx);
std::string remaining_until(const std::string& timestamp);

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

bool run_runtime_security() {
    WinSecRuntime::Policy policy{};
    policy.mode = WinSecRuntime::Mode::Aggressive;
    secure::runtime::Config cfg{};

    cfg.expected_parent_pid = 0;
    cfg.expected_image_path = L"...";
    cfg.require_same_session = false;
    cfg.expected_integrity_rid = 0;
    cfg.cmdline_hash_baseline = 0;
    cfg.cwd_hash_baseline = 0;
    cfg.disallow_unc = false;
    cfg.disallow_motw = false;
    cfg.cwd_allowlist_hashes = nullptr;
    cfg.cwd_allowlist_count = 0;
    cfg.image_path_allowlist_hashes = nullptr;
    cfg.image_path_allowlist_count = 0;
    cfg.enforce_safe_dll_search = false;
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
    cfg.vm_min_cores = 0;
    cfg.vm_min_ram_gb = 0;

    cfg.iat_baseline = 0;
    cfg.import_name_hash_baseline = 0;
    cfg.import_module_hash_baseline = 0;
    cfg.import_module_count_baseline = 0;
    cfg.import_func_count_baseline = 0;

    cfg.iat_write_protect = false;
    cfg.iat_writable_check = false;
    cfg.iat_count_baseline = 0;
    cfg.iat_mirror = nullptr;
    cfg.iat_mirror_count = 0;
    cfg.iat_bounds_check = false;
    cfg.iat_require_executable = false;
    cfg.iat_disallow_self = false;

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

    cfg.nop_sled_threshold = 0;
    cfg.int3_sled_threshold = 0;

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

    policy.cfg = cfg;

    if (!WinSecRuntime::Initialize(policy.mode, policy.cfg))
        return false;

    WinSecRuntime::StartIntegrityEngine(policy);
    const auto report = WinSecRuntime::RunAll(policy);
    return report.ok();
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

    std::string name = nigel_string("name", "app:name");
    std::string ownerid = nigel_string("ownerid", "app:ownerid");
    std::string version = nigel_string("1.0", "app:version");
    std::string url = nigel_string("https://keyauth.win/api/1.3/", "app:url"); // change if you're self-hosting
    std::string path = nigel_string("", "app:path"); // optional, set a path if you're using the token validation setting

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

    std::cout << nc("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ", "ui:menu");

    int option = 0;
    std::string username;
    std::string password;
    std::string key;

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
        app_instance.login(username, password);
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
        app_instance.license(key);
        break;
    default:
        std::cout << nc("\n\n Status: Failure: Invalid Selection", "ui:bad_selection");
        app_instance.bad_input_delay();
        exit(1);
    }

    if (!app_instance.response.success)
    {
        std::cout << nc("\n Status: ", "ui:status") << app_instance.response.message;
        api::record_login_fail(login_guard);
        app_instance.init_fail_delay();
        exit(1);
    }
    api::reset_lockout(login_guard);

    print_user_data(app_instance);

    std::cout << nc("\n\n Closing in five seconds...", "ui:closing");
    app_instance.close_delay();

    return 0;
}

std::string tm_to_readable_time(std::tm ctx) {
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);
    return std::string(buffer);
}

std::string remaining_until(const std::string& timestamp) {
    return api::expiry_remaining(timestamp);
}
