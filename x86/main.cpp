#include <Windows.h>
#include "lib/auth.hpp"
#include "lib/WinSecRuntime/WinSecRuntime.h"
#include "lib/nigelcrypt/nigelcrypt.hpp"
#include "skStr.h"
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

bool run_runtime_security() {
    WinSecRuntime::Policy policy{};
    policy.mode = WinSecRuntime::Mode::Aggressive;

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
    std::cout << skCrypt("\n User data:");
    std::cout << skCrypt("\n Username: ") << app.user_data.username;
    std::cout << skCrypt("\n IP address: ") << app.user_data.ip;
    std::cout << skCrypt("\n Hardware-Id: ") << app.user_data.hwid;
    std::cout << skCrypt("\n Create date: ")
              << tm_to_readable_time(utils::timet_to_tm(utils::string_to_timet(app.user_data.createdate)));
    std::cout << skCrypt("\n Last login: ")
              << tm_to_readable_time(utils::timet_to_tm(utils::string_to_timet(app.user_data.lastlogin)));
    std::cout << skCrypt("\n Subscription(s): ");

    for (size_t i = 0; i < app.user_data.subscriptions.size(); i++) {
        const auto& sub = app.user_data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ")
                  << tm_to_readable_time(utils::timet_to_tm(utils::string_to_timet(sub.expiry)));
        std::cout << skCrypt(" (") << remaining_until(sub.expiry) << skCrypt(")");
    }
}
} // namespace

const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);

static api* g_app = nullptr;
api::lockout_state login_guard{};

int main()
{
    nigelcrypt::set_policy(nigelcrypt::hardened_policy());
    nigelcrypt::StrictMode strict{};
    strict.enabled = true;
    nigelcrypt::set_strict_mode(strict);

    if (!run_runtime_security()) {
        std::cout << skCrypt("\n\n Security checks failed.");
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

    std::string consoleTitle = skCrypt("Loader - Built at:  ").decrypt() + compilation_date + " " + compilation_time;
    SetConsoleTitleA(consoleTitle.c_str());
    std::cout << skCrypt("\n\n Connecting..");

    app_instance.init();
    if (!app_instance.response.success)
    {
        std::cout << skCrypt("\n Status: ") << app_instance.response.message;
        app_instance.init_fail_delay();
        exit(1);
    }

    wipe_string(name);
    wipe_string(ownerid);
    wipe_string(version);
    wipe_string(url);
    wipe_string(path);

    if (api::lockout_active(login_guard)) {
        std::cout << skCrypt("\n Status: Too many attempts. Try again in ")
                  << api::lockout_remaining_ms(login_guard) << skCrypt(" ms.");
        app_instance.close_delay();
        return 0;
    }

    std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

    int option = 0;
    std::string username;
    std::string password;
    std::string key;

    if (!read_int(option))
    {
        std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
        app_instance.bad_input_delay();
        exit(1);
    }

    switch (option)
    {
    case 1:
        std::cout << skCrypt("\n\n Enter username: ");
        std::cin >> username;
        std::cout << skCrypt("\n Enter password: ");
        std::cin >> password;
        app_instance.login(username, password);
        break;
    case 2:
        std::cout << skCrypt("\n\n Enter username: ");
        std::cin >> username;
        std::cout << skCrypt("\n Enter password: ");
        std::cin >> password;
        std::cout << skCrypt("\n Enter license: ");
        std::cin >> key;
        app_instance.regstr(username, password, key);
        break;
    case 3:
        std::cout << skCrypt("\n\n Enter username: ");
        std::cin >> username;
        std::cout << skCrypt("\n Enter license: ");
        std::cin >> key;
        app_instance.upgrade(username, key);
        break;
    case 4:
        std::cout << skCrypt("\n Enter license: ");
        std::cin >> key;
        app_instance.license(key);
        break;
    default:
        std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
        app_instance.bad_input_delay();
        exit(1);
    }

    if (!app_instance.response.success)
    {
        std::cout << skCrypt("\n Status: ") << app_instance.response.message;
        api::record_login_fail(login_guard);
        app_instance.init_fail_delay();
        exit(1);
    }
    api::reset_lockout(login_guard);

    print_user_data(app_instance);

    std::cout << skCrypt("\n\n Closing in five seconds...");
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
