//
// Created by tad on 3/18/19.
//

#include "AuditRulesMonitor.h"

#include "Logger.h"
#include "ExecUtil.h"

void AuditRulesMonitor::run() {
    Logger::Info("AuditRulesMonitor: Starting");
    while(!_sleep(1000)) {
        auto now = std::chrono::steady_clock::now();

        if (now - _last_auoms_file_check > std::chrono::seconds(60)) {
            _last_auoms_file_check = now;
            get_desired_rules();
        }

        if (now - _last_audit_file_check > std::chrono::seconds(5*60)) {
            _last_audit_file_check = now;
            check_file_rules();
        }

        if (!check_kernel_rules()) {
            Logger::Error("AuditRulesMonitor: Encountered unrecoverable error, stopping");
            return;
        }
    }
}

void AuditRulesMonitor::on_stop() {

}

void AuditRulesMonitor::get_desired_rules() {
    try {
        auto rules = ReadAuditRulesFromDir(_audit_rules_dir);
        _desired_rules.resize(0);
        for (auto& rule: rules) {
            // Only include the rule in the desired rules if it is supported on the host system
            if (rule.IsSupported()) {
                rule.AddKey(AUOMS_RULE_KEY);
                _desired_rules.emplace_back(rule);
            }
        }
    } catch(std::exception& ex) {
        Logger::Error("AuditRulesMonitor: Failed to read rules from %s: %s", _audit_rules_dir.c_str(), ex.what());
    }
}

void AuditRulesMonitor::check_file_rules() {
    if (_desired_rules.empty()) {
        return;
    }
    try {
        auto rules = ReadActualAuditdRules(false);
        auto diff = DiffRules(rules, _desired_rules, "");
        if (diff.empty()) {
            return;
        }
        Logger::Info("AuditRulesMonitor: Found desired audit rules not currently present in auditd rules files(s), adding new rules");
        // Re-read rules but exclude auoms rules
        rules = ReadActualAuditdRules(true);
        // Re-calculate diff
        diff = DiffRules(rules, _desired_rules, "");
        if (WriteAuditdRules(diff)) {
            Logger::Info("AuditRulesMonitor: augenrules appears to be in-use, running augenrules after updating auoms rules in /etc/audit/rules.d");
            Cmd cmd(AUGENRULES_BIN, {}, Cmd::NULL_STDIN|Cmd::COMBINE_OUTPUT);
            std::string output;
            auto ret = cmd.Run(output);
            if (ret != 0) {
                Logger::Warn("AuditRulesMonitor: augenrules failed: %s", cmd.FailMsg().c_str());
                Logger::Warn("AuditRulesMonitor: augenrules output: %s", output.c_str());
            } else {
                Logger::Warn("AuditRulesMonitor: augenrules succeeded");
            }
        }
    } catch (std::exception& ex) {
        Logger::Error("AuditRulesMonitor: Failed to check/update auditd rules: %s", ex.what());
    }
}

bool AuditRulesMonitor::check_kernel_rules() {
    if (_desired_rules.empty()) {
        return true;
    }

    std::vector<AuditRule> rules;
    auto ret = _netlink.AuditListRules(rules);
    if (ret != 0) {
        Logger::Error("AuditRulesMonitor: Unable to fetch audit rules from kernel: %s", std::strerror(-ret));
        return false;
    }

    auto diff = DiffRules(rules, _desired_rules, "");
    if (diff.empty()) {
        return true;
    }

    Logger::Info("AuditRulesMonitor: Found desired audit rules not currently loaded, loading new rules");

    // Delete all old auoms rules
    for (auto& rule: rules) {
        if (rule.GetKeys().count(AUOMS_RULE_KEY) > 0) {
            ret = _netlink.AuditDelRule(rule);
            if (ret != 0) {
                Logger::Warn("AuditRulesMonitor: Failed to delete audit rule (%s): %s\n", rule.CanonicalText().c_str(), strerror(-ret));
            }
        }
    }

    for (auto& rule: _desired_rules) {
        ret = _netlink.AuditAddRule(rule);
        if (ret != 0) {
            Logger::Warn("AuditRulesMonitor: Failed to load audit rule (%s): %s\n", rule.CanonicalText().c_str(), strerror(-ret));
        }
    }

    return true;
}
