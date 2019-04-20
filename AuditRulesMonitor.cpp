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
        _op_status->ClearErrorCondition(ErrorCategory::DESIRED_RULES);
    } catch(std::exception& ex) {
        Logger::Error("AuditRulesMonitor: Failed to read desired rules from %s: %s", _audit_rules_dir.c_str(), ex.what());
        _op_status->SetErrorCondition(ErrorCategory::DESIRED_RULES, "Failed to read desired rules from " + _audit_rules_dir + ": " + ex.what());
    }
}

void AuditRulesMonitor::check_file_rules() {
    if (_desired_rules.empty() || !HasAuditdRulesFiles()) {
        _op_status->ClearErrorCondition(ErrorCategory::AUDIT_RULES_FILE);
        return;
    }
    try {
        auto rules = ReadActualAuditdRules(false);
        auto diff = DiffRules(rules, _desired_rules, "");
        if (diff.empty()) {
            _op_status->ClearErrorCondition(ErrorCategory::AUDIT_RULES_FILE);
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
                _op_status->SetErrorCondition(ErrorCategory::AUDIT_RULES_FILE, std::string("augenrules failed: ") + cmd.FailMsg());
            } else {
                Logger::Warn("AuditRulesMonitor: augenrules succeeded");
            }
        }
        _op_status->ClearErrorCondition(ErrorCategory::AUDIT_RULES_FILE);
    } catch (std::exception& ex) {
        Logger::Error("AuditRulesMonitor: Failed to check/update auditd rules: %s", ex.what());
        _op_status->SetErrorCondition(ErrorCategory::AUDIT_RULES_FILE, std::string("Failed to check/update auditd rules: ") + ex.what());
    }
}

bool AuditRulesMonitor::check_kernel_rules() {
    if (_desired_rules.empty()) {
        return true;
    }

    std::vector<AuditRule> rules;
    auto ret = NetlinkRetry([this,&rules]() {
        rules.clear();
        return _netlink.AuditListRules(rules);
    });
    if (ret != 0) {
        Logger::Error("AuditRulesMonitor: Unable to fetch audit rules from kernel: %s", std::strerror(-ret));
        _op_status->SetErrorCondition(ErrorCategory::AUDIT_RULES_KERNEL, std::string("Unable to fetch audit rules from kernel: ") + std::strerror(-ret));
        return false;
    }

    auto diff = DiffRules(rules, _desired_rules, "");
    if (diff.empty()) {
        _op_status->ClearErrorCondition(ErrorCategory::AUDIT_RULES_KERNEL);
        return true;
    }

    uint32_t enabled = 0;
    ret = NetlinkRetry([this,&enabled]() { return _netlink.AuditGetEnabled(enabled); });
    if (ret != 0) {
        Logger::Error("AuditRulesMonitor: Unable to get audit status from kernel: %s", std::strerror(-ret));
        _op_status->SetErrorCondition(ErrorCategory::AUDIT_RULES_KERNEL, std::string("Unable to get audit status from kernel: ") + std::strerror(-ret));
        return false;
    }

    if (enabled == 2) {
        if (!_rules_immutable) {
            Logger::Error("AuditRulesMonitor: Unable to add desired rules because audit rules are set to immutable");
            _op_status->SetErrorCondition(ErrorCategory::AUDIT_RULES_KERNEL, "Unable to add desired rules because audit rules are set to immutable");
            _rules_immutable = true;
        }
        return true;
    } else {
        _rules_immutable = false;
    }

    Logger::Info("AuditRulesMonitor: Found desired audit rules not currently loaded, loading new rules");

    std::unordered_set<std::string> _dset;
    for (auto& rule: _desired_rules) {
        _dset.emplace(rule.CanonicalDiffText());
    }

    bool failed_old = false;
    bool failed_new = false;
    // Delete all old auoms rules
    for (auto& rule: rules) {
        // Delete rule if it has AUOMS_RULE_KEY or matches any of the desired rules.
        if (rule.GetKeys().count(AUOMS_RULE_KEY) > 0 || _dset.count(rule.CanonicalDiffText())) {
            ret = _netlink.AuditDelRule(rule);
            if (ret != 0) {
                Logger::Warn("AuditRulesMonitor: Failed to delete audit rule (%s): %s\n", rule.CanonicalText().c_str(), strerror(-ret));
                failed_old = true;
            }
        }
    }

    // refresh rules list
    ret = NetlinkRetry([this,&rules]() {
        rules.clear();
        return _netlink.AuditListRules(rules);
    });
    if (ret != 0) {
        Logger::Error("AuditRulesMonitor: Unable to fetch audit rules from kernel: %s", std::strerror(-ret));
        _op_status->SetErrorCondition(ErrorCategory::AUDIT_RULES_KERNEL, std::string("Unable to fetch audit rules from kernel: ") + std::strerror(-ret));
        return false;
    }

    // re-diff rules
    diff = DiffRules(rules, _desired_rules, "");
    if (diff.empty()) {
        _op_status->ClearErrorCondition(ErrorCategory::AUDIT_RULES_KERNEL);
        return true;
    }

    // Add diff rules
    for (auto& rule: diff) {
        ret = _netlink.AuditAddRule(rule);
        if (ret != 0) {
            Logger::Warn("AuditRulesMonitor: Failed to load audit rule (%s): %s\n", rule.CanonicalText().c_str(), strerror(-ret));
            failed_new = true;
        }
    }

    if (failed_new && !failed_old) {
        _op_status->SetErrorCondition(ErrorCategory::AUDIT_RULES_KERNEL, "Failed to add new rule(s)");
    } else if (!failed_new && failed_old) {
        _op_status->SetErrorCondition(ErrorCategory::AUDIT_RULES_KERNEL, "Failed to delete old rule(s)");
    } else if (failed_new && failed_old) {
        _op_status->SetErrorCondition(ErrorCategory::AUDIT_RULES_KERNEL, "Failed to delete old rule(s) and failed to add new rule(s)");
    } else {
        _op_status->ClearErrorCondition(ErrorCategory::AUDIT_RULES_KERNEL);
    }

    return true;
}
