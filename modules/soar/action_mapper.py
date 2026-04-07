def simulate_action(action, alert):
    src_ip = alert.get("source_ip", "UNKNOWN_IP")
    dst_ip = alert.get("destination_ip", "UNKNOWN_DST")
    user = alert.get("username", "UNKNOWN_USER")

    action_map = {
        "block_ip": f"iptables -A INPUT -s {src_ip} -j DROP",
        "block_external_source_ip": f"iptables -A INPUT -s {src_ip} -j DROP",
        "disable_account": f"usermod -L {user}",
        "isolate_host": f"networkctl isolate {dst_ip}",
        "collect_memory": "volatility -f memory.dump --profile=Win10x64 pslist",
        "log_and_monitor_activity": f"logger 'Monitoring suspicious activity for user {user} from {src_ip}'",
        "review_user_behavior_patterns": f"grep '{user}' output/mapped_alerts.json",
        "flag_account_for_watchlist": f"echo '{user}' >> output/watchlist.txt",
        "identify_files_being_archived": f"grep '{dst_ip}\\|{user}\\|7z.exe' output/mapped_alerts.json",
        "monitor_for_data_exfiltration": f"tcpdump -i any host {src_ip} or host {dst_ip}",
        "isolate_host_if_transfer_detected": f"networkctl isolate {dst_ip}",
        "review_ioc_enrichment": f"grep '{src_ip}\\|{dst_ip}' output/mapped_alerts.json",
        "prioritize_patch_and_isolation": f"echo 'PRIORITY PATCH + ISOLATE {dst_ip}'",
        "expedite_patch_window": f"echo 'EXPEDITE PATCHING FOR {dst_ip}'",
        "escalate_to_ir": f"echo 'ESCALATE TO INCIDENT RESPONSE: {user} {src_ip} -> {dst_ip}'",
    }

    return action_map.get(action, f"manual action required: {action}")
