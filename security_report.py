from collections import Counter
from datetime import datetime


LOG_FILE = "security_events.log"
REPORT_FILE = "security_report.txt"


def read_events():
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"Error: {LOG_FILE} was not found.")
        return []


def analyze_events(events):
    failed_logins = 0
    successful_logins = 0
    event_types = Counter()
    source_ips = Counter()

    for event in events:
        parts = event.split()

        if "FAILED_LOGIN" in event:
            failed_logins += 1

        if "LOGIN_SUCCESS" in event:
            successful_logins += 1

        for part in parts:
            if part.startswith("EVENT="):
                event_types[part.split("=", 1)[1]] += 1

            if part.startswith("IP="):
                source_ips[part.split("=", 1)[1]] += 1

    return failed_logins, successful_logins, event_types, source_ips


def create_report(failed, successful, event_types, source_ips):
    total_events = failed + successful

    if failed >= 5:
        risk_level = "HIGH"
    elif failed >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    report = []

    report.append("AUTOMATED SECURITY REPORT")
    report.append("=" * 40)
    report.append(
        "Generated: "
        + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    report.append("")

    report.append("SUMMARY")
    report.append("-" * 40)
    report.append(f"Total login events: {total_events}")
    report.append(f"Successful logins: {successful}")
    report.append(f"Failed logins: {failed}")
    report.append(f"Risk level: {risk_level}")
    report.append("")

    report.append("EVENT TYPES")
    report.append("-" * 40)

    for event, count in event_types.items():
        report.append(f"{event}: {count}")

    report.append("")
    report.append("SOURCE IP ACTIVITY")
    report.append("-" * 40)

    for ip, count in source_ips.most_common():
        report.append(f"{ip}: {count} event(s)")

    report.append("")
    report.append("RECOMMENDATION")
    report.append("-" * 40)

    if risk_level == "HIGH":
        report.append(
            "Review failed login activity and investigate repeated attempts."
        )
    elif risk_level == "MEDIUM":
        report.append(
            "Monitor authentication activity for repeated failures."
        )
    else:
        report.append(
            "No significant login risk was detected in the sample data."
        )

    return "\n".join(report)


def main():
    events = read_events()

    if not events:
        return

    failed, successful, event_types, source_ips = analyze_events(events)

    report = create_report(
        failed,
        successful,
        event_types,
        source_ips
    )

    print(report)

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        file.write(report)

    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
