import re
import csv
import os
from collections import defaultdict

# Function to count requests per IP address
def count_requests_per_ip(log_file):
    ip_request_count = defaultdict(int)  # Using defaultdict to avoid key errors
    with open(log_file, 'r') as f:
        for line in f:
            ip_address = line.split()[0]  # The IP address is the first item in each log entry
            ip_request_count[ip_address] += 1  # Increment the request count for the IP address

    # Sort IP addresses by request count descending order
    sorted_ip_counts = sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True)

    return sorted_ip_counts


# Function to identify the most accessed endpoint
def identify_most_accessed_endpoint(log_file):
    endpoint_access_count = defaultdict(int)  # Default dictionary to count endpoint access

    with open(log_file, 'r') as f:
        for line in f:
            # Use regex to extract the endpoint (URL) from the log line
            # Regex explanation:
            # "GET|POST" matches the HTTP method (either GET or POST)
            # /([^ ]*) captures the endpoint path after the first space (e.g., "/home", "/login")
            match = re.search(r'\"(?:GET|POST) (/[^ ]+)', line)
            if match:
                endpoint = match.group(1)              # The first captured group is the endpoint
                endpoint_access_count[endpoint] += 1   # Increment the count for this endpoint

    # Find most accessed endpoint
    if endpoint_access_count:
        most_accessed = max(endpoint_access_count.items(), key=lambda x: x[1])
        return most_accessed
    else:
        return None, 0     # Return None and 0 if no endpoint is found


#  Function to detect suspicious activity (failed login attempts)
def detect_suspicious_activity(log_file, threshold):
    failed_login_attempts = defaultdict(int)     # Dictionary to count failed login attempts

    with open(log_file, 'r') as f:
        for line in f:
            # Checks for 401 status code or "Invalid credentials" failure message in the log
            # The condition  'POST /login' ensures that we only consider login attempts
            if 'POST /login' in line and ('401' in line or 'Invalid credentials' in line):
                ip_address = line.split()[0]               # Assuming IP is the first field in the log
                failed_login_attempts[ip_address] += 1     # Increment the failed login count for this IP

    # Filter out IPs that exceed the threshold
    suspicious_ips = {ip: count for ip, count in failed_login_attempts.items() if count > threshold}

    return suspicious_ips


# Function to save results to csv
def save_results_to_csv(ip_request_counts, most_accessed_endpoint, suspicious_activity):
    # Create the CSV file and write data
    with open('log_analysis_results.csv', 'w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP section
        writer.writerow(["Requests per IP:"])
        writer.writerow(["="*20])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_request_counts:
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])  # Separator
        writer.writerow(["Most Accessed Endpoint:"])
        writer.writerow(["="*25])
        if most_accessed_endpoint[0]:
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        else:
            writer.writerow(["No endpoint data found."])

        # Write Suspicious Activity section
        writer.writerow([])
        writer.writerow(["Suspicious Activity:"])
        writer.writerow(["=" * 20])
        if suspicious_activity:
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in suspicious_activity.items():
                writer.writerow([ip, count])
        else:
            writer.writerow(["No Suspicious Activity Found."])    # Handle no suspicious activity case


def main(log_file, threshold=10):
    if not os.path.exists(log_file):
        print(f"Error: The log file '{log_file}' does not exist.")
        return

    # Count requests per IP
    ip_request_counts = count_requests_per_ip(log_file)
    print("Requests per IP:")
    print("=" * 20)
    print(f"{'IP Address':<20}{'Request Count'}")
    for ip, count in ip_request_counts:
        print(f"{ip:<20}{count}")

    # Identify the most accessed endpoint
    most_accessed_endpoint = identify_most_accessed_endpoint(log_file)
    print("\nMost Accessed Endpoint:")
    print("=" * 25)
    if most_accessed_endpoint[0]:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    else:
        print("No endpoint data found.")

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(log_file, threshold)

    # Print suspicious activity result
    print("\nSuspicious Activity:")
    print("=" * 29)
    if suspicious_activity:
        print(f"{'IP Address':<20}{'Failed Login Attempts'}")
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20}{count}")
    else:
        print("No Suspicious Activity Found.")  # Handle no suspicious activity case

    # Save results to CSV
    save_results_to_csv(ip_request_counts, most_accessed_endpoint, suspicious_activity)


# Run the script with the provided log file path
if __name__ == '__main__':
    log_file = 'sample.log'   # log_file
    threshold = 10            # Set the threshold for failed login attempts
    main(log_file, threshold)
