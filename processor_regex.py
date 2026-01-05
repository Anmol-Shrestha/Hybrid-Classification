import re
def classify_with_regex(log_message):
  regex_patterns = {
    # HTTP Status (Cluster 0)
    r"nova\.(metadata|osapi_compute)\.wsgi\.server .* (RCODE|HTTP status code -|Status code -|Return code:)  ?\d{3} len: \d+ time: .*": "HTTP Status",
    
    # Resource Usage (Clusters 5, 10)
    r"nova\.compute\.(claims|resource_tracker) .* (Total memory|disk limit|Total usable vcpus|Final resource view): .*": "Resource Usage",
    
    # User Action (Clusters 11, 9)
    r"User User\d+ logged (in|out)\.": "User Action",
    r"Account with ID .* created by .*.": "User Action",
    
    # System Notification (Clusters 13, 8, 21, 4, 32, 16)
    r"Backup (started|ended) at .*": "System Notification",
    r"Backup completed successfully.*": "System Notification",
    r"System updated to version \d+\.\d+\.\d+\.": "System Notification",
    r"File .* uploaded successfully by user User\d+\.": "System Notification",
    r"Disk cleanup completed successfully\.": "System Notification",
    r"System reboot initiated by user User\d+\.": "System Notification",
    
    # Security Alert (Clusters 7, 17, 20, 34, 42, 59, 26)
    r".*(incorrect|failed|rejected) login attempts?.*user \d+.*": "Security Alert",
    r".*(Account\d+|secured account).* (unauthorized|unsuccessful|failed|not possible) (login|access).*": "Security Alert",
    r".*(unauthorized|unauthenticated) API access attempt.*user \d+.*": "Security Alert",
    r"Server \d+ experienced potential security incident.*": "Security Alert",
    r"Anomalous activity identified on server \d+.*": "Security Alert",
    r"User \d+ (has )?(escalated|elevated).*admin.*": "Security Alert",
    r".*Admin privilege escalation (alert|threat) for user \d+.*": "Security Alert",
    
    # Critical Error (Clusters 6, 14, 18, 25, 1)
    r".*(Failure|malfunction|not operating).*component ID Component\d+.*": "Critical Error",
    r".*(RAID|disk).* (faults|malfunctions|failures|errors).*": "Critical Error",
    r"(Boot|Kernel) .* (aborted|failure|terminated|crash|interrupted).*": "Critical Error",
    r"System configuration (errors|failure).*": "Critical Error",
    r"(Delivery failure|Mail delivery issue).*email services": "Critical Error",
    
    # Error (Clusters 3, 53, 52, 1)
    r"(Data replication|Shard \d+) .* (failed|unsuccessful|terminated)": "Error",
    r".*module X.*(parse|format|syntax|Invalid).*": "Error",
    r"Service health check .* (SSL certificate|invalid|failed).*": "Error",
    r"Email service experiencing issues.*": "Error"
    }
  for pattern, label in regex_patterns.items():
    if re.search(pattern, log_message, re.IGNORECASE):
      return label
  return None



if __name__ == "__main__":
  print(classify_with_regex("User User123 logged in."))
  print(classify_with_regex("Backup started at 12:00."))
  print(classify_with_regex("Hey Bro "))





  
