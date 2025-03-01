import time
import psutil
import socket
import platform
from colorama import Style, Fore
from app.helpers.genai import get_ai_response_textual
from app.settings.settings import SYSTEM_CAPTURE_DURATION, DEBUG, SYSTEM_CAPTURE_DURATION_INTERVAL


# Logs printer when DEBUG is True
def debug_print(message):
    if DEBUG:
        print(f"{Style.BRIGHT}{Fore.CYAN}DEBUG:{Style.RESET_ALL} {message}")

def check_system_activity():
    """
    Captures 5 seconds of system activity including CPU, memory, network, and process information.
    Analyzes the data for anomalies and returns the results.
    """
    
    # Step 1: Collect initial system data
    print() # For better readability
    print(f"{Style.BRIGHT}{Fore.YELLOW}Collecting system data (5 seconds)...{Style.RESET_ALL}")
    system_data = collect_system_data(duration=SYSTEM_CAPTURE_DURATION)
    
    # Step 2: Analyze the collected data
    print(f"{Style.BRIGHT}{Fore.YELLOW}Analyzing system activity...{Style.RESET_ALL}")
    analysis_results = analyze_system_data(system_data)

    
    # Step 3: Get AI interpretation of the results
    print(f"{Style.BRIGHT}{Fore.YELLOW}Getting AI assessment...{Style.RESET_ALL}")
    debug_print("Requesting AI assessment")
    ai_assessment = get_ai_assessment(system_data, analysis_results)
    debug_print(f"AI assessment received: {len(ai_assessment)} characters")
    
    # Compile and return final results
    final_results = {
        "system_data": system_data,
        "analysis": analysis_results,
        "ai_assessment": ai_assessment,
        "timestamp": time.time()
    }
    
    debug_print("System activity check complete")
    return final_results

def collect_system_data(duration=5):
    
    # Initialize data structure
    system_data = {
        "cpu": [],
        "memory": [],
        "network": {
            "bytes_sent": [],
            "bytes_recv": [],
            "connections": []
        },
        "disk": [],
        "processes": [],
        "system_info": {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "processor": platform.processor(),
            "hostname": socket.gethostname()
        }
    }
     # See the system version and hostname
    debug_print(f"System info: {system_data['system_info']['platform']} on {system_data['system_info']['hostname']}")

    # Collect data at intervals
    interval = SYSTEM_CAPTURE_DURATION_INTERVAL  # seconds
    iterations = int(duration / interval)
    
    # Perform data capture for the specified number of times
    for i in range(iterations):
        debug_print(f"Collecting sample {i+1}/{iterations}")
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=None, percpu=True)
            system_data["cpu"].append(cpu_percent)
            debug_print(f"CPU usage: {sum(cpu_percent)/len(cpu_percent):.1f}% avg across {len(cpu_percent)} cores")
            
            # Memory usage
            memory = psutil.virtual_memory()
            system_data["memory"].append({
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used,
                "free": memory.free
            })
            debug_print(f"Memory usage: {memory.percent:.1f}% ({memory.used/(1024*1024):.1f}MB used)")
            
            # Disk usage
            disk = psutil.disk_usage('/')
            system_data["disk"].append({
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": disk.percent
            })
            debug_print(f"Disk usage: {disk.percent:.1f}% ({disk.used/(1024*1024*1024):.1f}GB used)")
            
            # Network connections
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.raddr:
                    connections.append({
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                        "status": conn.status,
                        "pid": conn.pid
                    })
            system_data["network"]["connections"].append(connections)
            debug_print(f"Active network connections: {len(connections)}")
            
            # Process information (top 10 by CPU usage and memory usage)
            processes = []
            for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username', 'cmdline']), 
                              key=lambda p: p.info['cpu_percent'] + p.info['memory_percent'], 
                              reverse=True)[:10]:
                try:
                    # Get more detailed process information
                    process_info = {
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cpu_percent": proc.info['cpu_percent'],
                        "memory_percent": proc.info['memory_percent'],
                        "username": proc.info['username'],
                        "cmdline": " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                    }
                    
                    # Try to get additional information
                    try:
                        process = psutil.Process(proc.info['pid'])
                        process_info["create_time"] = process.create_time()
                        process_info["status"] = process.status()
                        process_info["threads"] = process.num_threads()
                        process_info["io_counters"] = {
                            "read_count": process.io_counters().read_count if hasattr(process.io_counters(), 'read_count') else 0,
                            "write_count": process.io_counters().write_count if hasattr(process.io_counters(), 'write_count') else 0
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError) as e:
                        debug_print(f"Could not get detailed info for PID {proc.info['pid']}: {str(e)}")
                    
                    processes.append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    debug_print(f"Error accessing process: {str(e)}")
                    pass
            system_data["processes"].append(processes)
            if processes:
                debug_print(f"Top process: {processes[0]['name']} (PID {processes[0]['pid']}) - CPU: {processes[0]['cpu_percent']:.1f}%, Memory: {processes[0]['memory_percent']:.1f}%")
            
        except Exception as e:
            debug_print(f"Error during data collection: {str(e)}")
        
        # Wait for the next interval
        time.sleep(interval)
    
    # Get final network counters
    try:
        if net_io_start:
            net_io_end = psutil.net_io_counters()
            bytes_sent = net_io_end.bytes_sent - net_io_start.bytes_sent
            bytes_recv = net_io_end.bytes_recv - net_io_start.bytes_recv
            system_data["network"]["bytes_sent"].append(bytes_sent)
            system_data["network"]["bytes_recv"].append(bytes_recv)
            debug_print(f"Network activity: {bytes_sent/1024:.1f}KB sent, {bytes_recv/1024:.1f}KB received")
    except Exception as e:
        debug_print(f"Error calculating network traffic: {str(e)}")
    
    debug_print("System data collection complete")
    return system_data

def analyze_system_data(system_data):
    """
    Analyzes the collected system data for anomalies.
    
    Args:
        system_data (dict): Collected system data
        
    Returns:
        dict: Analysis results
    """
    debug_print("Starting system data analysis")
    analysis = {
        "anomalies": [],
        "risk_score": 0,
        "summary": {}
    }
    
    # Analyze CPU usage
    debug_print("Analyzing CPU usage")
    cpu_usage = [sum(cpu)/len(cpu) for cpu in system_data["cpu"]]
    avg_cpu = sum(cpu_usage) / len(cpu_usage)
    analysis["summary"]["avg_cpu_usage"] = avg_cpu
    debug_print(f"Average CPU usage: {avg_cpu:.2f}%")
    
    if avg_cpu > 80:
        analysis["anomalies"].append("High CPU usage detected")
        analysis["risk_score"] += 20
        debug_print("ANOMALY: High CPU usage detected")
    
    # Analyze memory usage
    debug_print("Analyzing memory usage")
    memory_usage = [mem["percent"] for mem in system_data["memory"]]
    avg_memory = sum(memory_usage) / len(memory_usage)
    analysis["summary"]["avg_memory_usage"] = avg_memory
    debug_print(f"Average memory usage: {avg_memory:.2f}%")
    
    if avg_memory > 85:
        analysis["anomalies"].append("High memory usage detected")
        analysis["risk_score"] += 15
        debug_print("ANOMALY: High memory usage detected")
    
    # Analyze network activity
    debug_print("Analyzing network activity")
    total_sent = sum(system_data["network"]["bytes_sent"])
    total_recv = sum(system_data["network"]["bytes_recv"])
    analysis["summary"]["network_bytes_sent"] = total_sent
    analysis["summary"]["network_bytes_recv"] = total_recv
    debug_print(f"Total network traffic: {total_sent/1024:.2f}KB sent, {total_recv/1024:.2f}KB received")
    
    # Check for unusual network traffic (more than 5MB in 5 seconds)
    if total_sent > 5 * 1024 * 1024 or total_recv > 5 * 1024 * 1024:
        analysis["anomalies"].append("Unusually high network traffic detected")
        analysis["risk_score"] += 25
        debug_print("ANOMALY: Unusually high network traffic detected")
    
    # Analyze processes
    debug_print("Analyzing processes")
    suspicious_process_names = ["miner", "cryptominer", "xmrig", "malware", "backdoor"]
    high_cpu_processes = set()
    high_memory_processes = set()
    all_processes_info = []
    
    for process_list in system_data["processes"]:
        for process in process_list:
            # Track high resource processes
            if process["cpu_percent"] > 50:
                high_cpu_processes.add(process["name"])
                debug_print(f"High CPU process: {process['name']} ({process['cpu_percent']:.1f}%)")
            
            if process.get("memory_percent", 0) > 10:
                high_memory_processes.add(process["name"])
                debug_print(f"High memory process: {process['name']} ({process.get('memory_percent', 0):.1f}%)")
            
            # Check for suspicious processes
            for suspicious_name in suspicious_process_names:
                if suspicious_name in process["name"].lower():
                    analysis["anomalies"].append(f"Potentially suspicious process detected: {process['name']}")
                    analysis["risk_score"] += 30
                    debug_print(f"ANOMALY: Suspicious process detected: {process['name']}")
            
            # Add to all processes info list (avoid duplicates by PID)
            if not any(p.get("pid") == process["pid"] for p in all_processes_info):
                all_processes_info.append(process)
    
    # Sort processes by resource usage for the summary
    sorted_processes = sorted(all_processes_info, 
                             key=lambda p: (p.get("cpu_percent", 0) + p.get("memory_percent", 0)), 
                             reverse=True)
    
    analysis["summary"]["high_cpu_processes"] = list(high_cpu_processes)
    analysis["summary"]["high_memory_processes"] = list(high_memory_processes)
    analysis["summary"]["top_resource_processes"] = sorted_processes[:10]  # Top 10 resource-intensive processes
    
    debug_print(f"High CPU processes: {', '.join(list(high_cpu_processes)) if high_cpu_processes else 'None'}")
    debug_print(f"High memory processes: {', '.join(list(high_memory_processes)) if high_memory_processes else 'None'}")
    
    # Set overall risk level
    if analysis["risk_score"] >= 50:
        analysis["risk_level"] = "High"
    elif analysis["risk_score"] >= 25:
        analysis["risk_level"] = "Medium"
    else:
        analysis["risk_level"] = "Low"
    
    debug_print(f"Analysis complete: Risk score {analysis['risk_score']}, Risk level {analysis['risk_level']}")
    debug_print(f"Anomalies detected: {len(analysis['anomalies'])}")
    return analysis

def get_ai_assessment(system_data, analysis_results):
    """
    Gets AI assessment of the system activity data.
    
    Args:
        system_data (dict): Collected system data
        analysis_results (dict): Analysis of the system data
        
    Returns:
        str: AI assessment of the system activity
    """
    debug_print("Preparing AI assessment request")
    # Create a prompt for the AI
    prompt = f"""
    Analyze this system activity data for security concerns:
    
    System Information:
    - Platform: {system_data["system_info"]["platform"]} {system_data["system_info"]["platform_version"]}
    - Processor: {system_data["system_info"]["processor"]}
    
    Activity Summary:
    - Average CPU Usage: {analysis_results["summary"].get("avg_cpu_usage", 0):.2f}%
    - Average Memory Usage: {analysis_results["summary"].get("avg_memory_usage", 0):.2f}%
    - Network Data Sent: {analysis_results["summary"].get("network_bytes_sent", 0) / 1024:.2f} KB
    - Network Data Received: {analysis_results["summary"].get("network_bytes_recv", 0) / 1024:.2f} KB
    - High CPU Processes: {', '.join(analysis_results["summary"].get("high_cpu_processes", []))}
    - High Memory Processes: {', '.join(analysis_results["summary"].get("high_memory_processes", []))}
    
    Top Resource-Intensive Processes:
    {chr(10).join([f"- {p['name']} (PID {p['pid']}): CPU {p.get('cpu_percent', 0):.1f}%, Memory {p.get('memory_percent', 0):.1f}%, User: {p.get('username', 'unknown')}" for p in analysis_results["summary"].get("top_resource_processes", [])[:5]])}
    
    Detected Anomalies:
    {chr(10).join(['- ' + anomaly for anomaly in analysis_results["anomalies"]])}
    
    Risk Score: {analysis_results["risk_score"]}/100
    Risk Level: {analysis_results.get("risk_level", "Unknown")}
    
    Based on this data, provide a security assessment of the system. 
    Give an overall summary like this is the concern
    """
    
    debug_print("Sending prompt to AI service")
    # Get AI analysis
    try:
        ai_assessment = get_ai_response_textual(prompt=prompt)
        print(ai_assessment)
        debug_print(f"AI assessment received ({len(ai_assessment)} characters)")
    except Exception as e:
        debug_print(f"Error getting AI assessment: {str(e)}")
        ai_assessment = "Error obtaining AI assessment. Please check your network connection and try again."
    
    return ai_assessment
