import os
#import argparse
import datetime
import json
import glob
#import sys
#import collections

'''
    STILL IN DEVELOPMENT
'''

# Glob patterns to parse 
GLOB_PATTERNS = {
    "ffuf": "~/enumeration_results/*/ffuf/*.json",
    "ffuf_params": "~/enumeration_results/*/ffuf_params/*.json"
} 

# Find all files from glob patterns
def find_glob():
    all_files = []

    for name, path in GLOB_PATTERNS.items():
        expand = os.path.expanduser(path)
        matches = glob.glob(expand)
        all_files.extend(matches)
        print(f"{name} Found: {len(matches)} files")

    print(f"\nTotal files found: {len(all_files)}")
    return all_files

def decode_json(file_paths):
    results = {
        "ffuf": [],
        "ffuf_params": [],
        "errors": []
    }
    
    for file in file_paths:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Determine file type based on path
            if '/ffuf_params/' in file:
                results["ffuf_params"].append({
                    "file": file,
                    "data": data
                })
            elif '/ffuf/' in file:
                results["ffuf"].append({
                    "file": file,
                    "data": data
                })
            else:
                print(f"Unknown file type: {file}")
                
        except json.JSONDecodeError as e:
            error_msg = f"JSON decode error in {file}: {e}"
            print(error_msg)
            results["errors"].append(error_msg)
        except FileNotFoundError as e:
            error_msg = f"File not found: {file}"
            print(error_msg)
            results["errors"].append(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error processing {file}: {e}"
            print(error_msg)
            results["errors"].append(error_msg)
    
    print(f"Successfully parsed {len(results['ffuf'])} ffuf files")
    print(f"Successfully parsed {len(results['ffuf_params'])} ffuf_params files")
    if results["errors"]:
        print(f"Encountered {len(results['errors'])} errors")
    
    return results

def parse(objects):
    """
    Process and analyze the parsed JSON objects
    
    Args:
        objects (dict): Dictionary containing parsed ffuf results
    """
    print("\n=== Parsing Results ===")
    
    # Process ffuf results
    if objects["ffuf"]:
        print(f"\nProcessing {len(objects['ffuf'])} ffuf files:")
        for ffuf_result in objects["ffuf"]:
            file = ffuf_result["file"]
            data = ffuf_result["data"]
            
            print(f"\nFile: {os.path.basename(file)}")
            
            # Extract ffuf-specific data
            if "results" in data:
                results = data["results"]
                print(f"  Found {len(results)} results")
                
                # Show sample results (first 5)
                for i, result in enumerate(results[:5]):
                    if "url" in result:
                        status = result.get("status", "N/A")
                        length = result.get("length", "N/A")
                        print(f"    [{i+1}] {result['url']} - Status: {status}, Length: {length}")
                
                if len(results) > 5:
                    print(f"    ... and {len(results) - 5} more results")
    
    # Process ffuf_params results
    if objects["ffuf_params"]:
        print(f"\nProcessing {len(objects['ffuf_params'])} ffuf_params files:")
        for params_result in objects["ffuf_params"]:
            file = params_result["file"]
            data = params_result["data"]
            
            print(f"\nFile: {os.path.basename(file)}")
            
            # Extract parameter-specific data
            if "results" in data:
                results = data["results"]
                print(f"  Found {len(results)} parameter results")
                
                # Show sample results
                for i, result in enumerate(results[:3]):
                    if "url" in result:
                        status = result.get("status", "N/A")
                        print(f"    [{i+1}] {result['url']} - Status: {status}")
    
    # Show errors if any
    if objects["errors"]:
        print(f"\nErrors encountered:")
        for error in objects["errors"]:
            print(f"  - {error}")
    
    return objects

def high_priority(objects):
    
    high_value = {
        "critical": [],      # Admin panels, configs, backups
        "interesting": [],   # API endpoints, uploads, etc.
        "informational": [], # Standard pages, redirects
        "summary": {
            "total_findings": 0,
            "critical_count": 0,
            "interesting_count": 0,
            "informational_count": 0
        }
    }
    
    # Priority scoring patterns
    critical_patterns = [
        "admin", "login", "config", "backup", "database", "db", "sql", 
        "phpmyadmin", "wp-admin", "cpanel", "panel", "control", "manage",
        "password", "passwd", "auth", "secret", "private", "internal",
        "install", "setup", "debug", "test", "dev", "staging"
    ]
    
    interesting_patterns = [
        "api", "upload", "file", "download", "search", "user", "account",
        "profile", "dashboard", "portal", "service", "endpoint", "rest",
        "json", "xml", "export", "import", "report", "log", "stats"
    ]
    
    # Status codes that indicate interesting findings
    critical_status = [200, 302, 307]  # Accessible or redirecting
    interesting_status = [401, 403]    # Forbidden but exists
    
    def calculate_priority(url, status, length):
        url_lower = url.lower()
        score = 0
        category = "informational"
        reasons = []
        
        # Check for critical patterns
        for pattern in critical_patterns:
            if pattern in url_lower:
                score += 10
                category = "critical"
                reasons.append(f"Contains '{pattern}'")
        
        # Check for interesting patterns
        if score < 10:  # Don't double-score
            for pattern in interesting_patterns:
                if pattern in url_lower:
                    score += 5
                    category = "interesting" if category == "informational" else category
                    reasons.append(f"Contains '{pattern}'")
        
        # Status code scoring
        if status in critical_status:
            score += 3
            reasons.append(f"Status {status}")
        elif status in interesting_status:
            score += 2
            reasons.append(f"Protected ({status})")
        
        # Response size analysis
        if length:
            if length > 10000:
                score += 2
                reasons.append("Large response")
            elif length < 100:
                score += 1
                reasons.append("Minimal response")
        
        return score, category, reasons
    
    # Process all ffuf results
    all_findings = []
    
    # Extract from ffuf directory fuzzing
    for ffuf_result in objects.get("ffuf", []):
        if "results" in ffuf_result["data"]:
            for result in ffuf_result["data"]["results"]:
                if "url" in result:
                    score, category, reasons = calculate_priority(
                        result["url"], 
                        result.get("status", 0),
                        result.get("length", 0)
                    )
                    
                    finding = {
                        "url": result["url"],
                        "status": result.get("status"),
                        "length": result.get("length"),
                        "words": result.get("words"),
                        "lines": result.get("lines"),
                        "source_file": os.path.basename(ffuf_result["file"]),
                        "type": "directory_fuzzing",
                        "priority_score": score,
                        "reasons": reasons
                    }
                    
                    all_findings.append((category, finding))
    
    # Extract from ffuf parameter fuzzing
    for params_result in objects.get("ffuf_params", []):
        if "results" in params_result["data"]:
            for result in params_result["data"]["results"]:
                if "url" in result:
                    score, category, reasons = calculate_priority(
                        result["url"],
                        result.get("status", 0),
                        result.get("length", 0)
                    )
                    
                    finding = {
                        "url": result["url"],
                        "status": result.get("status"),
                        "length": result.get("length"),
                        "source_file": os.path.basename(params_result["file"]),
                        "type": "parameter_fuzzing",
                        "priority_score": score,
                        "reasons": reasons
                    }
                    
                    all_findings.append((category, finding))
    
    # Sort findings by priority score within each category
    for category, finding in all_findings:
        high_value[category].append(finding)
        high_value["summary"]["total_findings"] += 1
    
    # Sort each category by priority score (highest first)
    for category in ["critical", "interesting", "informational"]:
        high_value[category].sort(key=lambda x: x["priority_score"], reverse=True)
        high_value["summary"][f"{category}_count"] = len(high_value[category])
    
    # Print summary of high priority findings
    print(f"\n=== High Priority Analysis ===")
    print(f"Critical findings: {high_value['summary']['critical_count']}")
    print(f"Interesting findings: {high_value['summary']['interesting_count']}")
    print(f"Total findings: {high_value['summary']['total_findings']}")
    
    # Show top critical findings
    if high_value["critical"]:
        print(f"\nTop Critical Findings:")
        for i, finding in enumerate(high_value["critical"][:3], 1):
            print(f"  {i}. {finding['url']} (Status: {finding['status']}, Score: {finding['priority_score']})")
            if finding["reasons"]:
                print(f"     Reasons: {', '.join(finding['reasons'])}")
    
    # Show top interesting findings
    if high_value["interesting"]:
        print(f"\nTop Interesting Findings:")
        for i, finding in enumerate(high_value["interesting"][:3], 1):
            print(f"  {i}. {finding['url']} (Status: {finding['status']}, Score: {finding['priority_score']})")
            if finding["reasons"]:
                print(f"     Reasons: {', '.join(finding['reasons'])}")
    
    return high_value

def store_results(objects, high_priority_findings=None, output_dir="~/parsed_results"):
    """
    Store processed results in various formats
    
    Args:
        objects (dict): Dictionary containing parsed results
        high_priority_findings (dict): High priority findings from analysis
        output_dir (str): Directory to save results
    """
    output_dir = os.path.expanduser(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 1. Save raw consolidated JSON (all results in one file)
    consolidated_file = os.path.join(output_dir, f"consolidated_results_{timestamp}.json")
    with open(consolidated_file, 'w') as f:
        json.dump(objects, f, indent=2, default=str)
    print(f"Saved consolidated results: {consolidated_file}")
    
    # 2. Save processed/filtered results as JSON with high priority analysis
    processed_results = {
        "metadata": {
            "timestamp": timestamp,
            "total_ffuf_files": len(objects["ffuf"]),
            "total_ffuf_params_files": len(objects["ffuf_params"]),
            "errors_count": len(objects["errors"])
        },
        "findings": [],
        "high_priority": high_priority_findings if high_priority_findings else {}
    }
    
    # Extract key findings from ffuf results
    for ffuf_result in objects["ffuf"]:
        if "results" in ffuf_result["data"]:
            for result in ffuf_result["data"]["results"]:
                if "url" in result:
                    processed_results["findings"].append({
                        "source_file": os.path.basename(ffuf_result["file"]),
                        "type": "ffuf",
                        "url": result["url"],
                        "status": result.get("status"),
                        "length": result.get("length"),
                        "words": result.get("words"),
                        "lines": result.get("lines")
                    })
    
    # Extract key findings from ffuf_params results
    for params_result in objects["ffuf_params"]:
        if "results" in params_result["data"]:
            for result in params_result["data"]["results"]:
                if "url" in result:
                    processed_results["findings"].append({
                        "source_file": os.path.basename(params_result["file"]),
                        "type": "ffuf_params",
                        "url": result["url"],
                        "status": result.get("status"),
                        "length": result.get("length")
                    })
    
    # Save processed results
    processed_file = os.path.join(output_dir, f"processed_findings_{timestamp}.json")
    with open(processed_file, 'w') as f:
        json.dump(processed_results, f, indent=2, default=str)
    print(f"Saved processed findings: {processed_file}")
    
    # 3. Save high priority findings separately for easy review
    if high_priority_findings:
        priority_file = os.path.join(output_dir, f"high_priority_{timestamp}.json")
        with open(priority_file, 'w') as f:
            json.dump(high_priority_findings, f, indent=2, default=str)
        print(f"Saved high priority analysis: {priority_file}")
    
    # 4. Optional: Save as CSV for easy analysis
    csv_file = os.path.join(output_dir, f"findings_{timestamp}.csv")
    if processed_results["findings"]:
        import csv
        with open(csv_file, 'w', newline='') as f:
            if processed_results["findings"]:
                writer = csv.DictWriter(f, fieldnames=processed_results["findings"][0].keys())
                writer.writeheader()
                writer.writerows(processed_results["findings"])
        print(f"Saved CSV export: {csv_file}")
    
    # 5. Create high-priority CSV for critical findings
    if high_priority_findings and high_priority_findings.get("critical"):
        priority_csv = os.path.join(output_dir, f"critical_findings_{timestamp}.csv")
        import csv
        with open(priority_csv, 'w', newline='') as f:
            fieldnames = ["url", "status", "length", "type", "priority_score", "reasons"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # Write critical findings
            for finding in high_priority_findings["critical"]:
                row = {k: finding.get(k, "") for k in fieldnames}
                row["reasons"] = ", ".join(finding.get("reasons", []))
                writer.writerow(row)
        print(f"Saved critical findings CSV: {priority_csv}")
    
    return {
        "consolidated_file": consolidated_file,
        "processed_file": processed_file,
        "priority_file": priority_file if high_priority_findings else None,
        "csv_file": csv_file if processed_results["findings"] else None,
        "priority_csv": priority_csv if high_priority_findings and high_priority_findings.get("critical") else None
    }

def main():
    file_paths = find_glob()
    if file_paths:
        objects = decode_json(file_paths)
        parsed_results = parse(objects)
        priority_findings = high_priority(parsed_results)
        stored_files = store_results(parsed_results, priority_findings)
        
        print("\n=== Summary ===")
        print("Results have been saved in multiple formats:")
        for file_type, file in stored_files.items():
            if file:
                print(f"  {file_type}: {file}")
                
        print(f"\n=== Quick Stats ===")
        if priority_findings:
            print(f"Critical findings: {priority_findings['summary']['critical_count']}")
            print(f"Interesting findings: {priority_findings['summary']['interesting_count']}")
            print(f"Total findings analyzed: {priority_findings['summary']['total_findings']}")
    else:
        print("No files found to process")

if __name__ == "__main__":
    main()

