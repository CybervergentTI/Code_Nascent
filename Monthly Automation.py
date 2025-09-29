import re
import csv
from collections import defaultdict
from datetime import datetime
import os
import fitz  # Import PyMuPDF

def parse_report_file(filename, content):
    """Parse a single report file and extract data from all 9 tables by scanning for keywords."""
    week_match = re.search(r'Week (\d+)', filename)
    week_num = int(week_match.group(1)) if week_match else 0

    # print(f"\n--- Parsing file: {filename} (Week {week_num}) ---")
    # print(f"Full content length: {len(content)}") # Log content length for context

    # Initialize the 9 data tables
    data = {
        'Tickets': {},
        'Total Alarms for the Week by Severity': {},
        'Failed Logons': {},
        'Tickets Severity': {},
        'Threats Classification': {},
        'Resolution Matrix': {},
        'Threats Resolution': {},
        'Resolution Time of resolved tickets by severity': {},
        'Severity of Vulnerabilities': {}
    }

    # Define patterns for each data point within the tables
    # More flexible patterns to find numbers associated with keywords anywhere in the text
    data_patterns = {
        'Tickets': {
            'Number of tickets raised for the week': re.compile(r'NUMBER\s+OF\s+TICKETS\s+RAISED\s+FOR THE WEEK.*?(\d+)', re.IGNORECASE | re.DOTALL),
            'Tickets Resolved': re.compile(r'TICKETS\s+RESOLVED.*?(\d+)', re.IGNORECASE | re.DOTALL),
            'Tickets Pending': re.compile(r'TICKETS\s+PENDING.*?(\d+)', re.IGNORECASE | re.DOTALL)
        },
        'Total Alarms for the Week by Severity': {
            'High': re.compile(r'TOTAL ALARMS FOR THE WEEK BY SEVERITY.*?HIGH\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'Medium': re.compile(r'TOTAL ALARMS FOR THE WEEK BY SEVERITY.*?MEDIUM\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'Low': re.compile(r'TOTAL ALARMS FOR THE WEEK BY SEVERITY.*?LOW\s*(\d+)', re.IGNORECASE | re.DOTALL) # Added \s*
        },
        'Failed Logons': {
            'Failed Logon to Default Account': re.compile(r'Failed Logon to Default Account\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'Failed Logon to Disabled Account': re.compile(r'Failed Logon to Disabled Account\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'Failed Logon to Nonexistent Account': re.compile(r'Failed Logon to Nonexistent Account\s*(\d+)', re.IGNORECASE | re.DOTALL) # Added \s*
        },
        'Tickets Severity': {
            'Critical': re.compile(r'TICKETS SEVERITY.*?CRITICAL\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'High': re.compile(r'TICKETS SEVERITY.*?HIGH\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'Medium': re.compile(r'TICKETS SEVERITY.*?MEDIUM\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'Low': re.compile(r'TICKETS SEVERITY.*?LOW\s+(\d+)', re.IGNORECASE | re.DOTALL) # Explicitly match one or more space/newline
        },
        'Threats Classification': {
            # This table requires a different approach as variable names are not fixed keywords
            # We'll handle this separately below
        },
        'Resolution Matrix': {
            'True Positives': re.compile(r'RESOLUTION MATRIX.*?TRUE POSITIVES\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'False Positives': re.compile(r'RESOLUTION MATRIX.*?FALSE POSITIVES\s*(\d+)', re.IGNORECASE | re.DOTALL) # Added \s*
        },
        'Threats Resolution': {
            'Unmitigated Threats': re.compile(r'THREATS RESOLUTION.*?UNMITIGATED THREATS\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'Mitigated Threats': re.compile(r'MITIGATED THREATS\s*(\d+)', re.IGNORECASE | re.DOTALL), # Simplified regex for Mitigated Threats
            'Benign Threats': re.compile(r'THREATS RESOLUTION.*?BENIGN THREATS\s*(\d+)', re.IGNORECASE | re.DOTALL) # Added \s*
        },
        'Resolution Time of resolved tickets by severity': {
             'Critical': re.compile(r'RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY.*?CRITICAL\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
             'High': re.compile(r'RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY.*?HIGH\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
             'Medium': re.compile(r'RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY.*?MEDIUM\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
             'Low': re.compile(r'RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY.*?LOW\s*(\d+)', re.IGNORECASE | re.DOTALL) # Added \s*
        },
        'Severity of Vulnerabilities': {
            'Critical': re.compile(r'SEVERITY OF VULNERABILITIES.*?CRITICAL\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'High': re.compile(r'SEVERITY OF VULNERABILITIES.*?HIGH\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'Medium': re.compile(r'SEVERITY OF VULNERABILITIES.*?MEDIUM\s*(\d+)', re.IGNORECASE | re.DOTALL), # Added \s*
            'Low': re.compile(r'SEVERITY OF VULNERABILITIES.*?LOW\s*(\d+)', re.IGNORECASE | re.DOTALL) # Added \s*
        }
    }

    # Special handling for Threats Classification - variable names and values on separate lines
    threats_classification_section_match = re.search(r'THREATS CLASSIFICATION\s*COUNT(.*?)RESOLUTION MATRIX\s*COUNT', content, re.IGNORECASE | re.DOTALL) # Capture the section text
    if threats_classification_section_match:
        threats_section_text = threats_classification_section_match.group(1).strip() # Get captured text and strip whitespace
        threat_lines = [line.strip() for line in threats_section_text.split('\n') if line.strip()] # Split and remove empty lines
        # print("\nParsing Threats Classification section:")
        threat_name = None
        for line in threat_lines:
             # print(f"  Processing line: {line}")
             # Check if it's a number line
             value_match = re.match(r'^\d+$', line)
             if value_match:
                 if threat_name: # If we have a preceding name
                     value = int(value_match.group(0))
                     data['Threats Classification'][threat_name] = value
                     # print(f"    Extracted (Threats Classification) '{threat_name}': {value}")
                     threat_name = None # Reset name after extracting value
                 # else:
                     # print(f"    Found number '{line}' without preceding threat name. Skipping.")
             else:
                 # Assume it's a threat name line if it's not a number and not empty/header
                 threat_name = line
                 # print(f"    Identified potential threat name: '{threat_name}'")

    # Extract data using the defined patterns for other tables
    for table_name, patterns in data_patterns.items():
        if table_name == 'Threats Classification': # Already handled above
            continue
        # print(f"\nAttempting to extract data for table: {table_name}")
        for variable, pattern in patterns.items():
            match = pattern.search(content)
            # print(f"  Pattern for '{variable}': {pattern.pattern}")
            # Log the text chunk being searched for this pattern to help debug
            # search_start = max(0, content.find(variable) - 50)
            # if match:
            #      search_end = min(len(content), match.end() + 50)
            # else:
            #      search_end = min(len(content), content.find(variable) + len(variable) + 50)
            # print(f"  Searching in text chunk (around '{variable}'): '{content[search_start:search_end]}'")

            # print(f"  Match result for '{variable}': {match}")
            if match:
                try:
                    value = int(match.group(1))
                    data[table_name][variable] = value
                    # print(f"    Extracted '{variable}': {value}")
                except ValueError:
                    pass
                    # print(f"    Could not convert extracted value to int for '{variable}': {match.group(1)}")
            # else:
                # print(f"    Pattern did not match for '{variable}'.")


    return week_num, data

def aggregate_reports(report_files):
    """Aggregate data from multiple report files across all 9 tables."""
    all_data = {}
    week_numbers = []

    # print("\n--- Aggregating Reports ---")
    # Parse all files
    for filename, content in report_files:
        week_num, week_data = parse_report_file(filename, content)
        all_data[week_num] = week_data
        week_numbers.append(week_num)
        # print(f"Aggregated data for Week {week_num}: {week_data}") # Print extracted data for each week


    week_numbers.sort()
    # print(f"Sorted week numbers: {week_numbers}")


    # Initialize aggregated data structure based on expected variables
    aggregated = {
        'Tickets': {var: 0 for var in ['Number of tickets raised for the week', 'Tickets Resolved', 'Tickets Pending']},
        'Total Alarms for the Week by Severity': {var: 0 for var in ['Medium', 'High', 'Low']},
        'Failed Logons': {var: 0 for var in ['Failed Logon to Default Account', 'Failed Logon to Disabled Account', 'Failed Logon to Nonexistent Account']},
        'Tickets Severity': {var: 0 for var in ['Critical', 'High', 'Medium', 'Low']},
        'Threats Classification': {}, # Initialize as empty dict to allow adding new variables
        'Resolution Matrix': {var: 0 for var in ['True Positives', 'False Positives']},
        'Threats Resolution': {var: 0 for var in ['Unmitigated Threats', 'Mitigated Threats', 'Benign Threats']},
        'Resolution Time of resolved tickets by severity': {var: 0 for var in ['Critical', 'High', 'Medium', 'Low']},
        'Severity of Vulnerabilities': {var: 0 for var in ['Critical', 'High', 'Medium', 'Low']}
    }

    # print("\nInitial aggregated structure:", aggregated)

    # Aggregate data across all weeks
    for week_num in week_numbers:
        week_data = all_data[week_num]
        # print(f"\nAggregating Week {week_num} data: {week_data}")
        for table_name, table_data in week_data.items():
            if table_name in aggregated:
                # print(f"  Processing table: {table_name}")
                for variable, value in table_data.items():
                     # print(f"    Aggregating variable '{variable}' with value {value}")
                    # For Threats Classification, add any found variables
                     if table_name == 'Threats Classification':
                         aggregated[table_name][variable] = aggregated[table_name].get(variable, 0) + value
                         # print(f"      Updated aggregated[{table_name}][{variable}]: {aggregated[table_name][variable]}")
                    # For other tables, only aggregate if the variable is expected
                     elif variable in aggregated[table_name]:
                         # Add specific logging for Threats Resolution table
                         # if table_name == 'Threats Resolution':
                         #      print(f"      Aggregating '{variable}': Weekly value = {value}, Current total = {aggregated[table_name][variable]}")
                         aggregated[table_name][variable] += value
                         # if table_name == 'Threats Resolution':
                         #      print(f"      Updated aggregated[{table_name}][{variable}]: {aggregated[table_name][variable]}")
                     # else:
                         # print(f"Warning: Unexpected variable '{variable}' found in table '{table_name}' for Week {week_num}. Skipping aggregation for this variable.")


    # print("\nFinal aggregated data:", aggregated)

    return aggregated, week_numbers, all_data

def generate_csv_report(aggregated_data, week_numbers, all_data):
    """Generate CSV report with aggregated data."""
    csv_rows = []

    # print("\n--- Generating CSV Report ---")
    # Header row
    header = ['Data Table', 'Variable']
    for week in week_numbers:
        header.append(f'Week {week}')
    header.append('Total')
    csv_rows.append(header)
    # print("CSV Header:", header)

    # Process each table
    table_order = [
        'Tickets',
        'Total Alarms for the Week by Severity',
        'Failed Logons',
        'Tickets Severity',
        'Threats Classification',
        'Resolution Matrix',
        'Threats Resolution',
        'Resolution Time of resolved tickets by severity',
        'Severity of Vulnerabilities'
    ]

    for table_name in table_order:
        # print(f"\nProcessing table for CSV: {table_name}")
        if table_name in aggregated_data and aggregated_data[table_name]:
            # Sort variables for consistent output
            # Ensure all variables from individual weeks are included in the sorted list for Threats Classification
            all_variables_in_table = set()
            if table_name == 'Threats Classification':
                 for week_num in week_numbers:
                     week_data = all_data.get(week_num, {})
                     table_data = week_data.get(table_name, {})
                     all_variables_in_table.update(table_data.keys())
                 sorted_variables = sorted(list(all_variables_in_table))
            else:
                sorted_variables = sorted(aggregated_data[table_name].keys())

            # print(f"  Sorted variables for {table_name}: {sorted_variables}")

            for variable in sorted_variables:
                row = [table_name, variable]
                total_value = aggregated_data[table_name].get(variable, 0)
                # print(f"    Processing variable '{variable}' with total value {total_value}")

                # Add weekly values
                for week in week_numbers:
                    week_data = all_data.get(week, {})
                    table_data = week_data.get(table_name, {})
                    week_value = table_data.get(variable, 0)
                    row.append(week_value)
                    # print(f"      Week {week} value for '{variable}': {week_value}")

                # Add total
                row.append(total_value)
                csv_rows.append(row)
                # print(f"    CSV Row for '{variable}': {row}")

            # Add empty row between tables for clarity
            csv_rows.append([''] * len(header))
            # print("Added empty row.")

    return csv_rows

def load_reports_from_files(file_paths):
    """Load report content from file paths using PyMuPDF."""
    report_files = []

    for file_path in file_paths:
        try:
            doc = fitz.open(file_path)
            content = ""
            for page_num in range(doc.page_count):
                page = doc.load_page(page_num)
                content += page.get_text()
            doc.close()

            filename = os.path.basename(file_path)  # Get filename from path
            report_files.append((filename, content))
            # print(f"Loaded: {filename}")

        except FileNotFoundError:
            print(f"File not found: {file_path}")
        except Exception as e:
            print(f"Error loading {file_path}: {str(e)}")

    return report_files

def main():
    """Main function to process reports and generate CSV output."""
    print("Security Reports Aggregator")
    print("=" * 40)

    # Define the path to the "Weekly" folder in Google Drive
    drive_folder_path = '/content/drive/MyDrive/Weekly' # Update this path if your folder is elsewhere

    # Get list of files in the Google Drive folder
    file_paths = []
    try:
        for filename in os.listdir(drive_folder_path):
            if filename.endswith(".pdf"): # Assuming report files are .pdf
                file_paths.append(os.path.join(drive_folder_path, filename))
        # print(f"Found {len(file_paths)} report files in {drive_folder_path}")
    except FileNotFoundError:
        print(f"Error: Folder not found at {drive_folder_path}")
        print("Please make sure the 'Weekly' folder exists in your Google Drive and is spelled correctly.")
        return
    except Exception as e:
        print(f"Error listing files in {drive_folder_path}: {str(e)}")
        return


    if not file_paths:
        print("No report files found in the specified folder. Exiting.")
        return

    # Load reports from file paths
    report_files = load_reports_from_files(file_paths)

    if not report_files:
        print("No report files were successfully loaded. Exiting.")
        return

    # Process the reports
    try:
        aggregated_data, week_numbers, all_data = aggregate_reports(report_files)

        # Generate CSV report rows
        csv_rows = generate_csv_report(aggregated_data, week_numbers, all_data)

        # Print the aggregated data to the output
        print("\nAggregated Data Preview:")
        for row in csv_rows:
            print(row)

        # Define the output path within Google Drive
        output_filename = 'Monthly_Report_Document.csv'
        output_path = os.path.join(drive_folder_path, output_filename) # Save in the same folder

        # Save to CSV file in Google Drive
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(csv_rows)

        print(f"\n✓ Monthly Report Document generated successfully!")
        print(f"✓ Report saved to '{output_path}'")

        # Display summary
        print(f"\nSUMMARY:")
        print(f"- Processed {len(report_files)} weekly reports")
        print(f"- Weeks analyzed: {', '.join(map(str, week_numbers))}")
        print(f"- Total data tables processed: 9")

        # Show key metrics preview
        if 'Tickets' in aggregated_data:
            tickets_data = aggregated_data['Tickets']
            print(f"\nKEY METRICS:")
            print(f"- Total Tickets Raised: {tickets_data.get('Number of tickets raised for the week', 0)}")
            print(f"- Total Tickets Resolved: {tickets_data.get('Tickets Resolved', 0)}")
            print(f"- Total Tickets Pending: {tickets_data.get('Tickets Pending', 0)}")

        if 'Threats Classification' in aggregated_data:
            threats_data = aggregated_data['Threats Classification']
            total_threats = sum(threats_data.values())
            print(f"- Total Threats Detected: {total_threats}")

        if 'Severity of Vulnerabilities' in aggregated_data:
            vuln_data = aggregated_data['Severity of Vulnerabilities']
            total_vulns = sum(vuln_data.values())
            print(f"- Total Vulnerabilities: {vuln_data.get('Critical', 0) + vuln_data.get('High', 0) + vuln_data.get('Medium', 0) + vuln_data.get('Low', 0)}")
            critical_high = vuln_data.get('Critical', 0) + vuln_data.get('High', 0)
            print(f"- Critical/High Vulnerabilities: {critical_high}")

    except Exception as e:
        print(f"Error processing reports: {str(e)}")

if __name__ == "__main__":
    main()
