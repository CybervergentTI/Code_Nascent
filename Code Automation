import re
from collections import defaultdict
from datetime import datetime
def parse_report_file(filename, content):
"""Parse a single report file and extract data from all 9 tables."""
week_match = re.search(r'Week (\d+)', filename)
week_num = int(week_match.group(1)) if week_match else 0
# Initialize the 9 data tables
data = {
'Tickets': {},
'Total Alarms for the Week by Severity': {},
'Failed Logons': {},
'Tickets Severity': {},
'Threats Classification': {},
'Resolution Matrix': {},
'Threats Resolution': {},
'Resolution Time of Resolved Tickets by Severity': {},
'Severity of Vulnerabilities': {}
}
lines = content.strip().split('\n')
current_table = None
i = 0
while i < len(lines):
line = lines[i].strip()
# Identify table headers
if 'TICKETS COUNT' in line:
current_table = 'Tickets'
i += 1
# Parse tickets data
while i < len(lines) and lines[i].strip() and 'TOTAL ALARMS' not in lines[i]:
parse_line = lines[i].strip()
if 'NUMBER OF TICKETS RAISED FOR THE WEEK' in parse_line:
value = int(parse_line.split()[-1])
data['Tickets']['Number of Tickets Raised for the Week'] = value
elif 'TICKETS RESOLVED' in parse_line:
value = int(parse_line.split()[-1])
data['Tickets']['Tickets Resolved'] = value
elif 'TICKETS PENDING' in parse_line:
value = int(parse_line.split()[-1])
data['Tickets']['Tickets Pending'] = value
i += 1
continue
elif 'TOTAL ALARMS FOR THE WEEK BY SEVERITY COUNT' in line:
current_table = 'Total Alarms for the Week by Severity'
i += 1
# Parse alarms data
while i < len(lines) and lines[i].strip() and 'FAILED LOGONS' not in lines[i]:
parse_line = lines[i].strip()
if parse_line.startswith('HIGH'):
value = int(parse_line.split()[-1])
data['Total Alarms for the Week by Severity']['High'] = value
elif parse_line.startswith('MEDIUM'):
value = int(parse_line.split()[-1])
data['Total Alarms for the Week by Severity']['Medium'] = value
elif parse_line.startswith('LOW'):
value = int(parse_line.split()[-1])
data['Total Alarms for the Week by Severity']['Low'] = value
i += 1
continue
elif 'FAILED LOGONS COUNT' in line:
current_table = 'Failed Logons'
i += 1
# Parse failed logons data
while i < len(lines) and lines[i].strip() and 'DATA TABLES' not in lines[i]:
parse_line = lines[i].strip()
if 'Failed Logon to Default Account' in parse_line:
value = int(parse_line.split()[-1])
data['Failed Logons']['Failed Logon to Default Account'] = value
elif 'Failed Logon to Disabled Account' in parse_line:
value = int(parse_line.split()[-1])
data['Failed Logons']['Failed Logon to Disabled Account'] = value
elif 'Failed Logon to Nonexistent Account' in parse_line:
value = int(parse_line.split()[-1])
data['Failed Logons']['Failed Logon to Nonexistent Account'] = value
i += 1
continue
elif 'TICKETS SEVERITY COUNT' in line:
current_table = 'Tickets Severity'
i += 1
# Parse ticket severity data
while i < len(lines) and lines[i].strip() and 'THREATS CLASSIFICATION' not in
lines[i]:
parse_line = lines[i].strip()
if parse_line.startswith('CRITICAL'):
value = int(parse_line.split()[-1])
data['Tickets Severity']['Critical'] = value
elif parse_line.startswith('HIGH'):
value = int(parse_line.split()[-1])
data['Tickets Severity']['High'] = value
elif parse_line.startswith('MEDIUM'):
value = int(parse_line.split()[-1])
data['Tickets Severity']['Medium'] = value
elif parse_line.startswith('LOW'):
value = int(parse_line.split()[-1])
data['Tickets Severity']['Low'] = value
i += 1
continue
elif 'THREATS CLASSIFICATION COUNT' in line:
current_table = 'Threats Classification'
i += 1
# Parse threats classification data
while i < len(lines) and lines[i].strip() and 'RESOLUTION MATRIX' not in lines[i]:
parse_line = lines[i].strip()
parts = parse_line.split()
if len(parts) >= 2:
try:
value = int(parts[-1])
key = ' '.join(parts[:-1])
data['Threats Classification'][key] = value
except ValueError:
pass
i += 1
continue
elif 'RESOLUTION MATRIX COUNT' in line:
current_table = 'Resolution Matrix'
i += 1
# Parse resolution matrix data
while i < len(lines) and lines[i].strip() and 'THREATS RESOLUTION' not in lines[i]:
parse_line = lines[i].strip()
if 'TRUE POSITIVES' in parse_line:
value = int(parse_line.split()[-1])
data['Resolution Matrix']['True Positives'] = value
elif 'FALSE POSITIVES' in parse_line:
value = int(parse_line.split()[-1])
data['Resolution Matrix']['False Positives'] = value
i += 1
continue
elif 'THREATS RESOLUTION COUNT' in line:
current_table = 'Threats Resolution'
i += 1
# Parse threats resolution data
while i < len(lines) and lines[i].strip() and 'RESOLUTION TIME' not in lines[i]:
parse_line = lines[i].strip()
if 'UNMITIGATED THREATS' in parse_line:
value = int(parse_line.split()[-1])
data['Threats Resolution']['Unmitigated Threats'] = value
elif 'MITIGATED THREATS' in parse_line:
value = int(parse_line.split()[-1])
data['Threats Resolution']['Mitigated Threats'] = value
elif 'BENIGN THREATS' in parse_line:
value = int(parse_line.split()[-1])
data['Threats Resolution']['Benign Threats'] = value
i += 1
continue
elif 'RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY COUNT' in line:
current_table = 'Resolution Time of Resolved Tickets by Severity'
i += 1
# Parse resolution time data
while i < len(lines) and lines[i].strip() and 'SEVERITY OF VULNERABILITIES' not in
lines[i]:
parse_line = lines[i].strip()
if parse_line.startswith('CRITICAL'):
value = int(parse_line.split()[-1])
data['Resolution Time of Resolved Tickets by Severity']['Critical'] = value
elif parse_line.startswith('HIGH'):
value = int(parse_line.split()[-1])
data['Resolution Time of Resolved Tickets by Severity']['High'] = value
elif parse_line.startswith('MEDIUM'):
value = int(parse_line.split()[-1])
data['Resolution Time of Resolved Tickets by Severity']['Medium'] = value
elif parse_line.startswith('LOW'):
value = int(parse_line.split()[-1])
data['Resolution Time of Resolved Tickets by Severity']['Low'] = value
i += 1
continue
elif 'SEVERITY OF VULNERABILITIES COUNT' in line:
current_table = 'Severity of Vulnerabilities'
i += 1
# Parse vulnerability severity data
while i < len(lines):
parse_line = lines[i].strip()
if not parse_line:
break
if parse_line.startswith('CRITICAL'):
value = int(parse_line.split()[-1])
data['Severity of Vulnerabilities']['Critical'] = value
elif parse_line.startswith('HIGH'):
value = int(parse_line.split()[-1])
data['Severity of Vulnerabilities']['High'] = value
elif parse_line.startswith('MEDIUM'):
value = int(parse_line.split()[-1])
data['Severity of Vulnerabilities']['Medium'] = value
elif parse_line.startswith('LOW'):
value = int(parse_line.split()[-1])
data['Severity of Vulnerabilities']['Low'] = value
i += 1
break
i += 1
return week_num, data
def aggregate_reports(report_files):
"""Aggregate data from multiple report files across all 9 tables."""
all_data = {}
week_numbers = []
# Parse all files
for filename, content in report_files:
week_num, week_data = parse_report_file(filename, content)
all_data[week_num] = week_data
week_numbers.append(week_num)
week_numbers.sort()
# Initialize aggregated data structure
aggregated = {
'Tickets': defaultdict(int),
'Total Alarms for the Week by Severity': defaultdict(int),
'Failed Logons': defaultdict(int),
'Tickets Severity': defaultdict(int),
'Threats Classification': defaultdict(int),
'Resolution Matrix': defaultdict(int),
'Threats Resolution': defaultdict(int),
'Resolution Time of Resolved Tickets by Severity': defaultdict(int),
'Severity of Vulnerabilities': defaultdict(int)
}
# Aggregate data across all weeks
for week_num in week_numbers:
week_data = all_data[week_num]
for table_name, table_data in week_data.items():
for variable, value in table_data.items():
aggregated[table_name][variable] += value
# Convert defaultdicts to regular dicts
for table_name in aggregated:
aggregated[table_name] = dict(aggregated[table_name])
return aggregated, week_numbers, all_data
def generate_csv_report(aggregated_data, week_numbers, all_data):
"""Generate a CSV report in the same structure as the input files."""
import csv
import io
# Create CSV content
csv_rows = []
# TICKETS COUNT section
csv_rows.append(['TICKETS COUNT'])
tickets_data = aggregated_data.get('Tickets', {})
csv_rows.append(['NUMBER OF TICKETS RAISED FOR THE MONTH',
tickets_data.get('Number of Tickets Raised for the Week', 0)])
csv_rows.append(['TICKETS RESOLVED', tickets_data.get('Tickets Resolved', 0)])
csv_rows.append(['TICKETS PENDING', tickets_data.get('Tickets Pending', 0)])
csv_rows.append([]) # Empty row for spacing
# TOTAL ALARMS FOR THE MONTH BY SEVERITY COUNT section
csv_rows.append(['TOTAL ALARMS FOR THE MONTH BY SEVERITY COUNT'])
alarms_data = aggregated_data.get('Total Alarms for the Week by Severity', {})
csv_rows.append(['HIGH', alarms_data.get('High', 0)])
csv_rows.append(['MEDIUM', alarms_data.get('Medium', 0)])
csv_rows.append(['LOW', alarms_data.get('Low', 0)])
csv_rows.append([]) # Empty row for spacing
# FAILED LOGONS COUNT section
csv_rows.append(['FAILED LOGONS COUNT'])
logons_data = aggregated_data.get('Failed Logons', {})
csv_rows.append(['Failed Logon to Default Account', logons_data.get('Failed Logon to 
Default Account', 0)])
csv_rows.append(['Failed Logon to Disabled Account', logons_data.get('Failed Logon 
to Disabled Account', 0)])
csv_rows.append(['Failed Logon to Nonexistent Account', logons_data.get('Failed 
Logon to Nonexistent Account', 0)])
csv_rows.append([]) # Empty row for spacing
# TICKETS SEVERITY COUNT section
csv_rows.append(['TICKETS SEVERITY COUNT'])
ticket_severity_data = aggregated_data.get('Tickets Severity', {})
csv_rows.append(['CRITICAL', ticket_severity_data.get('Critical', 0)])
csv_rows.append(['HIGH', ticket_severity_data.get('High', 0)])
csv_rows.append(['MEDIUM', ticket_severity_data.get('Medium', 0)])
csv_rows.append(['LOW', ticket_severity_data.get('Low', 0)])
csv_rows.append([]) # Empty row for spacing
# THREATS CLASSIFICATION COUNT section
csv_rows.append(['THREATS CLASSIFICATION COUNT'])
threats_data = aggregated_data.get('Threats Classification', {})
# Sort threat types for consistent output
for threat_type in sorted(threats_data.keys()):
csv_rows.append([threat_type, threats_data[threat_type]])
csv_rows.append([]) # Empty row for spacing
# RESOLUTION MATRIX COUNT section
csv_rows.append(['RESOLUTION MATRIX COUNT'])
resolution_matrix_data = aggregated_data.get('Resolution Matrix', {})
csv_rows.append(['TRUE POSITIVES', resolution_matrix_data.get('True Positives', 0)])
csv_rows.append(['FALSE POSITIVES', resolution_matrix_data.get('False Positives', 0)])
csv_rows.append([]) # Empty row for spacing
# THREATS RESOLUTION COUNT section
csv_rows.append(['THREATS RESOLUTION COUNT'])
threats_resolution_data = aggregated_data.get('Threats Resolution', {})
csv_rows.append(['UNMITIGATED THREATS',
threats_resolution_data.get('Unmitigated Threats', 0)])
csv_rows.append(['MITIGATED THREATS', threats_resolution_data.get('Mitigated 
Threats', 0)])
csv_rows.append(['BENIGN THREATS', threats_resolution_data.get('Benign Threats',
0)])
csv_rows.append([]) # Empty row for spacing
# RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY COUNT section
csv_rows.append(['RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY COUNT'])
resolution_time_data = aggregated_data.get('Resolution Time of Resolved Tickets by 
Severity', {})
csv_rows.append(['CRITICAL', resolution_time_data.get('Critical', 0)])
csv_rows.append(['HIGH', resolution_time_data.get('High', 0)])
csv_rows.append(['MEDIUM', resolution_time_data.get('Medium', 0)])
csv_rows.append(['LOW', resolution_time_data.get('Low', 0)])
csv_rows.append([]) # Empty row for spacing
# SEVERITY OF VULNERABILITIES COUNT section
csv_rows.append(['SEVERITY OF VULNERABILITIES COUNT'])
vulnerability_data = aggregated_data.get('Severity of Vulnerabilities', {})
csv_rows.append(['CRITICAL', vulnerability_data.get('Critical', 0)])
csv_rows.append(['HIGH', vulnerability_data.get('High', 0)])
csv_rows.append(['MEDIUM', vulnerability_data.get('Medium', 0)])
csv_rows.append(['LOW', vulnerability_data.get('Low', 0)])
return csv_rows
# Main execution
def main():
# Define the report files with their content
report_files = [
("Week 1.pdf", """TICKETS COUNT
NUMBER OF TICKETS RAISED FOR THE WEEK 2
TICKETS RESOLVED 1
TICKETS PENDING 1
TOTAL ALARMS FOR THE WEEK BY SEVERITY COUNT
HIGH 0
MEDIUM 0
LOW 0
FAILED LOGONS COUNT
Failed Logon to Default Account 0
Failed Logon to Disabled Account 0
Failed Logon to Nonexistent Account 0
DATA TABLES
TICKETS SEVERITY COUNT
CRITICAL 0
HIGH 0
MEDIUM 0
LOW 2
THREATS CLASSIFICATION COUNT
Malware 9
Exploit 3
Hacktool 2
RESOLUTION MATRIX COUNT
TRUE POSITIVES 0
FALSE POSITIVES 0
THREATS RESOLUTION COUNT
UNMITIGATED THREATS 1
MITIGATED THREATS 13
BENIGN THREATS 0
RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY COUNT
CRITICAL 0
HIGH 0
MEDIUM 0
LOW 7
SEVERITY OF VULNERABILITIES COUNT
CRITICAL 0
HIGH 24
MEDIUM 564
LOW 100"""),
("Week 2.pdf", """TICKETS COUNT
NUMBER OF TICKETS RAISED FOR THE WEEK 2
TICKETS RESOLVED 0
TICKETS PENDING 2
TOTAL ALARMS FOR THE WEEK BY SEVERITY COUNT
HIGH 0
MEDIUM 0
LOW 0
FAILED LOGONS COUNT
Failed Logon to Default Account 0
Failed Logon to Disabled Account 0
Failed Logon to Nonexistent Account 1
DATA TABLES
TICKETS SEVERITY COUNT
CRITICAL 0
HIGH 0
MEDIUM 0
LOW 2
THREATS CLASSIFICATION COUNT
Malware 3
Exploit 0
Hacktool 0
RESOLUTION MATRIX COUNT
TRUE POSITIVES 0
FALSE POSITIVES 0
THREATS RESOLUTION COUNT
UNMITIGATED THREATS 0
MITIGATED THREATS 2
BENIGN THREATS 1
RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY COUNT
CRITICAL 0
HIGH 0
MEDIUM 0
LOW 0
SEVERITY OF VULNERABILITIES COUNT
CRITICAL 0
HIGH 11
MEDIUM 172
LOW 18"""),
("Week 3.pdf", """TICKETS COUNT
NUMBER OF TICKETS RAISED FOR THE WEEK 3
TICKETS RESOLVED 3
TICKETS PENDING 0
TOTAL ALARMS FOR THE WEEK BY SEVERITY COUNT
HIGH 0
MEDIUM 0
LOW 0
FAILED LOGONS COUNT
Failed Logon to Default Account 1
Failed Logon to Disabled Account 0
Failed Logon to Nonexistent Account 1
DATA TABLES
TICKETS SEVERITY COUNT
CRITICAL 0
HIGH 0
MEDIUM 0
LOW 3
THREATS CLASSIFICATION COUNT
Malware 14
Exploit 0
Hacktool 0
Backdoor 5
Trojan 2
Generic.Heuristic 1
Virus 1
RESOLUTION MATRIX COUNT
TRUE POSITIVES 0
FALSE POSITIVES 0
THREATS RESOLUTION COUNT
UNMITIGATED THREATS 0
MITIGATED THREATS 10
BENIGN THREATS 14
RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY COUNT
CRITICAL 0
HIGH 0
MEDIUM 0
LOW 41
SEVERITY OF VULNERABILITIES COUNT
CRITICAL 0
HIGH 10
MEDIUM 310
LOW 45"""),
("Week 4.pdf", """TICKETS COUNT
NUMBER OF TICKETS RAISED FOR THE WEEK 3
TICKETS RESOLVED 3
TICKETS PENDING 0
TOTAL ALARMS FOR THE WEEK BY SEVERITY COUNT
HIGH 0
MEDIUM 0
LOW 0
FAILED LOGONS COUNT
Failed Logon to Default Account 0
Failed Logon to Disabled Account 0
Failed Logon to Nonexistent Account 1
DATA TABLES
TICKETS SEVERITY COUNT
CRITICAL 0
HIGH 0
MEDIUM 0
LOW 3
THREATS CLASSIFICATION COUNT
Malware 10
Exploit 0
Hacktool 5
RESOLUTION MATRIX COUNT
TRUE POSITIVES 0
FALSE POSITIVES 0
THREATS RESOLUTION COUNT
UNMITIGATED THREATS 0
MITIGATED THREATS 15
BENIGN THREATS 0
RESOLUTION TIME OF RESOLVED TICKETS BY SEVERITY COUNT
CRITICAL 0
HIGH 0
MEDIUM 0
LOW 37
SEVERITY OF VULNERABILITIES COUNT
CRITICAL 0
HIGH 7
MEDIUM 737
LOW 54""")
]
# Process the reports
aggregated_data, week_numbers, all_data = aggregate_reports(report_files)
# Generate CSV report
csv_rows = generate_csv_report(aggregated_data, week_numbers, all_data)
# Save to CSV file
import csv
with open('Monthly Report Document.csv', 'w', newline='', encoding='utf-8') as f:
writer = csv.writer(f)
writer.writerows(csv_rows)
print("Monthly Report Document generated successfully!")
print(f"Report saved to 'Monthly Report Document.csv'")
print()
# Display a preview of the aggregated data
print("PREVIEW OF AGGREGATED DATA:")
print("-" * 40)
# Show key metrics
if 'Tickets' in aggregated_data:
tickets_data = aggregated_data['Tickets']
print(f"Total Tickets Raised: {tickets_data.get('Number of Tickets Raised for the 
Week', 0)}")
print(f"Total Tickets Resolved: {tickets_data.get('Tickets Resolved', 0)}")
print(f"Total Tickets Pending: {tickets_data.get('Tickets Pending', 0)}")
if 'Threats Classification' in aggregated_data:
threats_data = aggregated_data['Threats Classification']
total_threats = sum(threats_data.values())
print(f"Total Threats Detected: {total_threats}")
if threats_data:
print("Threat Breakdown:")
for threat_type in sorted(threats_data.keys()):
print(f" - {threat_type}: {threats_data[threat_type]}")
if 'Severity of Vulnerabilities' in aggregated_data:
vuln_data = aggregated_data['Severity of Vulnerabilities']
total_vulns = sum(vuln_data.values())
print(f"Total Vulnerabilities: {total_vulns}")
print(f" - Critical: {vuln_data.get('Critical', 0)}")
print(f" - High: {vuln_data.get('High', 0)}")
print(f" - Medium: {vuln_data.get('Medium', 0)}")
print(f" - Low: {vuln_data.get('Low', 0)}")
if __name__ == "__main__":
main()
