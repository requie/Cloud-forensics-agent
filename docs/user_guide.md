# Cloud Forensics AI Agent - User Documentation

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Usage](#usage)
5. [Modules](#modules)
   - [Data Collection Modules](#data-collection-modules)
   - [Analysis Modules](#analysis-modules)
   - [Reporting Modules](#reporting-modules)
6. [Common Forensic Scenarios](#common-forensic-scenarios)
7. [Troubleshooting](#troubleshooting)
8. [References](#references)

## Introduction

The Cloud Forensics AI Agent is a comprehensive tool designed for digital forensic analysis of incidents in cloud environments. It addresses the unique challenges of cloud forensics by providing automated evidence collection, analysis, and reporting capabilities across multiple cloud providers and service models.

### Key Features

- **Multi-cloud Support**: Collect evidence from AWS, Azure, GCP, and private cloud environments
- **Service Model Coverage**: Support for IaaS, PaaS, and SaaS forensics
- **AI-powered Analysis**: Automated timeline reconstruction, pattern detection, anomaly detection, and correlation
- **Forensic Integrity**: Maintains chain of custody and evidence integrity throughout the process
- **Standardized Reporting**: Generate comprehensive reports in multiple formats (HTML, PDF, JSON)

## Installation

### Prerequisites

- Python 3.8 or higher
- Access to cloud environments (AWS, Azure, GCP) with appropriate permissions
- Required Python packages (installed automatically during setup)

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/your-organization/cloud-forensics-agent.git
   cd cloud-forensics-agent
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Verify installation:
   ```bash
   python -m cloud_forensics_agent --version
   ```

## Configuration

### Cloud Provider Credentials

The agent requires credentials to access cloud environments. Configure these credentials using environment variables or configuration files:

#### AWS Configuration

```bash
# Using environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Or using AWS CLI
aws configure
```

#### Azure Configuration

```bash
# Using environment variables
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"

# Or using Azure CLI
az login
```

#### GCP Configuration

```bash
# Using environment variables
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"

# Or using gcloud CLI
gcloud auth application-default login
```

### Agent Configuration

Create a configuration file `config.yaml` in the root directory:

```yaml
case:
  organization: "Example Corp"
  department: "Security Operations"
  investigator: "Jane Doe"

evidence:
  output_path: "/path/to/evidence"
  format: "zip"  # Options: zip, tar, directory
  encryption: true
  encryption_key_path: "/path/to/encryption/key"

analysis:
  timeline:
    enabled: true
    time_zone: "UTC"
  pattern_detection:
    enabled: true
    custom_signatures_path: "/path/to/custom/signatures"
  anomaly_detection:
    enabled: true
    sensitivity: "medium"  # Options: low, medium, high
  correlation:
    enabled: true

reporting:
  formats:
    - html
    - pdf
    - json
  output_path: "/path/to/reports"
  template_path: "/path/to/custom/templates"
```

## Usage

### Command Line Interface

The agent provides a command-line interface for running forensic investigations:

```bash
# Start a new investigation
python -m cloud_forensics_agent investigate --case-id "CASE-2025-001" --config config.yaml

# Collect evidence only
python -m cloud_forensics_agent collect --case-id "CASE-2025-001" --config config.yaml

# Analyze existing evidence
python -m cloud_forensics_agent analyze --case-id "CASE-2025-001" --evidence-path "/path/to/evidence" --config config.yaml

# Generate reports from analysis results
python -m cloud_forensics_agent report --case-id "CASE-2025-001" --analysis-path "/path/to/analysis" --config config.yaml
```

### Python API

You can also use the agent programmatically in your Python code:

```python
from cloud_forensics_agent import ForensicAgent

# Initialize the agent
agent = ForensicAgent(
    case_id="CASE-2025-001",
    config_path="config.yaml"
)

# Run a complete investigation
agent.investigate()

# Or run individual phases
evidence = agent.collect_evidence()
analysis_results = agent.analyze_evidence(evidence)
reports = agent.generate_reports(analysis_results)
```

## Modules

### Data Collection Modules

The agent includes the following data collection modules:

#### AWS Collectors

- **CloudTrailCollector**: Collects AWS CloudTrail logs for auditing and security analysis
- **S3BucketCollector**: Collects access logs and metadata from S3 buckets
- **EC2InstanceCollector**: Collects disk images, memory dumps, and logs from EC2 instances
- **VPCFlowLogCollector**: Collects VPC Flow Logs for network traffic analysis
- **CloudWatchLogCollector**: Collects logs from CloudWatch

#### Azure Collectors

- **ActivityLogCollector**: Collects Azure Activity Logs for auditing and security analysis
- **VirtualMachineCollector**: Collects disk images, memory dumps, and logs from Azure VMs
- **StorageAccountCollector**: Collects logs and data from Azure Storage Accounts
- **NetworkWatcherCollector**: Collects network traffic logs and security group information

#### GCP Collectors

- **AuditLogCollector**: Collects GCP Audit Logs for auditing and security analysis
- **ComputeEngineCollector**: Collects disk images, memory dumps, and logs from GCP VMs
- **CloudStorageCollector**: Collects logs and data from GCP Cloud Storage
- **VPCFlowLogCollector**: Collects VPC Flow Logs for network traffic analysis

#### SaaS Collectors

- **Office365Collector**: Collects logs and data from Microsoft 365 services
- **GoogleWorkspaceCollector**: Collects logs and data from Google Workspace
- **SalesforceCollector**: Collects logs and data from Salesforce
- **GenericAPICollector**: Collects data from custom SaaS applications via API

### Analysis Modules

The agent includes the following analysis modules:

#### Timeline Analyzer

Reconstructs a chronological timeline of events across all collected evidence sources, identifying:
- Time gaps and anomalies
- Activity clusters
- Suspicious time patterns

#### Pattern Detector

Identifies known attack patterns and suspicious behaviors, including:
- Credential theft attempts
- Privilege escalation
- Data exfiltration
- Resource manipulation
- Known attack chains

#### Anomaly Detector

Detects statistical and behavioral anomalies in the collected evidence:
- Access anomalies (unusual access patterns)
- Temporal anomalies (unusual timing of events)
- Behavioral anomalies (unusual user or system behavior)
- Network anomalies (unusual network traffic)

#### Correlation Analyzer

Correlates events across different evidence sources to identify:
- Related events across multiple cloud providers
- Attack progression
- Causal relationships between events
- Impact assessment

### Reporting Modules

The agent includes the following reporting modules:

#### HTML Reporter

Generates interactive HTML reports with:
- Executive summary
- Interactive timeline visualization
- Detailed findings with evidence references
- Recommendations for remediation

#### PDF Reporter

Generates professional PDF reports suitable for legal and compliance purposes:
- Executive summary
- Methodology documentation
- Detailed findings with evidence references
- Chain of custody documentation
- Recommendations for remediation

#### JSON Reporter

Generates machine-readable JSON reports for integration with other tools:
- Structured representation of all findings
- Evidence metadata and references
- Analysis results in a standardized format

## Common Forensic Scenarios

### Scenario 1: Unauthorized Access Investigation

To investigate unauthorized access to cloud resources:

```bash
python -m cloud_forensics_agent investigate \
  --case-id "UNAUTHORIZED-ACCESS-001" \
  --config config.yaml \
  --start-time "2025-04-01T00:00:00Z" \
  --end-time "2025-04-17T00:00:00Z" \
  --focus "access" \
  --resources "s3://company-financial-data,ec2-instance-id-123"
```

This will:
1. Collect CloudTrail logs, S3 access logs, and EC2 instance logs
2. Analyze access patterns and identify anomalies
3. Generate a report highlighting unauthorized access events

### Scenario 2: Data Exfiltration Investigation

To investigate potential data exfiltration:

```bash
python -m cloud_forensics_agent investigate \
  --case-id "DATA-EXFIL-001" \
  --config config.yaml \
  --start-time "2025-04-01T00:00:00Z" \
  --end-time "2025-04-17T00:00:00Z" \
  --focus "data-movement" \
  --resources "s3://company-financial-data,rds-instance-id-456"
```

This will:
1. Collect S3 access logs, RDS logs, and network flow logs
2. Analyze data movement patterns and identify exfiltration indicators
3. Generate a report highlighting potential data exfiltration events

### Scenario 3: Ransomware Investigation

To investigate a ransomware incident:

```bash
python -m cloud_forensics_agent investigate \
  --case-id "RANSOMWARE-001" \
  --config config.yaml \
  --start-time "2025-04-01T00:00:00Z" \
  --end-time "2025-04-17T00:00:00Z" \
  --focus "file-modification" \
  --resources "s3://company-data,ec2-instance-id-789"
```

This will:
1. Collect S3 access logs, EC2 instance logs, and file modification events
2. Analyze file modification patterns and identify ransomware indicators
3. Generate a report highlighting the ransomware attack timeline and impact

## Troubleshooting

### Common Issues

#### Authentication Failures

If you encounter authentication failures:

1. Verify that your cloud provider credentials are correctly configured
2. Ensure that the credentials have the necessary permissions
3. Check for expired tokens or credentials

#### Resource Access Issues

If the agent cannot access certain resources:

1. Verify that the resources exist in the specified region
2. Check that your credentials have permissions to access the resources
3. Ensure that the resources are not protected by additional security measures

#### Performance Issues

If the agent is running slowly:

1. Consider narrowing the time range of your investigation
2. Limit the scope to specific resources of interest
3. Disable analysis modules that are not needed for your investigation

### Logging

The agent logs detailed information about its operations. To increase log verbosity:

```bash
python -m cloud_forensics_agent investigate --case-id "CASE-2025-001" --config config.yaml --log-level debug
```

Log files are stored in the `logs` directory by default.

## References

- [Cloud Forensics: Challenges and Opportunities](https://example.com/cloud-forensics-paper)
- [NIST Cloud Computing Forensic Science Challenges](https://example.com/nist-cloud-forensics)
- [AWS Security Incident Response Guide](https://example.com/aws-incident-response)
- [Azure Forensics Documentation](https://example.com/azure-forensics)
- [GCP Security Response Guide](https://example.com/gcp-security-response)
