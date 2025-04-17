# Cloud Forensics AI Agent

An AI-powered agent for digital forensic analysis of incidents in cloud environments.

## Overview

The Cloud Forensics AI Agent is a comprehensive tool designed to address the unique challenges of cloud forensics by providing automated evidence collection, analysis, and reporting capabilities across multiple cloud providers and service models.

### Key Features

- **Multi-cloud Support**: Collect evidence from AWS, Azure, GCP, and private cloud environments
- **Service Model Coverage**: Support for IaaS, PaaS, and SaaS forensics
- **AI-powered Analysis**: Automated timeline reconstruction, pattern detection, anomaly detection, and correlation
- **Forensic Integrity**: Maintains chain of custody and evidence integrity throughout the process
- **Standardized Reporting**: Generate comprehensive reports in multiple formats (HTML, PDF, JSON)

## Architecture

The Cloud Forensics AI Agent follows a modular, layered architecture:

1. **User Interface Layer**: CLI and Python API interfaces
2. **Orchestration Layer**: Case and workflow management
3. **Core Engines**: Data collection, analysis, reporting, and AI/ML
4. **Integration Layer**: Cloud provider adapters and API integration
5. **Cloud Provider Layer**: Provider-specific implementations

## Components

### Data Collection Modules

Specialized collectors for:
- **AWS**: CloudTrail logs, S3 buckets, EC2 instances, VPC Flow Logs
- **Azure**: Activity Logs, Virtual Machines, Storage Accounts, Network Watcher
- **GCP**: Audit Logs, Compute Engine, Cloud Storage, VPC Flow Logs
- **SaaS**: Office 365, Google Workspace, Salesforce, and custom SaaS applications

### Analysis Modules

Advanced analysis capabilities:
- **Timeline Analysis**: Chronological reconstruction of events across all evidence sources
- **Pattern Detection**: Identification of known attack patterns and suspicious behaviors
- **Anomaly Detection**: Statistical and behavioral anomaly detection
- **Correlation Analysis**: Cross-source event correlation and relationship mapping

### Reporting Modules

Comprehensive reports in multiple formats:
- **HTML Reports**: Interactive reports with visualizations
- **PDF Reports**: Professional reports for legal and compliance purposes
- **JSON Reports**: Machine-readable reports for integration with other tools

## Installation

### Prerequisites

- Python 3.8 or higher
- Access to cloud environments (AWS, Azure, GCP) with appropriate permissions
- Required Python packages (installed automatically during setup)

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/cloud-forensics-agent.git
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

## Usage

### Command Line Interface

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

## Documentation

For more detailed information, please refer to:

- [User Guide](docs/user_guide.md): Installation instructions, configuration options, usage examples, and common forensic scenarios
- [Technical Guide](docs/technical_guide.md): Architecture details, component descriptions, and extension guidelines for developers
- [Final Report](docs/final_report.md): Project summary, capabilities overview, and future enhancement possibilities

## Contributing

We welcome contributions to the Cloud Forensics AI Agent. Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Add your changes
4. Write tests for your changes
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
