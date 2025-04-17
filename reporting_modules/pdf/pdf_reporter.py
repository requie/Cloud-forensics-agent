"""
PDF reporter for the Cloud Forensics AI Agent.

This module provides functionality for generating forensic reports
in PDF format from analysis results.
"""

import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional, Union
import tempfile

from ..core.base_reporter import BaseReporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PDFReporter(BaseReporter):
    """
    Reporter for generating forensic reports in PDF format.
    
    This class extends the BaseReporter to generate professional PDF
    reports suitable for legal and compliance purposes.
    """
    
    def __init__(self, case_id: str, report_output_path: str):
        """
        Initialize the PDF reporter.
        
        Args:
            case_id: Unique identifier for the forensic case
            report_output_path: Path where reports will be stored
        """
        super().__init__(case_id, report_output_path)
        self.metadata['report_format'] = 'pdf'
        logger.info(f"Initialized PDFReporter for case {case_id}")
        
        # Check if required packages are installed
        try:
            import reportlab
            import weasyprint
        except ImportError:
            logger.warning("Required packages for PDF generation not found. Installing...")
            self._install_dependencies()
    
    def _install_dependencies(self):
        """Install required dependencies for PDF generation."""
        import subprocess
        
        try:
            # Install required Python packages
            subprocess.check_call(["pip3", "install", "reportlab", "weasyprint"])
            logger.info("Successfully installed PDF generation dependencies")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install dependencies: {str(e)}")
            raise
    
    def generate_report(self, analysis_results: Dict[str, Any], 
                      evidence_metadata: Dict[str, Any] = None,
                      include_raw_data: bool = False) -> str:
        """
        Generate a PDF forensic report from analysis results.
        
        Args:
            analysis_results: Dictionary containing analysis results
            evidence_metadata: Optional metadata about the evidence
            include_raw_data: Whether to include raw data in the report
            
        Returns:
            Path to the generated PDF report
        """
        # Import here to ensure dependencies are installed
        from weasyprint import HTML, CSS
        
        # Prepare report data
        report_data = self._prepare_report_data(analysis_results, evidence_metadata, include_raw_data)
        
        # Generate HTML content first (reuse HTML reporter logic)
        html_content = self._generate_html_content(report_data)
        
        # Define output path
        report_filename = f"forensic_report_{self.case_id}_{self.report_id}.pdf"
        report_path = os.path.join(self.report_output_path, report_filename)
        
        # Create a temporary HTML file
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as temp_html:
            temp_html_path = temp_html.name
            temp_html.write(html_content.encode('utf-8'))
        
        try:
            # Convert HTML to PDF
            html = HTML(filename=temp_html_path)
            html.write_pdf(report_path)
            
            logger.info(f"Generated PDF report at {report_path}")
            
            # Add custody event
            self.add_custody_event(
                event_type="report_generation",
                description=f"Generated PDF forensic report",
                handler="Cloud Forensics AI Agent"
            )
            
            return report_path
        
        finally:
            # Clean up temporary file
            if os.path.exists(temp_html_path):
                os.unlink(temp_html_path)
    
    def _generate_html_content(self, report_data: Dict[str, Any]) -> str:
        """
        Generate HTML content for the PDF report.
        
        Args:
            report_data: Dictionary containing report data
            
        Returns:
            HTML content as string
        """
        # This is a simplified version of the HTML reporter's method
        # Start with HTML template
        html_content = self._get_html_template()
        
        # Replace placeholders with actual content
        html_content = html_content.replace('{{REPORT_TITLE}}', f"Cloud Forensic Report - Case {self.case_id}")
        html_content = html_content.replace('{{GENERATION_DATE}}', self._format_timestamp(report_data['metadata']['generation_timestamp']))
        html_content = html_content.replace('{{CASE_ID}}', self.case_id)
        html_content = html_content.replace('{{REPORT_ID}}', self.report_id)
        
        # Add executive summary
        html_content = html_content.replace('{{EXECUTIVE_SUMMARY}}', self._html_format_text(report_data['executive_summary']))
        
        # Add case information
        case_info_html = self._generate_case_info_html(report_data['metadata'])
        html_content = html_content.replace('{{CASE_INFORMATION}}', case_info_html)
        
        # Add evidence metadata
        evidence_html = self._generate_evidence_html(report_data['evidence_metadata'])
        html_content = html_content.replace('{{EVIDENCE_INFORMATION}}', evidence_html)
        
        # Add findings
        findings_html = self._generate_findings_html(report_data['analysis_results'])
        html_content = html_content.replace('{{FINDINGS}}', findings_html)
        
        # Add analysis details
        analysis_html = self._generate_analysis_html(report_data['analysis_results'])
        html_content = html_content.replace('{{ANALYSIS_DETAILS}}', analysis_html)
        
        # Add recommendations
        recommendations_html = self._generate_recommendations_html(report_data['recommendations'])
        html_content = html_content.replace('{{RECOMMENDATIONS}}', recommendations_html)
        
        # Add chain of custody
        custody_html = self._generate_custody_html(report_data['chain_of_custody'])
        html_content = html_content.replace('{{CHAIN_OF_CUSTODY}}', custody_html)
        
        return html_content
    
    def _get_html_template(self) -> str:
        """
        Get the HTML template for the PDF report.
        
        Returns:
            HTML template as string
        """
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{REPORT_TITLE}}</title>
    <style>
        @page {
            size: letter;
            margin: 2cm;
            @top-center {
                content: "Cloud Forensic Report";
                font-family: Arial, sans-serif;
                font-size: 10pt;
            }
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-family: Arial, sans-serif;
                font-size: 10pt;
            }
        }
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 0;
            background-color: #fff;
        }
        .container {
            width: 100%;
            margin: 0 auto;
            padding: 0;
            background-color: #fff;
        }
        header {
            background-color: #2c3e50;
            color: #fff;
            padding: 20px;
            margin-bottom: 20px;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
            margin-top: 30px;
        }
        header h1 {
            color: #fff;
            margin-top: 0;
        }
        .meta-info {
            background-color: #f9f9f9;
            padding: 15px;
            border-left: 4px solid #2c3e50;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            page-break-inside: auto;
        }
        tr {
            page-break-inside: avoid;
            page-break-after: auto;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .severity-high {
            color: #e74c3c;
            font-weight: bold;
        }
        .severity-medium {
            color: #f39c12;
            font-weight: bold;
        }
        .severity-low {
            color: #3498db;
        }
        .priority-high {
            background-color: #ffebee;
        }
        .priority-medium {
            background-color: #fff8e1;
        }
        .priority-low {
            background-color: #e3f2fd;
        }
        .section {
            margin-bottom: 20px;
            page-break-inside: avoid;
        }
        .subsection {
            margin-top: 15px;
            margin-bottom: 15px;
        }
        footer {
            margin-top: 50px;
            padding: 20px;
            background-color: #2c3e50;
            color: #fff;
            text-align: center;
        }
        .page-break {
            page-break-before: always;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{REPORT_TITLE}}</h1>
            <p>Generated on: {{GENERATION_DATE}}</p>
        </header>
        
        <div class="meta-info">
            <p><strong>Case ID:</strong> {{CASE_ID}}</p>
            <p><strong>Report ID:</strong> {{REPORT_ID}}</p>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="section">
            {{EXECUTIVE_SUMMARY}}
        </div>
        
        <div class="page-break"></div>
        
        <h2>Case Information</h2>
        <div class="section">
            {{CASE_INFORMATION}}
        </div>
        
        <h2>Evidence Information</h2>
        <div class="section">
            {{EVIDENCE_INFORMATION}}
        </div>
        
        <div class="page-break"></div>
        
        <h2>Key Findings</h2>
        <div class="section">
            {{FINDINGS}}
        </div>
        
        <div class="page-break"></div>
        
        <h2>Analysis Details</h2>
        <div class="section">
            {{ANALYSIS_DETAILS}}
        </div>
        
        <div class="page-break"></div>
        
        <h2>Recommendations</h2>
        <div class="section">
            {{RECOMMENDATIONS}}
        </div>
        
        <div class="page-break"></div>
        
        <h2>Chain of Custody</h2>
        <div class="section">
            {{CHAIN_OF_CUSTODY}}
        </div>
        
        <footer>
            <p>This report was generated by the Cloud Forensics AI Agent.</p>
            <p>© 2025 Cloud Forensics AI Agent</p>
        </footer>
    </div>
</body>
</html>"""
    
    def _html_format_text(self, text: str) -> str:
        """
        Format text for HTML display.
        
        Args:
            text: Text to format
            
        Returns:
            HTML-formatted text
        """
        if not text:
            return ""
        
        import html
        
        # Escape HTML special characters
        text = html.escape(text)
        
        # Convert newlines to <br> tags
        text = text.replace('\n', '<br>')
        
        return text
    
    def _generate_case_info_html(self, metadata: Dict[str, Any]) -> str:
        """
        Generate HTML for case information.
        
        Args:
            metadata: Report metadata
            
        Returns:
            HTML string for case information
        """
        case_info = metadata.get('case_information', {})
        investigator_info = metadata.get('investigator_information', {})
        
        html_parts = ['<div class="case-info">']
        
        # Add case information
        if case_info:
            html_parts.append('<h3>Case Details</h3>')
            html_parts.append('<table>')
            html_parts.append('<tr><th>Field</th><th>Value</th></tr>')
            
            for key, value in case_info.items():
                html_parts.append(f'<tr><td>{key}</td><td>{value}</td></tr>')
            
            html_parts.append('</table>')
        else:
            html_parts.append('<p>No detailed case information available.</p>')
        
        # Add investigator information
        if investigator_info:
            html_parts.append('<h3>Investigator Details</h3>')
            html_parts.append('<table>')
            html_parts.append('<tr><th>Field</th><th>Value</th></tr>')
            
            for key, value in investigator_info.items():
                html_parts.append(f'<tr><td>{key}</td><td>{value}</td></tr>')
            
            html_parts.append('</table>')
        
        html_parts.append('</div>')
        
        return '\n'.join(html_parts)
    
    def _generate_evidence_html(self, evidence_metadata: Dict[str, Any]) -> str:
        """
        Generate HTML for evidence information.
        
        Args:
            evidence_metadata: Evidence metadata
            
        Returns:
            HTML string for evidence information
        """
        if not evidence_metadata:
            return '<p>No detailed evidence information available.</p>'
        
        html_parts = ['<div class="evidence-info">']
        
        # Add evidence sources
        if 'sources' in evidence_metadata:
            html_parts.append('<h3>Evidence Sources</h3>')
            html_parts.append('<table>')
            html_parts.append('<tr><th>Source</th><th>Type</th><th>Collection Time</th></tr>')
            
            for source in evidence_metadata['sources']:
                source_name = source.get('name', 'Unknown')
                source_type = source.get('type', 'Unknown')
                collection_time = self._format_timestamp(source.get('collection_time', 'Unknown'))
                
                html_parts.append(f'<tr><td>{source_name}</td><td>{source_type}</td><td>{collection_time}</td></tr>')
            
            html_parts.append('</table>')
        
        # Add evidence statistics
        if 'statistics' in evidence_metadata:
            html_parts.append('<h3>Evidence Statistics</h3>')
            html_parts.append('<table>')
            html_parts.append('<tr><th>Category</th><th>Count</th></tr>')
            
            for category, count in evidence_metadata['statistics'].items():
                html_parts.append(f'<tr><td>{category}</td><td>{count}</td></tr>')
            
            html_parts.append('</table>')
        
        # Add time range
        if 'time_range' in evidence_metadata:
            time_range = evidence_metadata['time_range']
            start_time = self._format_timestamp(time_range.get('start', 'Unknown'))
            end_time = self._format_timestamp(time_range.get('end', 'Unknown'))
            
            html_parts.append('<h3>Evidence Time Range</h3>')
            html_parts.append('<p>')
            html_parts.append(f'<strong>Start Time:</strong> {start_time}<br>')
            html_parts.append(f'<strong>End Time:</strong> {end_time}')
            html_parts.append('</p>')
        
        html_parts.append('</div>')
        
        return '\n'.join(html_parts)
    
    def _generate_findings_html(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate HTML for key findings.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            HTML string for key findings
        """
        # Collect all findings
        all_findings = []
        
        for analysis_type, result in analysis_results.items():
            if 'findings' in result:
                for finding in result['findings']:
                    finding['analysis_type'] = analysis_type
                    all_findings.append(finding)
        
        if not all_findings:
            return '<p>No findings were identified during the analysis.</p>'
        
        # Sort findings by severity
        severity_order = {'high': 0, 'medium': 1, 'low': 2}
        all_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 3))
        
        html_parts = ['<div class="findings-section">']
        
        # Group findings by severity
        severities = ['high', 'medium', 'low']
        
        for severity in severities:
            severity_findings = [f for f in all_findings if f.get('severity') == severity]
            
            if severity_findings:
                html_parts.append(f'<h3 class="severity-{severity}">{severity.upper()} Severity Findings ({len(severity_findings)})</h3>')
                html_parts.append('<div class="subsection">')
                
                html_parts.append('<table>')
                html_parts.append('<tr><th>Type</th><th>Description</th><th>Analysis</th><th>Confidence</th></tr>')
                
                for finding in severity_findings:
                    finding_type = finding.get('type', 'Unknown')
                    description = finding.get('description', 'No description available')
                    analysis_type = finding.get('analysis_type', 'Unknown')
                    confidence = finding.get('confidence', 'Unknown')
                    
                    html_parts.append(f'<tr>')
                    html_parts.append(f'<td>{finding_type}</td>')
                    html_parts.append(f'<td>{description}</td>')
                    html_parts.append(f'<td>{analysis_type}</td>')
                    html_parts.append(f'<td>{confidence}</td>')
                    html_parts.append(f'</tr>')
                
                html_parts.append('</table>')
                html_parts.append('</div>')
        
        html_parts.append('</div>')
        
        return '\n'.join(html_parts)
    
    def _generate_analysis_html(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate HTML for analysis details.
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            HTML string for analysis details
        """
        if not analysis_results:
            return '<p>No analysis results available.</p>'
        
        html_parts = ['<div class="analysis-section">']
        
        # Create content for each analysis type
        for analysis_type, result in analysis_results.items():
            html_parts.append(f'<h3>{analysis_type}</h3>')
            html_parts.append('<div class="subsection">')
            
            # Add summary
            if 'summary' in result:
                html_parts.append('<h4>Summary</h4>')
                html_parts.append(f'<p>{self._html_format_text(result["summary"])}</p>')
            
            # Add findings
            if 'findings' in result and result['findings']:
                html_parts.append('<h4>Findings</h4>')
                
                # Group findings by type
                findings_by_type = {}
                for finding in result['findings']:
                    finding_type = finding.get('type', 'Unknown')
                    if finding_type not in findings_by_type:
                        findings_by_type[finding_type] = []
                    findings_by_type[finding_type].append(finding)
                
                # Create sections for each finding type
                for finding_type, findings in findings_by_type.items():
                    html_parts.append(f'<h5>{finding_type} ({len(findings)})</h5>')
                    
                    html_parts.append('<table>')
                    html_parts.append('<tr><th>Severity</th><th>Description</th><th>Confidence</th></tr>')
                    
                    for finding in findings:
                        severity = finding.get('severity', 'low')
                        description = finding.get('description', 'No description available')
                        confidence = finding.get('confidence', 'Unknown')
                        
                        html_parts.append(f'<tr>')
                        html_parts.append(f'<td><span class="severity-{severity}">{severity.upper()}</span></td>')
                        html_parts.append(f'<td>{description}</td>')
                        html_parts.append(f'<td>{confidence}</td>')
                        html_parts.append(f'</tr>')
                    
                    html_parts.append('</table>')
            
            # Add report
            if 'report' in result:
                html_parts.append('<h4>Detailed Report</h4>')
                html_parts.append(f'<pre>{self._html_format_text(result["report"])}</pre>')
            
            html_parts.append('</div>')
        
        html_parts.append('</div>')
        
        return '\n'.join(html_parts)
    
    def _generate_recommendations_html(self, recommendations: List[Dict[str, Any]]) -> str:
        """
        Generate HTML for recommendations.
        
        Args:
            recommendations: List of recommendation dictionaries
            
        Returns:
            HTML string for recommendations
        """
        if not recommendations:
            return '<p>No recommendations available.</p>'
        
        html_parts = ['<div class="recommendations-section">']
        
        # Group recommendations by category
        recommendations_by_category = {}
        for recommendation in recommendations:
            category = recommendation.get('category', 'general')
            if category not in recommendations_by_category:
                recommendations_by_category[category] = []
            recommendations_by_category[category].append(recommendation)
        
        # Create sections for each category
        for category, category_recommendations in recommendations_by_category.items():
            html_parts.append(f'<h3>{category.capitalize()} Recommendations ({len(category_recommendations)})</h3>')
            html_parts.append('<div class="subsection">')
            
            html_parts.append('<table>')
            html_parts.append('<tr><th>Priority</th><th>Recommendation</th><th>Description</th></tr>')
            
            # Sort recommendations by priority
            priority_order = {'high': 0, 'medium': 1, 'low': 2}
            category_recommendations.sort(key=lambda x: priority_order.get(x.get('priority', 'low'), 3))
            
            for recommendation in category_recommendations:
                priority = recommendation.get('priority', 'medium')
                title = recommendation.get('title', 'No title available')
                description = recommendation.get('description', 'No description available')
                
                html_parts.append(f'<tr class="priority-{priority}">')
                html_parts.append(f'<td><span class="severity-{priority}">{priority.upper()}</span></td>')
                html_parts.append(f'<td><strong>{title}</strong></td>')
                html_parts.append(f'<td>{description}</td>')
                html_parts.append(f'</tr>')
            
            html_parts.append('</table>')
            html_parts.append('</div>')
        
        html_parts.append('</div>')
        
        return '\n'.join(html_parts)
    
    def _generate_custody_html(self, chain_of_custody: List[Dict[str, Any]]) -> str:
        """
        Generate HTML for chain of custody.
        
        Args:
            chain_of_custody: List of custody event dictionaries
            
        Returns:
            HTML string for chain of custody
        """
        if not chain_of_custody:
            return '<p>No chain of custody events recorded.</p>'
        
        html_parts = ['<div class="custody-info">']
        
        html_parts.append('<table>')
        html_parts.append('<tr><th>Timestamp</th><th>Event Type</th><th>Description</th><th>Handler</th></tr>')
        
        for event in chain_of_custody:
            timestamp = self._format_timestamp(event.get('timestamp', 'Unknown'))
            event_type = event.get('event_type', 'Unknown')
            description = event.get('description', 'No description available')
            handler = event.get('handler', 'Unknown')
            
            html_parts.append(f'<tr>')
            html_parts.append(f'<td>{timestamp}</td>')
            html_parts.append(f'<td>{event_type}</td>')
            html_parts.append(f'<td>{description}</td>')
            html_parts.append(f'<td>{handler}</td>')
            html_parts.append(f'</tr>')
        
        html_parts.append('</table>')
        html_parts.append('</div>')
        
        return '\n'.join(html_parts)
