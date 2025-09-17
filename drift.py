#!/usr/bin/env python3
"""
AWS IAM Drift Detector

A Python tool that analyzes AWS IAM policies to detect risky permissions 
using AI-powered explanations. This tool identifies potential security
vulnerabilities in your IAM policies and provides clear explanations
using Google's Gemini AI.

Author: jibin006
Version: 1.0.0
License: MIT
"""

import os
import sys
import json
import logging
from typing import List, Dict, Any

import boto3
import google.generativeai as genai
from botocore.exceptions import ClientError, NoCredentialsError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize AWS IAM client
try:
    iam = boto3.client("iam")
except NoCredentialsError:
    logger.error("AWS credentials not found. Please configure AWS credentials.")
    sys.exit(1)

# Configure Google Gemini AI
# TODO: Replace with your own API key or use environment variable
# For production, use: genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
api_key = os.getenv('GEMINI_API_KEY', 'AIzaSyDNPllJkC0QOoTu9vhBVz6rkuVEuqQJFhE')
if not api_key:
    logger.error("Gemini API key not found. Please set GEMINI_API_KEY environment variable.")
    sys.exit(1)

genai.configure(api_key=api_key)


def explain_risk_with_gemini(policy_name: str, risky_statements: List[Dict[str, Any]]) -> str:
    """
    Use Google Gemini AI to explain why IAM policy statements are risky.
    
    Args:
        policy_name (str): Name of the IAM policy
        risky_statements (List[Dict]): List of risky policy statements
        
    Returns:
        str: AI-generated explanation of the security risks
    """
    try:
        prompt = f"""
        You are a cloud security expert. Explain why the following IAM policy statements are risky:
        
        Policy Name: {policy_name}
        Statements: {json.dumps(risky_statements, indent=2)}
        
        Please provide:
        1. A concise explanation of the security risks (2-3 sentences)
        2. Potential attack scenarios
        3. Recommended remediation steps
        
        Keep the response clear and actionable.
        """
        
        logger.debug(f"Generating AI explanation for policy: {policy_name}")
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        
        return response.text if response.text else "Unable to generate AI explanation."
        
    except Exception as e:
        logger.error(f"Error generating AI explanation for {policy_name}: {e}")
        return f"Error generating AI explanation: {str(e)}"


def risky_statements(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyze IAM policy document to identify risky statements.
    
    Currently detects:
    - Wildcard actions ("*")
    - Wildcard resources ("*")
    
    Args:
        document (Dict): IAM policy document
        
    Returns:
        List[Dict]: List of risky policy statements
    """
    risky = []
    statements = document.get("Statement", [])
    
    # Ensure statements is a list (handle single statement case)
    if not isinstance(statements, list):
        statements = [statements]
    
    for stmt in statements:
        # Skip Deny statements as they are generally more restrictive
        if stmt.get("Effect", "").upper() == "DENY":
            continue
            
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        
        # Normalize actions and resources to lists for consistent processing
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        
        # Check for risky patterns
        has_wildcard_action = any(action == "*" for action in actions)
        has_wildcard_resource = any(resource == "*" for resource in resources)
        
        # Log detection details for debugging
        if has_wildcard_action:
            logger.debug(f"Detected wildcard action in statement: {stmt}")
        if has_wildcard_resource:
            logger.debug(f"Detected wildcard resource in statement: {stmt}")
        
        # Add statement to risky list if it matches our criteria
        if has_wildcard_action or has_wildcard_resource:
            risky.append(stmt)
    
    return risky


def get_policies_with_risky_permissions() -> List[Dict[str, Any]]:
    """
    Scan all customer-managed IAM policies and identify those with risky permissions.
    
    Returns:
        List[Dict]: List of findings with risky policies and AI explanations
    """
    findings = []
    policy_count = 0
    risky_policy_count = 0
    
    try:
        logger.info("Starting IAM policy analysis...")
        
        # Use paginator to handle large numbers of policies
        paginator = iam.get_paginator("list_policies")
        
        # Only scan customer-managed policies (not AWS managed)
        for page in paginator.paginate(Scope="Local"):
            for policy in page["Policies"]:
                policy_count += 1
                arn = policy["Arn"]
                policy_name = policy["PolicyName"]
                
                logger.debug(f"Analyzing policy: {policy_name} ({arn})")
                
                try:
                    # Get the default version of the policy
                    policy_details = iam.get_policy(PolicyArn=arn)
                    version_id = policy_details["Policy"]["DefaultVersionId"]
                    
                    # Get the policy document
                    policy_version = iam.get_policy_version(
                        PolicyArn=arn, 
                        VersionId=version_id
                    )
                    document = policy_version["PolicyVersion"]["Document"]
                    
                    # Analyze for risky statements
                    risky = risky_statements(document)
                    
                    if risky:
                        risky_policy_count += 1
                        logger.info(f"Found risky policy: {policy_name}")
                        
                        # Get AI explanation for the risky statements
                        ai_explanation = explain_risk_with_gemini(policy_name, risky)
                        
                        findings.append({
                            "PolicyName": policy_name,
                            "Arn": arn,
                            "RiskyStatements": risky,
                            "AIExplanation": ai_explanation,
                            "CreatedDate": policy["CreateDate"].isoformat(),
                            "UpdateDate": policy["UpdateDate"].isoformat(),
                            "AttachmentCount": policy.get("AttachmentCount", 0)
                        })
                        
                except ClientError as e:
                    logger.error(f"Error analyzing policy {policy_name}: {e}")
                    continue
    
    except ClientError as e:
        logger.error(f"Error listing IAM policies: {e}")
        return []
    
    logger.info(f"Analysis complete: {risky_policy_count}/{policy_count} policies have risky permissions")
    return findings


def save_report(findings: List[Dict[str, Any]], filename: str = "iam_risky_policies.json") -> None:
    """
    Save the analysis results to a JSON file.
    
    Args:
        findings (List[Dict]): Analysis results
        filename (str): Output filename
    """
    try:
        with open(filename, "w") as f:
            json.dump(findings, f, indent=2, default=str)
        
        logger.info(f"Report saved to {filename}")
        print(f"\n✅ Analysis complete! Report saved to {filename}")
        print(f"📊 Found {len(findings)} policies with risky permissions")
        
        if findings:
            print("\n⚠️  Risky Policies Found:")
            for finding in findings:
                print(f"  • {finding['PolicyName']} - {len(finding['RiskyStatements'])} risky statement(s)")
        
    except IOError as e:
        logger.error(f"Error saving report to {filename}: {e}")


def main() -> None:
    """
    Main function to orchestrate the IAM drift detection process.
    """
    try:
        print("🔍 AWS IAM Drift Detector")
        print("==========================\n")
        print("Analyzing customer-managed IAM policies for risky permissions...\n")
        
        # Run the analysis
        results = get_policies_with_risky_permissions()
        
        # Save results to file
        save_report(results)
        
        if not results:
            print("\n🎉 Great! No risky policies detected.")
        else:
            print("\n⚠️  Please review the findings and consider updating risky policies.")
            print("📖 See the generated report for detailed AI explanations and recommendations.")
            
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        print("\n⏹️  Analysis stopped by user.")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"\n❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
