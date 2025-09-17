import boto3
import json
import google.generativeai as genai

iam = boto3.client("iam")


genai.configure(api_key="AIzaSyDNPllJkC0QOoTu9vhBVz6rkuVEuqQJFhE")

def explain_risk_with_gemini(policy_name, risky_statements):
    prompt = f"""
    You are a cloud security expert. Explain why the following IAM policy statements are risky:

    Policy Name: {policy_name}
    Statements: {risky_statements}

    Give a short, plain-English explanation (2–3 sentences).
    """

    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)

    return response.text


def risky_statements(document):
    risky = []
    statements = document.get("Statement", [])
    
    if not isinstance(statements, list):
        statements = [statements]  # handle single statement case

    for stmt in statements:
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        # normalize to lists
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if "*" in actions or "*" in resources:
            risky.append(stmt)

    return risky


def get_policies_with_risky_permissions():
    findings = []

    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            arn = policy["Arn"]
            policy_name = policy["PolicyName"]

            version = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            document = iam.get_policy_version(
                PolicyArn=arn, VersionId=version
            )["PolicyVersion"]["Document"]

            risky = risky_statements(document)
            if risky:
                findings.append({
                    "PolicyName": policy_name,
                    "Arn": arn,
                    "RiskyStatements": risky,
                    "AIExplanation": explain_risk_with_gemini(policy_name, risky)
                })

    return findings

if __name__ == "__main__":
    results = get_policies_with_risky_permissions()
    
    with open("iam_risky_policies.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"Report saved → iam_risky_policies.json")    



