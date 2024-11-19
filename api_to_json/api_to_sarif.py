import json

def transform_to_exact_sarif(api_response, reference_sarif):
    """
    Transform the API response into a SARIF file format that exactly matches the reference SARIF.
    """
    sarif_output = {
        "$schema": reference_sarif["$schema"],
        "version": reference_sarif["version"],
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Semgrep",
                        "informationUri": "https://semgrep.dev",
                        "rules": []
                    }
                },
                "results": [],
                "invocations": reference_sarif["runs"][0].get("invocations", [])
            }
        ]
    }

    run = sarif_output["runs"][0]
    driver = run["tool"]["driver"]
    results = run["results"]

    for finding in api_response["findings"]:
        # Add a rule if not already present
        rule_id = finding["rule_name"]
        if not any(rule["id"] == rule_id for rule in driver["rules"]):
            driver["rules"].append({
                "id": rule_id,
                "shortDescription": {
                    "text": finding["rule_message"]
                },
                "fullDescription": {
                    "text": finding["rule_message"]
                },
                "helpUri": finding.get("line_of_code_url"),
                "properties": {
                    "severity": finding.get("severity", "unknown")
                }
            })

        # Map findings to SARIF results
        result = {
            "ruleId": rule_id,
            "message": {
                "text": finding["rule_message"]
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding["location"]["file_path"],
                            "uriBaseId": "%SRCROOT%"  # Align with reference SARIF
                        },
                        "region": {
                            "startLine": finding["location"]["line"],
                            "startColumn": finding["location"]["column"],
                            "endLine": finding["location"]["end_line"],
                            "endColumn": finding["location"]["end_column"]
                        }
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": finding["syntactic_id"]
            },
            "fingerprints": {
                "matchBasedId/v1": finding["match_based_id"]
            }
        }
        results.append(result)

    return sarif_output


def main():
    # Load the API response
    api_response_path = "./json_reponse.json"  # Path to the API response
    with open(api_response_path, "r") as api_file:
        api_response = json.load(api_file)

    # Load the reference SARIF
    reference_sarif_path = "./semgrep.sarif"  # Path to the reference SARIF
    with open(reference_sarif_path, "r") as reference_file:
        reference_sarif = json.load(reference_file)

    # Transform the API response to match the SARIF reference
    exact_sarif_output = transform_to_exact_sarif(api_response, reference_sarif)

    # Save the transformed SARIF
    exact_sarif_output_path = "./semgrep_exact_transformed.sarif"
    with open(exact_sarif_output_path, "w") as sarif_file:
        json.dump(exact_sarif_output, sarif_file, indent=4)

    print(f"Transformed SARIF saved to {exact_sarif_output_path}")


if __name__ == "__main__":
    main()
