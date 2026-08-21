pipeline {
    agent any

    environment {
        // Anchore Enterprise Credentials
        ANCHORECTL_URL      = credentials('ANCHORECTL_URL')
        ANCHORECTL_USERNAME = credentials('ANCHORECTL_USERNAME')
        ANCHORECTL_PASSWORD = credentials('ANCHORECTL_PASSWORD')
        ANCHORECTL_ACCOUNT  = 'demo-ci'
        
        // Image metadata for reuse
        FULL_IMAGE = "${params.REGISTRY}/${params.REPOSITORY}:${params.TAG}"
    }

    parameters {
        string(name: 'REGISTRY', defaultValue: 'docker.io', description: 'The container registry to use.', trim: true)
        string(name: 'REPOSITORY', defaultValue: 'library/nginx', description: 'The image repository path.', trim: true)
        string(name: 'TAG', defaultValue: 'latest', description: 'The image tag to analyze.', trim: true)
        
        choice(name: 'ANCHORECTL_QUIET', choices: ['true', 'false'], description: 'Suppress anchorectl informational messages.')
        choice(name: 'ANCHORECTL_OUTPUT', choices: ['json', 'csv', 'table'], description: 'The output format for anchorectl (e.g., json, csv).')
        choice(name: 'ANCHORECTL_FAIL_BASED_ON_RESULTS', choices: ['true', 'false'], description: 'Fail build if policy check fails.')
    }

    stages {
        stage('Add Image From Registry') {
            steps {
                // Centralized Analysis: Anchore pulls the image from the registry
                sh "anchorectl image add --wait --from registry ${env.FULL_IMAGE}"
            }
        }

        stage('Retrieve Vulnerability Report') {
            steps {
                // Generate and archive the vulnerability report using --output
                sh "anchorectl image vulnerabilities ${env.FULL_IMAGE} --output ${params.ANCHORECTL_OUTPUT} | tee vulnerabilities.${params.ANCHORECTL_OUTPUT}"
                archiveArtifacts artifacts: "vulnerabilities.${params.ANCHORECTL_OUTPUT}"
            }
        }

        stage('Perform Policy Eval') {
            steps {
                sh """#!/bin/bash
                    set -o pipefail
                    anchorectl image check --detail ${env.FULL_IMAGE} --output ${params.ANCHORECTL_OUTPUT} | tee policy-check.${params.ANCHORECTL_OUTPUT}
                """
                archiveArtifacts artifacts: "policy-check.${params.ANCHORECTL_OUTPUT}"

                script {
                    // Logic to parse results and potentially fail the build
                    def report = readFile("policy-check.${params.ANCHORECTL_OUTPUT}")
                    echo "Policy Report Summary: ${report}"
                    
                    if (params.ANCHORECTL_FAIL_BASED_ON_RESULTS == 'true') {
                        // Check for 'pass' status in the saved report file
                        boolean passed = report.toLowerCase().contains('"status": "pass"') || report.toLowerCase().contains('status: pass')
                        
                        if (!passed) {
                            error("Policy check failed for ${env.FULL_IMAGE}. Review policy-check.${params.ANCHORECTL_OUTPUT} for details.")
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            echo "Analysis workflow complete for ${env.FULL_IMAGE}"
        }
    }
}