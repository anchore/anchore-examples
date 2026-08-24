/*
// ---------------------------------------------------------------------------
// Part of the Anchore Examples Repository.
// Licensed under the Apache License, Version 2.0 (the "License").
//
// THIS FILE IS UNMAINTAINED AND PROVIDED "AS IS", WITHOUT WARRANTIES OR
// CONDITIONS OF ANY KIND. USE AT YOUR OWN RISK.
// ---------------------------------------------------------------------------
*/

pipeline {
    agent any

    environment {
        // Anchore Enterprise Credentials
        ANCHORECTL_URL      = credentials('ANCHORECTL_URL')
        ANCHORECTL_USERNAME = credentials('ANCHORECTL_USERNAME')
        ANCHORECTL_PASSWORD = credentials('ANCHORECTL_PASSWORD')
        ANCHORECTL_ACCOUNT  = 'demo-ci'
        
        // The image must exist in a registry accessible by the Anchore service
        FULL_IMAGE = "${params.REGISTRY}/${params.REPOSITORY}:${params.TAG}"
    }

    parameters {
        string(name: 'REGISTRY', defaultValue: 'docker.io', description: 'The container registry to use.', trim: true)
        string(name: 'REPOSITORY', defaultValue: 'library/nginx', description: 'The image repository path.', trim: true)
        string(name: 'TAG', defaultValue: 'latest', description: 'The image tag to analyze.', trim: true)
        
        choice(name: 'ANCHORECTL_OUTPUT', choices: ['json', 'csv', 'table'], description: 'The output format for anchorectl.')
        choice(name: 'ANCHORECTL_FAIL_BASED_ON_RESULTS', choices: ['true', 'false'], description: 'Fail build if policy check fails.')
    }

    stages {
        stage('Trigger Centralized Analysis') {
            steps {
                echo "Requesting Anchore Enterprise to pull and analyze ${env.FULL_IMAGE} from registry..."
                
                // '--from registry' instructs the Anchore service to perform the analysis
                // '--wait' ensures the pipeline pauses until the Anchore worker finishes the task
                sh "anchorectl image add --wait ${env.FULL_IMAGE}"
            }
        }

        stage('Retrieve Vulnerability Report') {
            steps {
                // Fetching results from the Anchore API that were generated server-side
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
                    def report = readFile("policy-check.${params.ANCHORECTL_OUTPUT}")
                    
                    if (params.ANCHORECTL_FAIL_BASED_ON_RESULTS == 'true') {
                        // Check if the server-side policy evaluation returned a 'pass'
                        boolean passed = report.toLowerCase().contains('"status": "pass"') || report.toLowerCase().contains('status: pass')
                        
                        if (!passed) {
                            error("Policy check failed for ${env.FULL_IMAGE}. Check Anchore Enterprise UI or the archived report.")
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            echo "Centralized Analysis workflow complete."
        }
    }
}
