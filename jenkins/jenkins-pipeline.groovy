pipeline {

    parameters {
        choice(name: 'SCAN_MODE', choices: ['centralized', 'distributed'], description: 'Select the scan mode. "distributed" uses the --from registry flag.')
        string(name: 'REGISTRY', defaultValue: 'docker.io', description: 'The container registry to use.', trim: true)
        string(name: 'REPOSITORY', defaultValue: 'library/nginx', description: 'The image repository path.', trim: true)
        string(name: 'TAG', defaultValue: 'latest', description: 'The image tag to analyze.', trim: true)
        choice(name: 'ANCHORECTL_QUIET', choices: ['true', 'false'], description: 'Suppress anchorectl informational messages.')
        choice(name: 'ANCHORECTL_FORMAT', choices: ['json', 'csv'], description: 'The output format for anchorectl (e.g., json, csv).')
        choice(name: 'ANCHORECTL_FAIL_BASED_ON_RESULTS', choices: ['true', 'false'],  description: 'How to handle fail signals (e.g.,  policy check outcomes)')
    }

    agent {
        kubernetes {
            yaml """
apiVersion: v1
kind: Pod
metadata:
  labels:
    jenkins: kaniko
spec:
  containers:
  - name: kaniko
    image: gcr.io/kaniko-project/executor:debug
    command: ["/bin/sh", "-c"]
    args: ["sleep infinity"]
    volumeMounts:
    - name: workspace-volume
      mountPath: /home/jenkins/agent
  serviceAccountName: jenkins
  volumes:
  - name: workspace-volume
    emptyDir: {}
"""
        }
    }

    environment {
        ANCHORECTL_URL                   = credentials('ANCHORECTL_URL')
        ANCHORECTL_USERNAME              = credentials('ANCHORECTL_USERNAME')
        ANCHORECTL_PASSWORD              = credentials('ANCHORECTL_PASSWORD')
        ANCHORECTL_FAIL_BASED_ON_RESULTS = "${params.ANCHORECTL_FAIL_BASED_ON_RESULTS}"
        ANCHORECTL_HTTP_TLS_INSECURE     = "true"
        ANCHORECTL_QUIET                 = "${params.ANCHORECTL_QUIET}"
        ANCHORECTL_FORMAT                = "${params.ANCHORECTL_FORMAT}"
    }

    stages {
        stage('Download Anchore CLI') {
            steps {
                sh '''
                    echo "Downloading anchorectl to the current directory..."
                    curl -k -sSfL "${ANCHORECTL_URL}v2/system/anchorectl?operating_system=linux&architecture=amd64" \\
                        -H "accept: */*" | tar -zx -C . anchorectl
                '''
            }
        }

        stage('Add Image to Anchore Enterprise') {
            steps {
                script {
                    sh "echo 'Analyzing image: ${params.REGISTRY}/${params.REPOSITORY}:${params.TAG} with mode: ${params.SCAN_MODE}'"
                    
                    // Define the base command
                    def addCommand = "./anchorectl image add --wait"
                    
                    // Conditionally add the --from flag
                    if (params.SCAN_MODE == 'distributed') {
                        addCommand += " --from registry"
                    }
                    
                    // Append the image name
                    addCommand += " ${params.REGISTRY}/${params.REPOSITORY}:${params.TAG}"

                    // Execute the final command
                    sh addCommand
                }
            }
        }
        
        stage('Retrieve Image Vulnerabilities') {
            steps {
                sh "echo 'Checking for vulnerabilities: ${params.REGISTRY}/${params.REPOSITORY}:${params.TAG}'"
                sh "./anchorectl image vulnerabilities ${params.REGISTRY}/${params.REPOSITORY}:${params.TAG} | tee vulnerabilities.${ANCHORECTL_FORMAT}"
                archiveArtifacts artifacts: "vulnerabilities.${env.ANCHORECTL_FORMAT}"
            }
        }
        
        stage('Run Image Policy Check') {
            steps {
                sh """#!/bin/bash
                    set -o pipefail
                    ./anchorectl image check --detail ${params.REGISTRY}/${params.REPOSITORY}:${params.TAG} | tee policy-check.${ANCHORECTL_FORMAT}
                """
            }
            post {
                always {
                    echo "Archiving policy check results..."
                    archiveArtifacts artifacts: "policy-check.${env.ANCHORECTL_FORMAT}"
                }
            }
        }
    }
}