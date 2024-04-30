properties(
    [
        disableConcurrentBuilds(),
        buildDiscarder(logRotator(
            artifactDaysToKeepStr: '15',
            artifactNumToKeepStr: '15',
            daysToKeepStr: '30',
            numToKeepStr: '20')),

        parameters(
            [
                string(name: 'VERSION',
                       defaultValue: '1.0.7',
                       description: 'ClamAV version string'),
                string(name: 'FRAMEWORK_BRANCH',
                       defaultValue: '1.0',
                       description: 'test-framework branch'),
                string(name: 'TESTS_BRANCH',
                       defaultValue: '1.0',
                       description: 'tests branch'),
                string(name: 'TESTS_CUSTOM_BRANCH',
                       defaultValue: '1.0',
                       description: 'tests-custom branch'),
                string(name: 'TESTS_FUZZ_BRANCH',
                       defaultValue: '1.0',
                       description: 'tests-fuzz-regression branch'),
                string(name: 'TEST_PIPELINES_PATH',
                       defaultValue: 'ClamAV/test-pipelines',
                       description: 'test-pipelines path for clamav in Jenkins'),
                string(name: 'BUILD_PIPELINE',
                       defaultValue: 'build-1.0',
                       description: 'test-pipelines branch for build acceptance'),
                string(name: 'REGULAR_PIPELINE',
                       defaultValue: 'regular-1.0',
                       description: 'test-pipelines branch for regular tests.'),
                string(name: 'CUSTOM_PIPELINE',
                       defaultValue: 'custom-1.0',
                       description: 'test-pipelines branch for custom tests'),
                string(name: 'FUZZ_PIPELINE',
                       defaultValue: 'fuzz-regression-1.0',
                       description: 'test-pipelines branch for fuzz regression tests'),
                string(name: 'FUZZ_CORPUS_BRANCH',
                       defaultValue: '1.0',
                       description: 'private-fuzz-corpus branch'),
                string(name: 'APPCHECK_PIPELINE',
                       defaultValue: 'appcheck-1.0',
                       description: 'test-pipelines branch for appcheck'),
                string(name: 'SHARED_LIB_BRANCH',
                       defaultValue: 'master',
                       description: 'tests-jenkins-shared-libraries branch')
            ]
        )
    ]
)

node('master') {
    stage('Generate Tarball') {
        cleanWs()

        checkout scm

        dir(path: 'clamav_documentation') {
            git(url: 'https://github.com/Cisco-Talos/clamav-documentation.git', branch: "gh-pages")
        }

        dir(path: 'docs/html') {
            sh '''# Move the clamav-documentation here.
                cp -r ../../clamav_documentation/* .
                # Clean-up
                rm -rf ../../clamav_documentation
                rm -rf .git .nojekyll CNAME Placeholder || true
                '''
        }

        dir(path: 'build') {
            sh """# CPack
                cmake .. -D VENDOR_DEPENDENCIES=ON
                cpack --config CPackSourceConfig.cmake """
            archiveArtifacts(artifacts: "clamav-${params.VERSION}*.tar.gz", onlyIfSuccessful: true)
        }

        cleanWs()
    }

    def buildResult

    stage('Build') {
        buildResult = build(job: "${params.TEST_PIPELINES_PATH}/${params.BUILD_PIPELINE}",
            propagate: true,
            wait: true,
            parameters: [
                [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NAME', value: "${JOB_NAME}"],
                [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NUMBER', value: "${BUILD_NUMBER}"],
                [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"]
            ]
        )
        echo "${params.TEST_PIPELINES_PATH}/${params.BUILD_PIPELINE} #${buildResult.number} succeeded."
    }

    stage('Test') {
        def tasks = [:]

        tasks["regular_and_custom"] = {
            def regularResult
            def exception = null
            try {
                stage("Regular Pipeline") {
                    regularResult = build(job: "${params.TEST_PIPELINES_PATH}/${params.REGULAR_PIPELINE}",
                        propagate: true,
                        wait: true,
                        parameters: [
                            [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NAME', value: "${JOB_NAME}"],
                            [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NUMBER', value: "${BUILD_NUMBER}"],
                            [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "${params.TEST_PIPELINES_PATH}/${params.BUILD_PIPELINE}"],
                            [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                            [$class: 'StringParameterValue', name: 'TESTS_BRANCH', value: "${params.TESTS_BRANCH}"],
                            [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                            [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                            [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"]
                        ]
                    )
                    echo "${params.TEST_PIPELINES_PATH}/${params.REGULAR_PIPELINE} #${regularResult.number} succeeded."
                }
            } catch (exc) {
                echo "${params.TEST_PIPELINES_PATH}/${params.REGULAR_PIPELINE} failed."
                exception = exc
            }
            stage("Custom Pipeline") {
                final customResult = build(job: "${params.TEST_PIPELINES_PATH}/${params.CUSTOM_PIPELINE}",
                    propagate: true,
                    wait: true,
                    parameters: [
                        [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NAME', value: "${JOB_NAME}"],
                        [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NUMBER', value: "${BUILD_NUMBER}"],
                        [$class: 'StringParameterValue', name: 'TESTS_BRANCH', value: "${params.TESTS_CUSTOM_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                        [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"]
                    ]
                )
                echo "${params.TEST_PIPELINES_PATH}/${params.CUSTOM_PIPELINE} #${customResult.number} succeeded."
            }
            if(exception != null) {
                echo "Custom Pipeline passed, but Regular pipeline failed!"
                throw exception
            }
        }

        tasks["fuzz_regression"] = {
            stage("Fuzz Regression") {
                final fuzzResult = build(job: "${params.TEST_PIPELINES_PATH}/${params.FUZZ_PIPELINE}",
                    propagate: true,
                    wait: true,
                    parameters: [
                        [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NAME', value: "${JOB_NAME}"],
                        [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NUMBER', value: "${BUILD_NUMBER}"],
                        [$class: 'StringParameterValue', name: 'TESTS_FUZZ_BRANCH', value: "${params.TESTS_FUZZ_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'FUZZ_CORPUS_BRANCH', value: "${params.FUZZ_CORPUS_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"]
                    ]
                )
                echo "${params.TEST_PIPELINES_PATH}/${params.FUZZ_PIPELINE} #${fuzzResult.number} succeeded."
            }
        }

        tasks["appcheck"] = {
            stage("AppCheck") {
                final appcheckResult = build(job: "test-pipelines/${params.APPCHECK_PIPELINE}",
                    propagate: true,
                    wait: true,
                    parameters: [
                        [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NAME', value: "${JOB_NAME}"],
                        [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NUMBER', value: "${BUILD_NUMBER}"],
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "test-pipelines/${params.BUILD_PIPELINE}"],
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                        [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"]
                    ]
                )
                echo "test-pipelines/${params.APPCHECK_PIPELINE} #${appcheckResult.number} succeeded."
            }
        }

        parallel tasks
    }
}
