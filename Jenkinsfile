properties(
    [
        disableConcurrentBuilds(),
        parameters(
            [
                string(name: 'CLAMAV_BRANCH',
                       defaultValue: "${env.BRANCH_NAME}",
                       description: 'clamav-devel branch'),
                string(name: 'VERSION',
                       defaultValue: '0.104.0',
                       description: 'ClamAV version string'),
                string(name: 'FRAMEWORK_BRANCH',
                       defaultValue: '0.104',
                       description: 'test-framework branch'),
                string(name: 'TESTS_BRANCH',
                       defaultValue: '0.104',
                       description: 'tests branch'),
                string(name: 'TESTS_CUSTOM_BRANCH',
                       defaultValue: '0.104',
                       description: 'tests-custom branch'),
                string(name: 'TESTS_FUZZ_BRANCH',
                       defaultValue: '0.104',
                       description: 'tests-fuzz-regression branch'),
                string(name: 'BUILD_PIPELINE',
                       defaultValue: 'build-0.104',
                       description: 'test-pipelines branch for build acceptance'),
                string(name: 'REGULAR_PIPELINE',
                       defaultValue: 'regular-0.104',
                       description: 'test-pipelines branch for regular tests.'),
                string(name: 'CUSTOM_PIPELINE',
                       defaultValue: 'custom-0.104',
                       description: 'test-pipelines branch for custom tests'),
                string(name: 'FUZZ_PIPELINE',
                       defaultValue: 'fuzz-regression-0.104',
                       description: 'test-pipelines branch for fuzz regression tests'),
                string(name: 'FUZZ_CORPUS_BRANCH',
                       defaultValue: 'master',
                       description: 'private-fuzz-corpus branch'),
                string(name: 'SHARED_LIB_BRANCH',
                       defaultValue: 'master',
                       description: 'tests-jenkins-shared-libraries branch')
            ]
        )
    ]
)

def buildResult

node('master') {
    stage('Build') {
        buildResult = build(job: "test-pipelines/${params.BUILD_PIPELINE}",
            propagate: true,
            wait: true,
            parameters: [
                [$class: 'StringParameterValue', name: 'TARGET_BRANCH', value: "${params.CLAMAV_BRANCH}"],
                [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"]
            ]
        )
        echo "test-pipelines/${params.BUILD_PIPELINE} #${buildResult.number} succeeded."
    }

    stage('Test') {
        def tasks = [:]

        tasks["regular_and_custom"] = {
            def regularResult
            def exception = null
            try {
                stage("Regular Pipeline") {
                    regularResult = build(job: "test-pipelines/${params.REGULAR_PIPELINE}",
                        propagate: true,
                        wait: true,
                        parameters: [
                            [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "test-pipelines/${params.BUILD_PIPELINE}"],
                            [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                            [$class: 'StringParameterValue', name: 'TESTS_BRANCH', value: "${params.TESTS_BRANCH}"],
                            [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                            [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                            [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"],
                            [$class: 'StringParameterValue', name: 'CLAMAV_BRANCH', value: "${params.CLAMAV_BRANCH}"]
                        ]
                    )
                    echo "test-pipelines/${params.REGULAR_PIPELINE} #${regularResult.number} succeeded."
                }
            } catch (exc) {
                echo "test-pipelines/${params.REGULAR_PIPELINE} failed."
                exception = exc
            }
            stage("Custom Pipeline") {
                final customResult = build(job: "test-pipelines/${params.CUSTOM_PIPELINE}",
                    propagate: true,
                    wait: true,
                    parameters: [
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "test-pipelines/${params.BUILD_PIPELINE}"],
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                        [$class: 'StringParameterValue', name: 'TESTS_BRANCH', value: "${params.TESTS_CUSTOM_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                        [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'CLAMAV_BRANCH', value: "${params.CLAMAV_BRANCH}"]
                    ]
                )
                echo "test-pipelines/${params.CUSTOM_PIPELINE} #${customResult.number} succeeded."
            }
            if(exception != null) {
                echo "Custom Pipeline passed, but Regular pipeline failed!"
                throw exception
            }
        }

        tasks["fuzz_regression"] = {
            stage("Fuzz Regression") {
                final fuzzResult = build(job: "test-pipelines/${params.FUZZ_PIPELINE}",
                    propagate: true,
                    wait: true,
                    parameters: [
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "test-pipelines/${params.BUILD_PIPELINE}"],
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                        [$class: 'StringParameterValue', name: 'TESTS_FUZZ_BRANCH', value: "${params.TESTS_FUZZ_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'FUZZ_CORPUS_BRANCH', value: "${params.FUZZ_CORPUS_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                        [$class: 'StringParameterValue', name: 'CLAMAV_BRANCH', value: "${params.CLAMAV_BRANCH}"]
                    ]
                )
                echo "test-pipelines/${params.FUZZ_PIPELINE} #${fuzzResult.number} succeeded."
            }
        }

        tasks["appcheck"] = {
            stage("AppCheck") {
                final appcheckResult = build(job: "test-pipelines/appcheck",
                    propagate: true,
                    wait: true,
                    parameters: [
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "test-pipelines/${params.BUILD_PIPELINE}"],
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                        [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                        [$class: 'StringParameterValue', name: 'CLAMAV_BRANCH', value: "${params.CLAMAV_BRANCH}"]
                    ]
                )
                echo "test-pipelines/appcheck #${appcheckResult.number} succeeded."
            }
        }

        parallel tasks
    }
}
