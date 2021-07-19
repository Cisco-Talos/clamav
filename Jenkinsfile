properties(
    [
        disableConcurrentBuilds(),
        parameters(
            [
                string(name: 'CLAMAV_BRANCH',
                       defaultValue: "${env.BRANCH_NAME}",
                       description: 'clamav-devel branch'),
                string(name: 'VERSION',
                       defaultValue: '0.103.4',
                       description: 'ClamAV version string'),
                string(name: 'BUILD_BRANCH',
                       defaultValue: 'build-0.103',
                       description: 'test-pipelines branch for build acceptance'),
                string(name: 'FRAMEWORK_BRANCH',
                       defaultValue: '0.103',
                       description: 'test-framework branch'),
                string(name: 'TEST_BRANCH',
                       defaultValue: '0.103',
                       description: 'tests branch'),
                string(name: 'TEST_CUSTOM_BRANCH',
                       defaultValue: '0.103',
                       description: 'tests-custom branch'),
                string(name: 'REGULAR_PIPELINE',
                       defaultValue: 'regular-0.103',
                       description: 'test-pipelines branch for regular tests.'),
                string(name: 'CUSTOM_PIPELINE',
                       defaultValue: 'custom-0.103',
                       description: 'test-pipelines branch for custom tests'),
                string(name: 'FUZZ_PIPELINE',
                       defaultValue: 'fuzz-regression-0.103',
                       description: 'test-pipelines branch for fuzz regression tests'),
                string(name: 'FUZZ_BRANCH',
                       defaultValue: 'master',
                       description: 'private-fuzz-corpus branch'),
                string(name: 'FUZZ_TEST_BRANCH',
                       defaultValue: '0.103',
                       description: 'tests-fuzz-regression branch'),
                string(name: 'SHARED_LIB_BRANCH',
                       defaultValue: '0.103',
                       description: 'tests-jenkins-shared-libraries branch')
            ]
        )
    ]
)

def buildResult

node('master') {
    stage('Build') {
        buildResult = build(job: "test-pipelines/${params.BUILD_BRANCH}",
            propagate: true,
            wait: true,
            parameters: [
                [$class: 'StringParameterValue', name: 'TARGET_BRANCH', value: "${params.CLAMAV_BRANCH}"],
                [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"]
            ]
        )
        echo "test-pipelines/${params.BUILD_BRANCH} #${buildResult.number} succeeded."
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
                            [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "test-pipelines/${params.BUILD_BRANCH}"],
                            [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                            [$class: 'StringParameterValue', name: 'TEST_BRANCH', value: "${params.TEST_BRANCH}"],
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
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "test-pipelines/${params.BUILD_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                        [$class: 'StringParameterValue', name: 'TEST_BRANCH', value: "${params.TEST_CUSTOM_BRANCH}"],
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
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "test-pipelines/${params.BUILD_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                        [$class: 'StringParameterValue', name: 'FUZZ_TEST_BRANCH', value: "${params.FUZZ_TEST_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'FUZZ_BRANCH', value: "${params.FUZZ_BRANCH}"],
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
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "test-pipelines/${params.BUILD_BRANCH}"],
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
