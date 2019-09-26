properties(
    [
        disableConcurrentBuilds(),
        parameters(
            [
                string(name: 'CLAMAV_BRANCH',
                       defaultValue: "${env.BRANCH_NAME}",
                       description: 'clamav-devel branch'),
                string(name: 'VERSION',
                       defaultValue: '0.102.0',
                       description: 'ClamAV version string'),
                string(name: 'BUILD_BRANCH',
                       defaultValue: 'build-0.102',
                       description: 'build-acceptance branch'),
                string(name: 'BUILD_ENGINE_BRANCH',
                       defaultValue: 'master',
                       description: 'build-acceptance engine branch'),
                string(name: 'TEST_BRANCH',
                       defaultValue: 'dev/0.102',
                       description: 'tests branch'),
                string(name: 'REGULAR_PIPELINE',
                       defaultValue: 'regular-scripted-chain-0.102',
                       description: 'test-pipelines branch for regular tests.'),
                string(name: 'CUSTOM_PIPELINE',
                       defaultValue: 'custom-scripted-chain-0.102',
                       description: 'test-pipelines branch for custom tests'),
                string(name: 'FUZZ_PIPELINE',
                       defaultValue: 'fuzz-regression-chain-0.102',
                       description: 'test-pipelines branch for fuzz regression tests'),
                string(name: 'FUZZ_BRANCH',
                       defaultValue: 'master',
                       description: 'private-fuzz-corpus branch'),
                string(name: 'FUZZ_TEST_BRANCH',
                       defaultValue: 'dev/0.102',
                       description: 'tests-fuzz-regression branch')
            ]
        )
    ]
)

def buildResult

node('master') {
    stage('Build') {
        buildResult = build(job: "build-acceptance/${params.BUILD_BRANCH}",
            propagate: true,
            wait: true,
            parameters: [
                [$class: 'StringParameterValue', name: 'TARGET_BRANCH', value: "${params.CLAMAV_BRANCH}"],
                [$class: 'StringParameterValue', name: 'BUILD_ENGINE_BRANCH', value: "${params.BUILD_ENGINE_BRANCH}"],
                [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"]
            ]
        )
        echo "build-acceptance/${params.BUILD_BRANCH} #${buildResult.number} succeeded."
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
                            [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "build-acceptance/${params.BUILD_BRANCH}"],
                            [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                            [$class: 'StringParameterValue', name: 'TEST_BRANCH', value: "${params.TEST_BRANCH}"],
                            [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"]
                        ]
                    )
                    echo "test-pipelines/${params.REGULAR_PIPELINE} #${regularResult.number} succeeded."
                }
            } catch (exc) {
                echo "test-pipelines/${params.REGULAR_PIPELINE} #${regularResult.number} failed."
                exception = exc
            }
            stage("Custom Pipeline") {
                final customResult = build(job: "test-pipelines/${params.CUSTOM_PIPELINE}",
                    propagate: true,
                    wait: true,
                    parameters: [
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "build-acceptance/${params.BUILD_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                        [$class: 'StringParameterValue', name: 'TEST_BRANCH', value: "${params.TEST_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"]
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
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "build-acceptance/${params.BUILD_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                        [$class: 'StringParameterValue', name: 'FUZZ_TEST_BRANCH', value: "${params.FUZZ_TEST_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'FUZZ_BRANCH', value: "${params.FUZZ_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
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
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "build-acceptance/${params.BUILD_BRANCH}"],
                        [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                        [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"]
                    ]
                )
                echo "test-pipelines/appcheck #${appcheckResult.number} succeeded."
            }
        }

        parallel tasks
    }
}
