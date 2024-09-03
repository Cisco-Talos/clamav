properties(
    [
        disableConcurrentBuilds(),
        parameters(
            [
                string(name: 'VERSION',
                       defaultValue: '0.103.12',
                       description: 'ClamAV version string'),
                string(name: 'FRAMEWORK_BRANCH',
                       defaultValue: '0.103',
                       description: 'test-framework branch'),
                string(name: 'TESTS_BRANCH',
                       defaultValue: '0.103',
                       description: 'tests branch for the package and regular tests'),
                string(name: 'TESTS_CUSTOM_BRANCH',
                       defaultValue: '0.103',
                       description: 'tests-custom branch'),
                string(name: 'TESTS_FUZZ_BRANCH',
                       defaultValue: '0.103',
                       description: 'tests-fuzz-regression branch'),
                string(name: 'BUILD_PIPELINES_PATH',
                       defaultValue: 'ClamAV/build-pipelines',
                       description: 'build-pipelines path for clamav in Jenkins'),
                string(name: 'TEST_PIPELINES_PATH',
                       defaultValue: 'ClamAV/test-pipelines',
                       description: 'test-pipelines path for clamav in Jenkins'),
                string(name: 'BUILD_PIPELINE',
                       defaultValue: 'build-0.103',
                       description: 'test-pipelines branch for build acceptance'),
                string(name: 'PACKAGE_PIPELINE',
                       defaultValue: 'package-0.103',
                       description: 'test-pipelines branch for package tests.'),
                string(name: 'REGULAR_PIPELINE',
                       defaultValue: 'regular-0.103',
                       description: 'test-pipelines branch for regular tests.'),
                string(name: 'CUSTOM_PIPELINE',
                       defaultValue: 'custom-0.103',
                       description: 'test-pipelines branch for custom tests'),
                string(name: 'FUZZ_PIPELINE',
                       defaultValue: 'fuzz-regression-0.103',
                       description: 'test-pipelines branch for fuzz regression tests'),
                string(name: 'FUZZ_CORPUS_BRANCH',
                       defaultValue: '0.103',
                       description: 'private-fuzz-corpus branch'),
                string(name: 'SHARED_LIB_BRANCH',
                       defaultValue: '0.103',
                       description: 'tests-jenkins-shared-libraries branch')
            ]
        )
    ]
)

node('docker') {
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

        // start up docker image
        def dockerImage = docker.build("autoconf", "./Jenkins")

        try {
            dockerImage.inside { c ->
                dir(path: "build") {
                    sh """# Make Dist
                        if [ -f '../autogen.sh' ] ; then /bin/chmod +x ../autogen.sh && ../autogen.sh ; fi
                        ../configure --enable-milter --disable-clamav --disable-silent-rules --enable-llvm --with-system-llvm=no
                        make dist
                        mv clamav-${params.VERSION}*.tar.gz clamav-${params.VERSION}.tar.gz || true"""
                    archiveArtifacts(artifacts: "clamav-${params.VERSION}.tar.gz", onlyIfSuccessful: true)
                }
            }
        }
        catch(IOException err) {
            cleanWs()
            throw err
        }

        cleanWs()
    }

    def buildResult

    stage('Build') {
        buildResult = build(job: "${params.BUILD_PIPELINES_PATH}/${params.BUILD_PIPELINE}",
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
        echo "${params.BUILD_PIPELINES_PATH}/${params.BUILD_PIPELINE} #${buildResult.number} succeeded."
    }

    stage('Test') {
        def tasks = [:]

        tasks["package_regular_custom"] = {
            def exception = null
            try {
                stage("Package") {
                    final regularResult = build(job: "${params.TEST_PIPELINES_PATH}/${params.PACKAGE_PIPELINE}",
                        propagate: true,
                        wait: true,
                        parameters: [
                            [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NAME', value: "${JOB_NAME}"],
                            [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NUMBER', value: "${BUILD_NUMBER}"],
                            [$class: 'StringParameterValue', name: 'BUILD_JOB_NAME', value: "${params.BUILD_PIPELINES_PATH}/${params.BUILD_PIPELINE}"],
                            [$class: 'StringParameterValue', name: 'BUILD_JOB_NUMBER', value: "${buildResult.number}"],
                            [$class: 'StringParameterValue', name: 'TESTS_BRANCH', value: "${params.TESTS_BRANCH}"],
                            [$class: 'StringParameterValue', name: 'FRAMEWORK_BRANCH', value: "${params.FRAMEWORK_BRANCH}"],
                            [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"],
                            [$class: 'StringParameterValue', name: 'SHARED_LIB_BRANCH', value: "${params.SHARED_LIB_BRANCH}"]
                        ]
                    )
                    echo "${params.TEST_PIPELINES_PATH}/${params.PACKAGE_PIPELINE} #${regularResult.number} succeeded."
                }
            } catch (exc) {
                echo "${params.TEST_PIPELINES_PATH}/${params.PACKAGE_PIPELINE} failed."
                exception = exc
            }

            try {
                stage("Regular From-Source") {
                    final regularResult = build(job: "${params.TEST_PIPELINES_PATH}/${params.REGULAR_PIPELINE}",
                        propagate: true,
                        wait: true,
                        parameters: [
                            [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NAME', value: "${JOB_NAME}"],
                            [$class: 'StringParameterValue', name: 'CLAMAV_JOB_NUMBER', value: "${BUILD_NUMBER}"],
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

            stage("Custom From-Source") {
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
                echo "Custom Pipeline passed, but prior pipelines failed!"
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

        parallel tasks
    }
}
