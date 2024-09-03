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
                       defaultValue: '1.4.1',
                       description: 'ClamAV version string'),
                string(name: 'FRAMEWORK_BRANCH',
                       defaultValue: '1.4',
                       description: 'test-framework branch'),
                string(name: 'TESTS_BRANCH',
                       defaultValue: '1.4',
                       description: 'tests branch for the package and regular tests'),
                string(name: 'TESTS_CUSTOM_BRANCH',
                       defaultValue: '1.4',
                       description: 'tests-custom branch'),
                string(name: 'TESTS_FUZZ_BRANCH',
                       defaultValue: '1.4',
                       description: 'tests-fuzz-regression branch'),
                string(name: 'BUILD_PIPELINES_PATH',
                       defaultValue: 'ClamAV/build-pipelines',
                       description: 'build-pipelines path for clamav in Jenkins'),
                string(name: 'TEST_PIPELINES_PATH',
                       defaultValue: 'ClamAV/test-pipelines',
                       description: 'test-pipelines path for clamav in Jenkins'),
                string(name: 'BUILD_PIPELINE',
                       defaultValue: 'build-1.4',
                       description: 'test-pipelines branch for build acceptance'),
                string(name: 'PACKAGE_PIPELINE',
                       defaultValue: 'package-1.4',
                       description: 'test-pipelines branch for package tests.'),
                string(name: 'REGULAR_PIPELINE',
                       defaultValue: 'regular-1.4',
                       description: 'test-pipelines branch for regular tests.'),
                string(name: 'CUSTOM_PIPELINE',
                       defaultValue: 'custom-1.4',
                       description: 'test-pipelines branch for custom tests'),
                string(name: 'FUZZ_PIPELINE',
                       defaultValue: 'fuzz-regression-1.4',
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

node('default') {
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
                cmake .. -D VENDOR_DEPENDENCIES=ON \
                    -D JSONC_INCLUDE_DIR="$HOME/.mussels/install/host-static/include/json-c" \
                    -D JSONC_LIBRARY="$HOME/.mussels/install/host-static/lib/libjson-c.a" \
                    -D ENABLE_JSON_SHARED=OFF \
                    -D BZIP2_INCLUDE_DIR="$HOME/.mussels/install/host-static/include" \
                    -D BZIP2_LIBRARY_RELEASE="$HOME/bzip2-1.0.8-install/lib/libbz2.a" \
                    -D OPENSSL_ROOT_DIR="$HOME/.mussels/install/host-static" \
                    -D OPENSSL_INCLUDE_DIR="$HOME/.mussels/install/host-static/include" \
                    -D OPENSSL_CRYPTO_LIBRARY="$HOME/.mussels/install/host-static/lib/libcrypto.a" \
                    -D OPENSSL_SSL_LIBRARY="$HOME/.mussels/install/host-static/lib/libssl.a" \
                    -D LIBXML2_INCLUDE_DIR="$HOME/.mussels/install/host-static/include/libxml2" \
                    -D LIBXML2_LIBRARY="$HOME/.mussels/install/host-static/lib/libxml2.a" \
                    -D PCRE2_INCLUDE_DIR="$HOME/.mussels/install/host-static/include" \
                    -D PCRE2_LIBRARY="$HOME/.mussels/install/host-static/lib/libpcre2-8.a" \
                    -D CURSES_INCLUDE_DIR="$HOME/.mussels/install/host-static/include" \
                    -D CURSES_LIBRARY="$HOME/.mussels/install/host-static/lib/libncurses.a;$HOME/.mussels/install/host-static/lib/libtinfo.a" \
                    -D ZLIB_INCLUDE_DIR="$HOME/.mussels/install/host-static/include" \
                    -D ZLIB_LIBRARY="$HOME/.mussels/install/host-static/lib/libz.a" \
                    -D LIBCHECK_INCLUDE_DIR="$HOME/.mussels/install/host-static/include" \
                    -D LIBCHECK_LIBRARY="$HOME/.mussels/install/host-static/lib/libcheck.a"

                cpack --config CPackSourceConfig.cmake """
            archiveArtifacts(artifacts: "clamav-${params.VERSION}*.tar.gz", onlyIfSuccessful: true)
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
