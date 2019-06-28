properties(
    [
        parameters(
            [
                string(name: 'CLAMAV_BRANCH', defaultValue: "${env.BRANCH_NAME}"),
                string(name: 'VERSION', defaultValue: '0.102.0-devel'),
                string(name: 'TESTS_BRANCH', defaultValue: 'build-0.102')
            ]
        )
    ]
)

node('master') {
    build job: "clamav-build-acceptance/${params.TESTS_BRANCH}",
        propagate: true,
        wait: true,
        parameters: [
            [$class: 'StringParameterValue', name: 'TARGET_BRANCH', value: "${params.CLAMAV_BRANCH}"],
            [$class: 'StringParameterValue', name: 'VERSION', value: "${params.VERSION}"]
        ]
}
