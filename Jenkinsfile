// -*- groovy -*-

pipeline {
  agent any

  environment {
    PYTEST_ADDOPTS = '--color=yes'
  }

  stages {
    stage('Test') {
      steps {
        timeout(15) {
          ansiColor('xterm') {
            sh './run_tests.sh'
          }
        }
      }
    }
  }

  post {
    always {
      junit healthScaleFactor: 200.0,           \
        testResults: '**/build/reports/*.xml'

      cobertura coberturaReportFile: 'coverage.xml',    \
        maxNumberOfBuilds: 0

      cleanWs()
    }
  }
}
