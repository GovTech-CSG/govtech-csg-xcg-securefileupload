#!/bin/bash

# Runs unit tests in testapp/tests.py with all settings file configurations (see testproject/settings/*)
settings_modules=(
    'default'
    'keep_filename'
    'use_clamav'
    'use_yara'
)
sum_retval=0

# This section deals with CI runs where the clamav service
# is installed and started before tests are run. As the
# service can take a few seconds to start up, we want to
# make sure we don't start running the tests before
# it is fully up, otherwise some of the tests will fail.
seconds_elapsed=0
clamav_socket_wait_timeout=60
while ! [ -S /var/run/clamav/clamd.ctl ]
do
    if [ $seconds_elapsed -ge $clamav_socket_wait_timeout ]
    then
        echo "Waited for clamav daemon socket for more than $clamav_socket_wait_timeout seconds. Exiting without running tests."
        exit 1
    else
        echo "clamav daemon socket may not be up yet. Sleeping for 1 second before retrying."
        sleep 1
        let seconds_elapsed+="1"
    fi
done

for module_name in "${settings_modules[@]}"
do
    echo "===================================================="
    echo "Running tests with settings module: testproject.settings.$module_name"
    echo "===================================================="
    env DJANGO_SETTINGS_MODULE="testproject.settings.$module_name" python manage.py test
    let sum_retval+="$?"
done

evaluate_tests () {
    if [ $1 -eq 0 ]
    then
        echo "All test runs passed"
        return 0
    else
        echo "$1 test runs failed"
        return 1
    fi
}

evaluate_tests $sum_retval
