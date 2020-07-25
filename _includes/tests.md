## Testing

On each commit to the master branch two git workflows are triggered

1. ShellCheck - This ensures all code is error free and POSIX compliant
2. ContainerTests - This runs all the container tests running deepce.sh on a varitey of environments

The output to all the containers tests is automatically converted to html and published below following completion. This gives an example of how deepce functions and ensures that nothing gets broken accidentally.

## Test Results
