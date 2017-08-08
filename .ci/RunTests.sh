#!/bin/sh -x

runTest(){
    mono --runtime=v4.0 packages/nunit.consolerunner/3.7.0/tools/nunit3-console.exe --noresult -labels=All $@
   if [ $? -ne 0 ]
   then   
     exit 1
   fi
}

runTest Test/bin/Debug/net46/Test.dll --where "cat != AzureEmulator"

exit $?