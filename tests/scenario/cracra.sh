#!/bin/bash

CWCMD="../../cmd/crowdsec/crowdsec"
PLUGINS_FOLDER="../../plugins"
PLUGINS_FOLDER_BACKEND="./plugins/backend/"

dostuff() {
   
    STEP=${1}


     if [[ "${STEP}" == *consensus_* ]]  ; then
     cat > ./acquis.yaml << EOF
mode: cat
type: bin
filename: ${STEP}/file.log
labels:
    type: consensus
EOF

EXTRA=""
if [ -f "./buckets_state.json" ] ; then
    echo "Reusing existing bucket state"
    EXTRA="-restore-state ./buckets_state.json"
else
    echo "Creating new bucket state"
fi;

${CWCMD} -c ./dev.yaml -acquis ./acquis.yaml ${EXTRA} -custom-config "parser:${STEP}/parsers.yaml,scenario:${STEP}/scenarios.yaml" -dump-state

     else


SCENAR=${1}
FILE_LABELS=$(cat ${SCENAR}"/labels" 2>/dev/null)

rm "./test.db"
cat > ./acquis.yaml << EOF
mode: cat
filename: ${SCENAR}/file.log
labels:
    ${FILE_LABELS}
EOF

${CWCMD} -c ./dev.yaml -acquis ./acquis.yaml -custom-config "parser:${SCENAR}/parsers.yaml,scenario:${SCENAR}/scenarios.yaml"
fi;

success=0
echo "Checking results"
# check results
while read sqq ; do
    if [ -z "${sqq}" ] ; then 
        continue
    fi;
    success=$((${success}+1))

    if [ `echo ${sqq} | sqlite3 ./test.db`  -eq "1" ] ; then 
        echo "OK : ${sqq}" ;
    else 
        echo "FAILED : ${1} ${sqq}"; 
        echo "IN logs : ${1}/file.log"
        echo "Expected : ${1}/success.sqlite"
        echo "Failed sql query : ${sqq}"
	echo "Full log : out.log"
	exit
    fi
done < ${1}/success.sqlite


echo "Done testing ${success} tests runned"

}

# Still cracra, but build the plugins and move them in ./plugins
CWD=$(pwd)
cd ../..
bash ./scripts/build_plugins.sh
cd $CWD
mkdir -p "$PLUGINS_FOLDER_BACKEND"
cp -r ../../plugins/backend/*.so "$PLUGINS_FOLDER_BACKEND"
# Cracra finished

###

if [ -z ${1} ] ; then
    echo "${0} [-all|/path/to/test]"
    echo "	/path/to/test : path to test directory (ie. ./01ssh/)"
    echo "	-all : run all tests"
    echo " **./hub/** must be up-to-date hub directory/symlink (ie. hub clone)"
    exit;
fi;

case ${1} in
    "-all")
	for i in `find  . -mindepth 1 -type d -iname "0*"` ;
	do
	    echo "Testing ${i}";
	    dostuff $i ;
	done
    ;;
    *)
	echo "Testing ${1}";
	dostuff $1 ;
    ;;
esac

