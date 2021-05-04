#!/bin/bash
 echo
 for domain in $@; do
 echo $domain
 curl -sILk $domain | egrep 'HTTP|Loc' | sed 's/Loc/ -> Loc/g'
 done