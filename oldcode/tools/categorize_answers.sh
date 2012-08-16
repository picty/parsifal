#!/bin/sh

mkfifo toto
tools/categorize_answers.acesl /mnt/ssl-data/Campaigns/00[01]*/*.dump 2> toto | while read line; do if [ -n "$line" ]; then echo "$line"; else clear; fi; done

