#!/bin/bash
# Plays when Claude is waiting for user input
if [[ -f ".claude/sounds/bonk.aiff" ]]; then
    afplay .claude/sounds/bonk.aiff &
else
    osascript -e 'beep 2'
fi
