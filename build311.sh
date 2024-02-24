#!/bin/bash

gcc $(python3.11-config --cflags --ldflags --embed) audit_hook_head_finder.c -o audit_hook_head_finder
