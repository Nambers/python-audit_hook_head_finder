#!/bin/bash

gcc $(python-config --cflags --ldflags --embed) audit_hook_head_finder.c -o audit_hook_head_finder