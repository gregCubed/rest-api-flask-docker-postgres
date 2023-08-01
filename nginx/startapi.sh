#!/bin/bash
exec nginx -g 'daemon off;'
while :; do nginx -s reload; sleep 1d; done &