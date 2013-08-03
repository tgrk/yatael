#!/bin/bash
erl -pa ebin deps/*/ebin -s yatael -s reloader
