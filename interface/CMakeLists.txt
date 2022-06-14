cmake_minimum_required(VERSION 2.8)

project(interface)


set(SOURCE_LIB interface.c)

add_library(interface STATIC ${SOURCE_LIB})