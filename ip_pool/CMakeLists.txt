cmake_minimum_required(VERSION 2.8)

project(ip_pool)


set(SOURCE_LIB ip_pool.c)

add_library(ip_pool STATIC ${SOURCE_LIB})