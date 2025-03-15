cmake_minimum_required(VERSION 3.10)
project(client_bbv C)

find_package(DynamoRIO REQUIRED)


include_directories(${DynamoRIO_INCLUDE_DIRS})
add_library(client_bbv SHARED client_bbv.c)
configure_DynamoRIO_client(client_bbv)


use_DynamoRIO_extension(client_bbv drmgr)
use_DynamoRIO_extension(client_bbv drutil)