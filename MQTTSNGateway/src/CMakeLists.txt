#*******************************************************************************
#  Copyright (c) 2022 a1lu
#
#  All rights reserved. This program and the accompanying materials
#  are made available under the terms of the Eclipse Public License v1.0
#  and Eclipse Distribution License v1.0 which accompany this distribution.
#
#  The Eclipse Public License is available at
#     http://www.eclipse.org/legal/epl-v10.html
#  and the Eclipse Distribution License is available at
#    http://www.eclipse.org/org/documents/edl-v10.php.
#
#  Contributors:
#     a1lu  - initial version
#     ty4tw - modify
#*******************************************************************************/
PROJECT(mqtt-sn-gateway CXX)

SET(GW_VERSION_MAJOR 1)
SET(GW_VERSION_MINOR 5)
SET(GW_VERSION_PATCH 1)

SET(GATEWAY_VERSION ${GW_VERSION_MAJOR}.${GW_VERSION_MINOR}.${GW_VERSION_PATCH})
MESSAGE(STATUS "VERSION : ${GATEWAY_VERSION}")

configure_file( MQTTSNGWVersion.h.in ${CMAKE_CURRENT_SOURCE_DIR}/MQTTSNGWVersion.h )

SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../bin)
SET(CMAKE_CXX_STANDARD 11)

SET(OS linux)

IF(NOT DEFINED SENSORNET)
    SET(SENSORNET udp)
ENDIF()
MESSAGE(STATUS "SENSORNET: " ${SENSORNET})

# wolfSSL support, SSL library handling:
set(SSL_LIB "openssl" CACHE STRING "Choose SSL Library: openssl or wolfssl")
set_property(CACHE SSL_LIB PROPERTY STRINGS "openssl" "wolfssl")

if(NOT SSL_LIB STREQUAL "openssl" AND NOT SSL_LIB STREQUAL "wolfssl")
    message(FATAL_ERROR "Invalid SSL_LIB value: ${SSL_LIB}. Valid values are 'openssl', 'wolfssl'.")
endif()

string(TOLOWER ${SSL_LIB} SSL_LIB_LOWER)
MESSAGE(STATUS "SSL_LIB: " ${SSL_LIB})

if(SSL_LIB_LOWER STREQUAL "wolfssl")
    find_library(WOLFSSL_LIBRARY wolfssl HINTS /usr/local/lib)
    find_path(WOLFSSL_INCLUDE_DIR wolfssl/wolfcrypt/settings.h HINTS /usr/local/include)
    if(WOLFSSL_LIBRARY AND WOLFSSL_INCLUDE_DIR)
        message(STATUS "Compiling with wolfSSL support")
        add_definitions(-DUSE_WOLFSSL)
    else()
        message(FATAL_ERROR "wolfSSL not found")
    endif()
endif()

ADD_DEFINITIONS(${DEFS})
MESSAGE(STATUS "Definitions: " ${DEFS})

ADD_LIBRARY(mqtt-sngateway_common
    MQTTGWConnectionHandler.cpp
    MQTTGWPacket.cpp
    MQTTGWPublishHandler.cpp
    MQTTGWSubscribeHandler.cpp
    MQTTSNGateway.cpp
    MQTTSNGWBrokerRecvTask.cpp
    MQTTSNGWBrokerSendTask.cpp
    MQTTSNGWClient.cpp
    MQTTSNGWClientRecvTask.cpp
    MQTTSNGWClientSendTask.cpp
    MQTTSNGWConnectionHandler.cpp
    MQTTSNGWLogmonitor.cpp
    MQTTSNGWPacket.cpp
    MQTTSNGWPacketHandleTask.cpp
    MQTTSNGWProcess.cpp
    MQTTSNGWPublishHandler.cpp
    MQTTSNGWSubscribeHandler.cpp
    MQTTSNGWEncapsulatedPacket.cpp
    MQTTSNGWForwarder.cpp
    MQTTSNGWQoSm1Proxy.cpp
    MQTTSNGWAdapter.cpp
    MQTTSNGWAggregater.cpp
    MQTTSNGWClientList.cpp
    MQTTSNGWTopic.cpp
    MQTTSNGWAdapterManager.cpp
    MQTTSNAggregateConnectionHandler.cpp
    MQTTSNGWMessageIdTable.cpp
    MQTTSNGWAggregateTopicTable.cpp
    ${OS}/${SENSORNET}/${SSL_LIB}/SensorNetwork.cpp
    ${OS}/${SENSORNET}/${SSL_LIB}/SensorNetwork.h
    ${OS}/Timer.cpp
    ${OS}/Timer.h
    ${OS}/network/${SSL_LIB}/Network.cpp
    ${OS}/network/${SSL_LIB}/Network.h
    ${OS}/Threading.cpp
    ${OS}/Threading.h
)

# wolfSSL
if(SSL_LIB_LOWER STREQUAL "wolfssl")
    target_sources(mqtt-sngateway_common PRIVATE ${OS}/network/${SSL_LIB}/BioMethods.cpp ${OS}/network/${SSL_LIB}/BioMethods.h)
endif()

# linux
link_directories("/usr/local/lib")

# Mac
link_directories("/usr/local/opt/openssl/lib")

if(SSL_LIB_LOWER STREQUAL "wolfssl")
    target_include_directories(mqtt-sngateway_common
       PUBLIC
       .
       ${OS}
       ${OS}/network/${SSL_LIB}
       ${OS}/${SENSORNET}
       ${OS}/${SENSORNET}/${SSL_LIB}
       ../../MQTTSNPacket/src
       ${WOLFSSL_INCLUDE_DIR}
    )
else()
    target_include_directories(mqtt-sngateway_common
       PUBLIC
       .
       ${OS}
       ${OS}/network/${SSL_LIB}
       ${OS}/${SENSORNET}
       ${OS}/${SENSORNET}/${SSL_LIB}
       ../../MQTTSNPacket/src
       /usr/local/include
       /usr/local/opt/openssl/include
    )
endif()

# Common libraries
SET(TARGET_LIBRARIES MQTTSNPacket pthread)

# Add SSL library based on the SSL_LIB_LOWER variable
IF(SSL_LIB_LOWER STREQUAL "wolfssl")
    LIST(APPEND TARGET_LIBRARIES ${WOLFSSL_LIBRARY})
ELSE()
    LIST(APPEND TARGET_LIBRARIES ssl crypto)
ENDIF()

# Add bluetooth library if SENSORNET matches "rfcomm"
IF(SENSORNET MATCHES "rfcomm")
    LIST(APPEND TARGET_LIBRARIES bluetooth)
ENDIF()

# Link the libraries
TARGET_LINK_LIBRARIES(mqtt-sngateway_common PRIVATE ${TARGET_LIBRARIES})

ADD_EXECUTABLE(MQTT-SNGateway
       mainGateway.cpp
       )

TARGET_LINK_LIBRARIES(MQTT-SNGateway
       mqtt-sngateway_common
       )

ADD_EXECUTABLE(MQTT-SNLogmonitor
       mainLogmonitor.cpp
       )

TARGET_LINK_LIBRARIES(MQTT-SNLogmonitor
       mqtt-sngateway_common
       )

ADD_EXECUTABLE(testPFW
       tests/mainTestProcess.cpp
       tests/TestProcess.cpp
       tests/TestQue.cpp
       tests/TestTree23.cpp
       tests/TestTopics.cpp
       tests/TestTopicIdMap.cpp
       tests/TestTask.cpp
       )
TARGET_LINK_LIBRARIES(testPFW
       mqtt-sngateway_common
       )


ADD_TEST(NAME testPFW
       WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/..
       COMMAND testPFW -f ./gateway.conf)
