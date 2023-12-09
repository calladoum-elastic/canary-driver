project(MinifilterDriver LANGUAGES CXX VERSION 0.1.0)

message(STATUS "Configuring '${PROJECT_NAME}'")

wdk_add_driver(${PROJECT_NAME}
    KMDF
    1.15

    MinifilterDriver.cpp
)

target_compile_definitions(${PROJECT_NAME} PRIVATE DEBUG=1 KERNEL_MODE=1)
target_link_options(${PROJECT_NAME} PUBLIC /integritycheck)
target_link_libraries(${PROJECT_NAME} CommonLib WDK::FLTMGR WDK::KSECDD)

set(RC_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.rc)
set(INF_FILE ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.inf)
set(CERT_CN "BlahCat Corp")
set(CERT_STORE "PrivateCertStore")
set(CERT_FILE "$<TARGET_FILE_DIR:MinifilterDriver>/BlahCatTest.cer")

add_custom_command(
    TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND
    powershell -ep bypass "Get-ChildItem -Recurse Cert:\\CurrentUser | Where-Object { $_.Subject -match '${CERT_CN}' } | Remove-Item"
    COMMAND
    makecert.exe -r -pe -ss ${CERT_STORE} -n CN="${CERT_CN}" -eku 1.3.6.1.5.5.7.3.3 "${CERT_FILE}"
    COMMAND
    signtool.exe sign /v /a /fd SHA256 /s ${CERT_STORE} /n "${CERT_CN}" "$<TARGET_FILE:MinifilterDriver>"
    COMMAND
    certmgr.exe -del -c -n "${CERT_CN}" -s -r currentUser ${CERT_STORE}
    COMMAND
    ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}.inf "$<TARGET_FILE_DIR:MinifilterDriver>/${PROJECT_NAME}.inf"
    COMMAND
    ${CMAKE_COMMAND} -E copy_if_different $<TARGET_FILE:${PROJECT_NAME}> "$ENV{TEMP}"
    COMMAND
    ${CMAKE_COMMAND} -E copy_if_different ${INF_FILE} "$ENV{TEMP}"
    COMMENT
    "Signing driver with self-signed certificate"
)

install(TARGETS ${PROJECT_NAME} DESTINATION Drivers)
install(FILES $<TARGET_PDB_FILE:MinifilterDriver> ${RC_FILE} ${INF_FILE} DESTINATION Drivers/Debug)
