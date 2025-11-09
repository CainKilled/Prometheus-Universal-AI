#!/usr/bin/env bash
set -e
SHA=$(git rev-parse --short HEAD)
BUILD_NUMBER=${GITHUB_RUN_NUMBER:-1}
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${BUILD_NUMBER}" "${BUILT_PRODUCTS_DIR}/${INFOPLIST_PATH}"
/usr/libexec/PlistBuddy -c "Add :WebSSHGitSHA string ${SHA}" "${BUILT_PRODUCTS_DIR}/${INFOPLIST_PATH}" || /usr/libexec/PlistBuddy -c "Set :WebSSHGitSHA ${SHA}" "${BUILT_PRODUCTS_DIR}/${INFOPLIST_PATH}"
echo "Inserted build SHA ${SHA}"
