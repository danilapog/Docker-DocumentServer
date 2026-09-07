variable "TAG" {
    default = ""
}

variable "SHORTER_TAG" {
    default = ""
}

variable "SHORTEST_TAG" {
    default = ""
}

variable "PULL_TAG" {
    default = ""
}

variable "COMPANY_NAME" {
    default = ""
}

variable "PREFIX_NAME" {
    default = ""
}

variable "PRODUCT_EDITION" {
    default = ""
}

variable "PRODUCT_NAME" {
    default = ""
}

variable "PACKAGE_VERSION" {
    default = ""
}

variable "PLATFORM" {
    default = ""
}

variable "PACKAGE_BASEURL" {
    default = ""
}

variable "PACKAGE_FILE" {
    default = ""
}

variable "BUILD_CHANNEL" {
    default = ""
}

variable "PUSH_MAJOR" {
    default = "false"
}

variable "LATEST" {
    default = "false"
}

target "documentserver" {
    dockerfile = PRODUCT_EDITION == "" ? "Dockerfile" : "Dockerfile.enterprise"
    tags = [
           "docker.io/danilaworker/${PREFIX_NAME}${PRODUCT_NAME}${PRODUCT_EDITION}:${TAG}"
           ]
    platforms = ["${PLATFORM}"]
    args = {
        "COMPANY_NAME": "${COMPANY_NAME}"
        "PRODUCT_NAME": "${PRODUCT_NAME}"
        "PRODUCT_EDITION": "${PRODUCT_EDITION}"
        "PACKAGE_VERSION": "${PACKAGE_VERSION}"
        "PACKAGE_BASEURL": "${PACKAGE_BASEURL}"
        "PLATFORM": "${PLATFORM}"
    }
}
